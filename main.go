package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	flagMixMode       bool
	flagConvertOutput string
)

const flagConvertDefaultOutput = "<file_name>.srs"

var mainCommand = &cobra.Command{
	Use:   "sing-srs-converter [source-path]",
	Short: "convert clash rule-provider to source type rule-set and binary type rule-set",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := compileRuleSet(args[0])
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	mainCommand.Flags().StringVarP(&flagConvertOutput, "output", "o", flagConvertDefaultOutput, "Output file name")
	mainCommand.Flags().BoolVarP(&flagMixMode, "mix", "m", false, "Output file name")
}

func main() {
	if err := mainCommand.Execute(); err != nil {
		log.Fatal(err)
	}
}

type clashRuleProvider struct {
	Rules []string `yaml:"payload,omitempty"`
}

func getRulesFromContent(content []byte) ([]string, error) {
	var provider clashRuleProvider
	if err := yaml.Unmarshal(content, &provider); err == nil {
		return provider.Rules, nil
	}
	var ruleArr []string
	for _, lineRaw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(lineRaw)
		if strings.HasPrefix(line, "#") {
			continue
		}
		ruleArr = append(ruleArr, line)
	}
	return ruleArr, nil
}

func saveRuleSet(rules []option.DefaultHeadlessRule, outputPath string) error {
	plainRuleSet := option.PlainRuleSetCompat{
		Version: 1,
		Options: option.PlainRuleSet{
			Rules: common.Map(rules, func(it option.DefaultHeadlessRule) option.HeadlessRule {
				return option.HeadlessRule{
					Type:           C.RuleTypeDefault,
					DefaultOptions: it,
				}
			}),
		},
	}
	if err := saveSourceRuleSet(&plainRuleSet, outputPath+".json"); err != nil {
		return err
	}
	if err := saveBinaryRuleSet(&plainRuleSet, outputPath+".srs"); err != nil {
		return err
	}
	return nil
}

func readYamlToRuleset(content []byte, outputPath string) error {
	rawRules, err := getRulesFromContent(content)
	if err != nil {
		return err
	}
	var (
		rules            []option.DefaultHeadlessRule
		hasStarOnlyRule  bool
		domainArr        []string
		domainSuffixArr  []string
		domainKeywordArr []string
		domainRegexArr   []string
		ipcidrArr        []string
		srcipcidrArr     []string
		portArr          []uint16
		srcPortArr       []uint16
		processNameArr   []string
		processPathArr   []string
	)
	for _, line := range rawRules {
		switch true {
		case strings.HasPrefix(line, "DOMAIN,"):
			str := line[7:]
			if str == "*" {
				hasStarOnlyRule = true
				continue
			}
			if strings.Contains(str, "*") {
				strings.ReplaceAll(str, "*", "[^\\.]*?")
				domainRegexArr = append(domainRegexArr, str[1:])
				continue
			}
			if strings.HasPrefix(str, "+.") {
				domainSuffixArr = append(domainSuffixArr, str[1:])
				continue
			}
			domainArr = append(domainArr, line[7:])
		case strings.HasPrefix(line, "DOMAIN-KEYWORD,"):
			domainKeywordArr = append(domainKeywordArr, line[15:])
		case strings.HasPrefix(line, "DOMAIN-SUFFIX,"):
			str := line[14:]
			domainArr = append(domainArr, str)
			str = "." + str
			domainSuffixArr = append(domainSuffixArr, str)
		case strings.HasPrefix(line, "DOMAIN-REGEX,"):
			domainRegexArr = append(domainRegexArr, line[13:])
		case strings.HasPrefix(line, "IP-CIDR,"):
			ipcidrArr = append(ipcidrArr, line[8:])
		case strings.HasPrefix(line, "IP-CIDR6,"):
			ipcidrArr = append(ipcidrArr, line[9:])
		case strings.HasPrefix(line, "SRC-IP-CIDR,"):
			ipcidrArr = append(srcipcidrArr, line[12:])
		case strings.HasPrefix(line, "DST-PORT,"):
			port, _ := strconv.Atoi(line[8:])
			portArr = append(portArr, uint16(port))
		case strings.HasPrefix(line, "SRC-DST-PORT,"):
			port, _ := strconv.Atoi(line[12:])
			srcPortArr = append(srcPortArr, uint16(port))
		case strings.HasPrefix(line, "PROCESS-NAME,"):
			processNameArr = append(processNameArr, line[13:])
		case strings.HasPrefix(line, "PROCESS-PATH,"):
			processPathArr = append(processPathArr, line[13:])
		}
	}
	if !flagMixMode {
		if len(domainArr) > 0 || len(domainSuffixArr) > 0 || len(domainKeywordArr) > 0 || len(domainRegexArr) > 0 {
			domainRuleArr := []option.DefaultHeadlessRule{
				{
					Domain:        domainArr,
					DomainKeyword: domainKeywordArr,
					DomainSuffix:  domainSuffixArr,
					DomainRegex:   domainRegexArr,
				},
			}
			if hasStarOnlyRule {
				domainRuleArr = append(domainRuleArr, option.DefaultHeadlessRule{
					DomainKeyword: []string{"."},
					Invert:        true,
				})
			}
			if err := saveRuleSet(domainRuleArr, outputPath+"-domain"); err != nil {
				return err
			}
			rules = append(rules, domainRuleArr...)
		}
		if len(ipcidrArr) > 0 {
			ipcidrRuleArr := []option.DefaultHeadlessRule{
				{
					IPCIDR: ipcidrArr,
				},
			}
			if err := saveRuleSet(ipcidrRuleArr, outputPath+"-ip"); err != nil {
				return err
			}
			rules = append(rules, ipcidrRuleArr...)
		}
	} else {
		if len(domainArr) > 0 || len(domainSuffixArr) > 0 || len(domainKeywordArr) > 0 || len(domainRegexArr) > 0 || len(ipcidrArr) > 0 {
			rules = append(rules, option.DefaultHeadlessRule{
				Domain:        domainArr,
				DomainKeyword: domainKeywordArr,
				DomainSuffix:  domainSuffixArr,
				DomainRegex:   domainRegexArr,
				IPCIDR:        ipcidrArr,
			})
			if hasStarOnlyRule {
				rules = append(rules, option.DefaultHeadlessRule{
					DomainKeyword: []string{"."},
					Invert:        true,
				})
			}
		}
	}
	if len(portArr) > 0 {
		portRuleArr := []option.DefaultHeadlessRule{
			{
				Port: portArr,
			},
		}
		if !flagMixMode {
			if err := saveRuleSet(portRuleArr, outputPath+"-port"); err != nil {
				return err
			}
		}
		rules = append(rules, portRuleArr...)
	}
	if len(srcPortArr) > 0 {
		srcPortRuleArr := []option.DefaultHeadlessRule{
			{
				SourcePort: srcPortArr,
			},
		}
		if !flagMixMode {
			if err := saveRuleSet(srcPortRuleArr, outputPath+"-src-port"); err != nil {
				return err
			}
		}
		rules = append(rules, srcPortRuleArr...)
	}
	if len(srcipcidrArr) > 0 {
		srcIPCidrRuleArr := []option.DefaultHeadlessRule{
			{
				SourceIPCIDR: srcipcidrArr,
			},
		}
		if !flagMixMode {
			if err := saveRuleSet(srcIPCidrRuleArr, outputPath+"-src-ip"); err != nil {
				return err
			}
		}
		rules = append(rules, srcIPCidrRuleArr...)
	}
	if len(processNameArr) > 0 || len(processPathArr) > 0 {
		var processRuleArr []option.DefaultHeadlessRule
		if len(processNameArr) > 0 {
			processRuleArr = append(processRuleArr, option.DefaultHeadlessRule{
				ProcessName: processNameArr,
			})
		}
		if len(processPathArr) > 0 {
			processRuleArr = append(processRuleArr, option.DefaultHeadlessRule{
				ProcessPath: processPathArr,
			})
		}
		if !flagMixMode {
			if err := saveRuleSet(processRuleArr, outputPath+"-process"); err != nil {
				return err
			}
		}
		rules = append(rules, processRuleArr...)
	}
	if len(processPathArr) > 0 {
		rule := option.DefaultHeadlessRule{
			ProcessPath: processPathArr,
		}
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return E.New("empty input")
	}
	if flagMixMode {
		return saveRuleSet(rules, outputPath)
	}
	return nil
}

func saveSourceRuleSet(ruleset *option.PlainRuleSetCompat, outputPath string) error {
	buffer := new(bytes.Buffer)
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(ruleset); err != nil {
		return E.Cause(err, "encode config")
	}
	output, err := os.Create(outputPath)
	if err != nil {
		return E.Cause(err, "open output")
	}
	_, err = output.Write(buffer.Bytes())
	output.Close()
	if err != nil {
		return E.Cause(err, "write output")
	}
	return nil
}

func saveBinaryRuleSet(ruleset *option.PlainRuleSetCompat, outputPath string) error {
	ruleSet := ruleset.Upgrade()
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	err = srs.Write(outputFile, ruleSet)
	if err != nil {
		outputFile.Close()
		os.Remove(outputPath)
		return err
	}
	outputFile.Close()
	return nil
}

func compileRuleSet(sourcePath string) error {
	var (
		reader io.Reader
		err    error
	)
	if sourcePath == "stdin" {
		reader = os.Stdin
	} else {
		reader, err = os.Open(sourcePath)
		if err != nil {
			return err
		}
	}
	content, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	var outputPath string
	if flagConvertOutput == flagConvertDefaultOutput {
		outputPath = sourcePath
		if strings.HasSuffix(sourcePath, ".yaml") {
			outputPath = sourcePath[:len(sourcePath)-5]
		}
	} else {
		outputPath = flagConvertOutput
	}
	return readYamlToRuleset(content, outputPath)
}
