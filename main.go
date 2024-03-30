package main

import (
	"bytes"
	"encoding/json"
	"github.com/sagernet/sing-box/common/srs"
	"io"
	"os"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var flagRuleSetCompileOutput string

const flagRuleSetCompileDefaultOutput = "<file_name>.srs"

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
	mainCommand.PersistentFlags().StringVarP(&flagRuleSetCompileOutput, "output", "o", flagRuleSetCompileDefaultOutput, "Output file name")
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

func readYamlToRuleset(content []byte) ([]option.DefaultHeadlessRule, error) {
	rawRules, err := getRulesFromContent(content)
	if err != nil {
		return nil, err
	}
	var (
		rules            []option.DefaultHeadlessRule
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
	if len(domainArr) > 0 || len(domainSuffixArr) > 0 || len(domainKeywordArr) > 0 || len(domainRegexArr) > 0 || len(ipcidrArr) > 0 {
		rule := option.DefaultHeadlessRule{
			Domain:        domainArr,
			DomainKeyword: domainKeywordArr,
			DomainSuffix:  domainSuffixArr,
			DomainRegex:   domainRegexArr,
			IPCIDR:        ipcidrArr,
		}
		rules = append(rules, rule)
	}
	if len(portArr) > 0 {
		rule := option.DefaultHeadlessRule{
			Port: portArr,
		}
		rules = append(rules, rule)
	}
	if len(srcPortArr) > 0 {
		rule := option.DefaultHeadlessRule{
			SourcePort: srcPortArr,
		}
		rules = append(rules, rule)
	}
	if len(srcipcidrArr) > 0 {
		rule := option.DefaultHeadlessRule{
			SourceIPCIDR: srcipcidrArr,
		}
		rules = append(rules, rule)
	}
	if len(processNameArr) > 0 {
		rule := option.DefaultHeadlessRule{
			ProcessName: processNameArr,
		}
		rules = append(rules, rule)
	}
	if len(processPathArr) > 0 {
		rule := option.DefaultHeadlessRule{
			ProcessPath: processPathArr,
		}
		rules = append(rules, rule)
	}
	return rules, nil
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
	rules, err := readYamlToRuleset(content)
	if err != nil {
		return E.Cause(err, "decode rule-provider")
	}
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
	var outputPath string
	if flagRuleSetCompileOutput == flagRuleSetCompileDefaultOutput {
		outputPath = sourcePath
		if strings.HasSuffix(sourcePath, ".yaml") {
			outputPath = sourcePath[:len(sourcePath)-5]
		}
	} else {
		outputPath = flagRuleSetCompileOutput
	}
	if err := saveSourceRuleSet(&plainRuleSet, outputPath+".json"); err != nil {
		return err
	}
	if err := saveBinaryRuleSet(&plainRuleSet, outputPath+".srs"); err != nil {
		return err
	}
	return nil
}
