package core

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/synacktiv/octoscan/common"
	"github.com/synacktiv/octoscan/core/rules"

	"github.com/rhysd/actionlint"
)

type OctoLinter struct {
	actionlint.Linter
}

// not optimal but I can't pass other parameters to OnRulesCreated
var (
	FilterTriggers    = []string{}
	FilterRun         = false
	Internetavailable = true
	DebugRules        = false
	RulesSwitch       = map[string]bool{
		"dangerous-action":       true,
		"dangerous-checkout":     true,
		"expression-injection":   true,
		"dangerous-write":        true,
		"local-action":           true,
		"oidc-action":            true,
		"repo-jacking":           true,
		"shellcheck":             true,
		"credentials":            true,
		"runner-label":           true,
		"unsecure-commands":      true,
		"known-vulnerability":    true,
		"bot-check":              true,
		"debug-external-trigger": true,
		"debug-artefacts":        true,
		"debug-js-exec":          true,
	}
)

func FilterRules(include bool, rulesFiltered []string) {
	for name := range RulesSwitch {
		RulesSwitch[name] = (include == common.IsStringInArray(rulesFiltered, name))
	}
}

func OnRulesCreated(rules []actionlint.Rule) []actionlint.Rule {
	res := filterUnWantedRules(rules)
	res = append(res, offlineRules()...)

	if Internetavailable {
		res = append(res, onlineRules()...)
	}

	return res
}

func filterUnWantedRules(rules []actionlint.Rule) []actionlint.Rule {
	res := []actionlint.Rule{}

	for _, r := range rules {
		// only keep credential and shellcheck rule
		if r.Name() == "credentials" && RulesSwitch["credentials"] {
			res = append(res, r)
		}

		if r.Name() == "shellcheck" && RulesSwitch["shellcheck"] {
			res = append(res, r)
		}

		// if r.Name() == "runner-label" && rulesSwitch["runner-label"] {
		// 	res = append(res, r)
		// }
	}

	/*
		if no rules are passed this function is called from octosan
		so we can add dummy rules for the --list-rule option and for the sarif format.
	*/
	if len(res) == 0 {
		res = append(res, &actionlint.RuleCredentials{RuleBase: actionlint.NewRuleBase("shellcheck", "Checks for shell script sources in \"run:\" using shellcheck")})
		res = append(res, &actionlint.RuleShellcheck{RuleBase: actionlint.NewRuleBase("credentials", "Checks for credentials in \"services:\" configuration")})
	}

	return res
}

func offlineRules() []actionlint.Rule {

	var res = []actionlint.Rule{}

	if RulesSwitch["dangerous-action"] {
		res = append(res, rules.NewRuleDangerousAction(FilterTriggers))
	}

	if RulesSwitch["dangerous-checkout"] {
		res = append(res, rules.NewRuleDangerousCheckout(FilterTriggers))
	}

	if RulesSwitch["expression-injection"] {
		res = append(res, rules.NewRuleExpressionInjection(FilterTriggers, FilterRun))
	}

	if RulesSwitch["dangerous-write"] {
		res = append(res, rules.NewRuleDangerousWrite(FilterTriggers))
	}

	if RulesSwitch["local-action"] {
		res = append(res, rules.NewRuleLocalAction(FilterTriggers))
	}

	if RulesSwitch["oidc-action"] {
		res = append(res, rules.NewRuleOIDCAction())
	}

	if RulesSwitch["runner-label"] {
		res = append(res, rules.NewRuleRunnerLabel())
	}

	if RulesSwitch["unsecure-commands"] {
		res = append(res, rules.NewRuleUnsecureCommands(FilterTriggers))
	}

	if RulesSwitch["known-vulnerability"] {
		res = append(res, rules.NewRuleKnownVulnerability(FilterTriggers))
	}

	if RulesSwitch["bot-check"] {
		res = append(res, rules.NewRuleBotCheck(FilterTriggers))
	}

	if DebugRules {
		if RulesSwitch["debug-external-trigger"] {
			res = append(res, rules.NewRuleDebugExternalTrigger(FilterTriggers))
		}

		if RulesSwitch["debug-artefacts"] {
			res = append(res, rules.NewRuleRuleDebugArtefacts(FilterTriggers))
		}

		if RulesSwitch["debug-js-exec"] {
			res = append(res, rules.NewRuleDebugJSExec(FilterTriggers))
		}
	}

	return res
}

func onlineRules() []actionlint.Rule {
	var res = []actionlint.Rule{}

	if RulesSwitch["repo-jacking"] {
		res = append(res, rules.NewRuleRepoJacking())
	}

	return res
}

// LintRepositoryRecurse search for all GitHub project recursively and run the linter
func (l *OctoLinter) LintRepositoryRecurse(dir string) ([]*actionlint.Error, error) {
	var lintErrors []*actionlint.Error
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		w := filepath.Join(path, ".github", "workflows")
		if s, err := os.Stat(w); err == nil && s.IsDir() {
			if lintErrorsBatch, err := l.LintRepository(w); err == nil {
				lintErrors = append(lintErrors, lintErrorsBatch...)
			}

			return fs.SkipDir
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("could not read files in %q: %w", "./", err)
	}
	return lintErrors, nil
}

/*
Everything is stolen from here: https://github.com/rhysd/actionlint/blob/main/docs/usage.md#format
Again thanks @rhysd for the great work.
*/
func DisplayErrors(writer io.Writer, format string, errs []*actionlint.Error) error {
	formatter, err := actionlint.NewErrorFormatter(format)
	rules := &[]actionlint.Rule{}
	availableRules := OnRulesCreated(*rules)

	for _, rule := range availableRules {
		formatter.RegisterRule(rule)
	}

	if err != nil {
		return err
	}

	temp := make([]*actionlint.ErrorTemplateFields, 0, len(errs))

	for _, octoscanErr := range errs {
		src, _ := os.ReadFile(octoscanErr.Filepath)
		temp = append(temp, octoscanErr.GetTemplateFields(src))
	}

	return formatter.Print(writer, temp)
}
