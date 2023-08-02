package core

import (
	"octoscan/core/rules"

	"github.com/rhysd/actionlint"
)

func OnRulesCreated(rules []actionlint.Rule) []actionlint.Rule {

	res := filterUnWantedRules(rules)
	res = append(res, addCustomRules()...)
	return res
}

func filterUnWantedRules(rules []actionlint.Rule) []actionlint.Rule {
	res := []actionlint.Rule{}

	for _, r := range rules {

		// only keep credential and shellcheck rule
		if r.Name() == "credentials" || r.Name() == "shellcheck" {
			res = append(res, r)
		}

	}

	return res
}

func addCustomRules() []actionlint.Rule {
	return []actionlint.Rule{
		rules.NewRuleDangerousAction(),
		rules.NewRuleDangerousCheckout(),
		rules.NewRuleExpressionInjection(),
		rules.NewRuleDangerousWrite(),
	}
}
