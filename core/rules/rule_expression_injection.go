package rules

import "github.com/rhysd/actionlint"

type RuleCommandInjection struct {
	actionlint.RuleBase
}

// NewRuleExpression creates new RuleExpression instance.
func NewRuleCommandInjection() *RuleCommandInjection {
	return &RuleCommandInjection{
		RuleBase: actionlint.NewRuleBase(
			"expression-injection",
			"Check expression injection.",
		),
	}
}
