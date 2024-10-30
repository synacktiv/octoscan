package rules

import (
	"github.com/rhysd/actionlint"
)

type RuleOIDCAction struct {
	actionlint.RuleBase
}

var OIDCActions = []string{
	"aws-actions/configure-aws-credentials",
	"azure/login",
}

// NewRuleOIDCAction creates new RuleOIDCAction instance.
func NewRuleOIDCAction() *RuleOIDCAction {
	return &RuleOIDCAction{
		RuleBase: actionlint.NewRuleBase(
			"debug-oidc-action",
			"Check for OIDC actions.",
		),
	}
}

// VisitStep is callback when visiting Step node.
func (rule *RuleOIDCAction) VisitStep(n *actionlint.Step) error {
	e, ok := n.Exec.(*actionlint.ExecAction)
	if !ok || e.Uses == nil {
		return nil
	}

	checkForSpecificActions(&rule.RuleBase, e, OIDCActions)

	return nil
}
