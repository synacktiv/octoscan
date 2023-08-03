package rules

import (
	"strings"

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
			"oidc-action",
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

	spec := e.Uses.Value

	rule.checkOIDCActions(spec, e)

	return nil
}

func (rule *RuleOIDCAction) checkOIDCActions(spec string, exec *actionlint.ExecAction) {
	for _, action := range OIDCActions {
		if strings.HasPrefix(spec, action) {
			rule.Errorf(
				exec.Uses.Pos,
				"Use of OIDC action %q",
				spec,
			)
		}
	}
}
