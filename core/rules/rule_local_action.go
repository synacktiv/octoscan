package rules

import (
	"strings"

	"github.com/rhysd/actionlint"
)

type RuleLocalAction struct {
	actionlint.RuleBase
}

// NewRuleDangerousAction creates new RuleDangerousAction instance.
func NewRuleLocalAction() *RuleLocalAction {
	return &RuleLocalAction{
		RuleBase: actionlint.NewRuleBase(
			"local-action",
			"Check for local actions.",
		),
	}
}

// VisitStep is callback when visiting Step node.
func (rule *RuleLocalAction) VisitStep(n *actionlint.Step) error {
	e, ok := n.Exec.(*actionlint.ExecAction)
	if !ok || e.Uses == nil {
		return nil
	}

	spec := e.Uses.Value

	if strings.HasPrefix(spec, "./") {
		// Relative to repository root
		rule.Errorf(
			e.Uses.Pos,
			"Use of local action %q",
			spec,
		)
	}

	return nil
}
