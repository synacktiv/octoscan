package rules

import (
	"strings"

	"github.com/rhysd/actionlint"
)

type RuleLocalAction struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
}

// NewRuleLocalAction creates new RuleLocalAction instance.
func NewRuleLocalAction(filterTriggers []string) *RuleLocalAction {
	return &RuleLocalAction{
		RuleBase: actionlint.NewRuleBase(
			"local-action",
			"Check for local actions.",
		),
		filterTriggers: filterTriggers,
		skip:           false,
	}
}

func (rule *RuleLocalAction) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleLocalAction) VisitStep(n *actionlint.Step) error {
	if rule.skip {
		return nil
	}

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
