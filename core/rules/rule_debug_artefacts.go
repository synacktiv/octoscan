package rules

import (
	"strings"

	"github.com/rhysd/actionlint"
)

type RuleDebugArtefacts struct {
	actionlint.RuleBase
}

// NewRuleOIDCAction creates new RuleOIDCAction instance.
func NewRuleRuleDebugArtefacts() *RuleDebugArtefacts {
	return &RuleDebugArtefacts{
		RuleBase: actionlint.NewRuleBase(
			"debug-artefacts",
			"Check for workflow that upload artefacts.",
		),
	}
}

// VisitStep is callback when visiting Step node.
func (rule *RuleDebugArtefacts) VisitStep(n *actionlint.Step) error {
	e, ok := n.Exec.(*actionlint.ExecAction)
	if !ok || e.Uses == nil {
		return nil
	}

	spec := e.Uses.Value

	if strings.HasPrefix(spec, "actions/upload-artifact") {
		rule.Errorf(
			e.Inputs["path"].Value.Pos,
			"Use of action 'actions/upload-artifact'",
		)
	}

	return nil
}
