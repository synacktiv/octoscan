package rules

import (
	"strings"

	"github.com/rhysd/actionlint"
)

type RuleDebugArtefacts struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
}

// NewRuleOIDCAction creates new RuleOIDCAction instance.
func NewRuleRuleDebugArtefacts(filterTriggers []string) *RuleDebugArtefacts {
	return &RuleDebugArtefacts{
		RuleBase: actionlint.NewRuleBase(
			"debug-artefacts",
			"Check for workflow that upload artefacts.",
		),
		filterTriggers: filterTriggers,
		skip:           false,
	}
}

func (rule *RuleDebugArtefacts) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleDebugArtefacts) VisitStep(n *actionlint.Step) error {
	if rule.skip {
		return nil
	}

	e, ok := n.Exec.(*actionlint.ExecAction)
	if !ok || e.Uses == nil {
		return nil
	}

	spec := e.Uses.Value

	if strings.HasPrefix(spec, "actions/upload-artifact") {

		path := e.Inputs["path"]
		if path != nil {
			// weird linter error
			//nolint:typecheck
			rule.Errorf(
				e.Inputs["path"].Value.Pos,
				"Use of action 'actions/upload-artifact'",
			)
		}
	}

	return nil
}
