package rules

import (
	"strings"

	"github.com/rhysd/actionlint"
	"github.com/synacktiv/octoscan/common"
)

type RuleDangerousArtefact struct {
	actionlint.RuleBase
	filterTriggers      []string
	skip                bool
	checkoutStepPresent bool
}

var sensitivePaths = []string{
	".",
	"./",
	".\\",
}

// NewRuleOIDCAction creates new RuleOIDCAction instance.
func NewRuleRuleDangerousArtefact(filterTriggers []string) *RuleDangerousArtefact {
	return &RuleDangerousArtefact{
		RuleBase: actionlint.NewRuleBase(
			"dangerous-artefact",
			"Check for workflow that upload artefacts containing sensitive files.",
		),
		filterTriggers: filterTriggers,
		skip:           false,
	}
}

func (rule *RuleDangerousArtefact) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleDangerousArtefact) VisitStep(n *actionlint.Step) error {
	if rule.skip {
		return nil
	}

	e, ok := n.Exec.(*actionlint.ExecAction)
	if !ok || e.Uses == nil {
		return nil
	}

	spec := e.Uses.Value

	// search for checkout action
	if strings.HasPrefix(spec, "actions/checkout") {
		rule.checkoutStepPresent = true
		return nil
	}

	if strings.HasPrefix(spec, "actions/upload-artifact") {

		path := e.Inputs["path"]
		if path != nil && common.IsStringInArray(sensitivePaths, path.Value.Value) {
			// weird linter error
			//nolint:typecheck
			rule.Errorf(
				e.Inputs["path"].Value.Pos,
				"Use of action 'actions/upload-artifact' with a sensitive path %q",
				path.Value.Value,
			)
		}
	}

	return nil
}

func (rule *RuleDangerousArtefact) VisitJobPost(job *actionlint.Job) error {
	// reset for each job
	rule.checkoutStepPresent = false

	return nil
}
