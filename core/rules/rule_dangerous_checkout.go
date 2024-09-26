package rules

import (
	"strings"

	"github.com/synacktiv/octoscan/common"

	"github.com/rhysd/actionlint"
)

type RuleDangerousCheckout struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
}

// NewRuleDangerousCheckout creates new RuleDangerousCheckout instance.
func NewRuleDangerousCheckout(filterTriggers []string) *RuleDangerousCheckout {
	return &RuleDangerousCheckout{
		RuleBase: actionlint.NewRuleBase(
			"dangerous-checkout",
			"Check for dangerous checkout.",
		),
		filterTriggers: filterTriggers,
		skip:           false,
	}
}

func (rule *RuleDangerousCheckout) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleDangerousCheckout) VisitStep(n *actionlint.Step) error {

	if rule.skip {
		return nil
	}

	switch e := n.Exec.(type) {
	case *actionlint.ExecRun:
		rule.checkManualCheckout(e)
	case *actionlint.ExecAction:
		rule.checkCheckoutAction(e)
	}

	return nil
}

func (rule *RuleDangerousCheckout) checkCheckoutAction(action *actionlint.ExecAction) {
	if action.Uses.ContainsExpression() {
		// Cannot parse specification made with interpolation. Give up
		return
	}

	spec := action.Uses.Value

	// search for checkout action
	if strings.HasPrefix(spec, "actions/checkout") {
		// basicRegExp := regexp.MustCompile(`github.event.pull_request`)
		ref := action.Inputs["ref"]

		if ref != nil && !common.StaticRefRegexp.MatchString(ref.Value.Value) {
			rule.Errorf(
				ref.Value.Pos,
				"Use of 'actions/checkout' with a custom ref.",
			)
		}
	}
}

func (rule *RuleDangerousCheckout) checkManualCheckout(action *actionlint.ExecRun) {
	rule.checkGitManualCheckout(action)
	rule.checkGHCliManualCheckout(action)
}

func (rule *RuleDangerousCheckout) checkGitManualCheckout(action *actionlint.ExecRun) {
	posArray := searchInScript(action.Run.Value, common.GitCheckoutBashRexexp)

	for _, pos := range posArray {
		err := &actionlint.ExprError{
			Message: "Use of \"git checkout\" in a bash script with a potentially dangerous reference.",
			Offset:  0,
			Line:    pos.Line,
			Column:  pos.Col,
		}
		err.Column -= len("git checkout")
		exprError(&rule.RuleBase, err, action.Run.Pos.Line, action.Run.Pos.Col)
	}
}

func (rule *RuleDangerousCheckout) checkGHCliManualCheckout(action *actionlint.ExecRun) {
	posArray := searchInScript(action.Run.Value, common.GHCliCheckoutBashRexexp)

	for _, pos := range posArray {
		err := &actionlint.ExprError{
			Message: "Use of \"gh pr checkout\" in a bash script with a potentially dangerous reference.",
			Offset:  0,
			Line:    pos.Line,
			Column:  pos.Col,
		}
		err.Column -= len("gh pr checkout")
		exprError(&rule.RuleBase, err, action.Run.Pos.Line, action.Run.Pos.Col)
	}
}
