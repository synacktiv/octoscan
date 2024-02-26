package rules

import (
	"octoscan/common"
	"strings"

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

		if ref != nil && !common.LettersRegexp.MatchString(ref.Value.Value) {
			rule.Errorf(
				action.Uses.Pos,
				"Use of 'actions/checkout' with external workflow trigger and custom ref.",
			)
		}
	}
}

func (rule *RuleDangerousCheckout) checkManualCheckout(action *actionlint.ExecRun) {
	pos := searchInScript(action.Run.Value, common.GitCheckoutBashRexexp)

	if pos != nil {
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
