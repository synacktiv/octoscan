package rules

import (
	"github.com/rhysd/actionlint"
	"github.com/synacktiv/octoscan/common"
)

type RuleBotCheck struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
}

// NewRuleBotCheck creates new RuleDebugJSExec instance.
func NewRuleBotCheck(filterTriggers []string) *RuleBotCheck {
	return &RuleBotCheck{
		RuleBase: actionlint.NewRuleBase(
			"bot-check",
			"Check for if statements that are based on a bot identity.",
		),
		filterTriggers: filterTriggers,
		skip:           false,
	}
}

func (rule *RuleBotCheck) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	if rule.skip {
		return nil
	}

	for _, job := range n.Jobs {
		rule.checkBotActor(job.If)
	}

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleBotCheck) VisitStep(n *actionlint.Step) error {
	if rule.skip {
		return nil
	}

	rule.checkBotActor(n.If)

	return nil
}

func (rule *RuleBotCheck) checkBotActor(ifStr *actionlint.String) {
	if ifStr != nil {
		posArray := searchInScript(ifStr.Value, common.BotActor)

		for _, pos := range posArray {
			err := &actionlint.ExprError{
				Message: "If statement based on the github.actor variable and a bot identity.",
				Offset:  0,
				Line:    pos.Line,
				Column:  pos.Col,
			}
			err.Column -= len("downloadArtifact")
			exprError(&rule.RuleBase, err, ifStr.Pos.Line, ifStr.Pos.Col)
		}
	}
}
