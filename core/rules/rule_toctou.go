package rules

import (
	"slices"
	"strings"

	"github.com/synacktiv/octoscan/common"

	"github.com/rhysd/actionlint"
)

// RuleToctou looks for workflows where somebody approves a PR (comment, dispatch, label) and the
// workflow then checks out a mutable reference to it: the author can push between approval and checkout.
type RuleToctou struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
	trigger        string // the approval trigger of the workflow, empty if none
}

// NewRuleToctou creates new RuleToctou instance.
func NewRuleToctou(filterTriggers []string) *RuleToctou {
	return &RuleToctou{
		RuleBase: actionlint.NewRuleBase(
			"toctou",
			"Check for checkouts of a mutable PR reference in workflows triggered after an approval (comment, dispatch, label).",
		),
		filterTriggers: filterTriggers,
	}
}

func (rule *RuleToctou) VisitWorkflowPre(n *actionlint.Workflow) error {
	rule.skip = skipAnalysis(n, rule.filterTriggers)
	rule.trigger = approvalTrigger(n)

	return nil
}

func approvalTrigger(n *actionlint.Workflow) string {
	for _, event := range n.On {
		switch e := event.(type) {
		case *actionlint.WebhookEvent:
			if e.EventName() == "issue_comment" {
				return e.EventName()
			}

			// the label is the approval, the author can still push after it is set
			if e.EventName() == "pull_request_target" && slices.ContainsFunc(e.Types, func(t *actionlint.String) bool { return t.Value == "labeled" }) {
				return "pull_request_target (labeled)"
			}
		case *actionlint.WorkflowDispatchEvent:
			return e.EventName()
		}
	}

	return ""
}

// VisitStep is callback when visiting Step node.
func (rule *RuleToctou) VisitStep(n *actionlint.Step) error {
	if rule.skip || rule.trigger == "" {
		return nil
	}

	switch e := n.Exec.(type) {
	case *actionlint.ExecAction:
		rule.checkCheckoutAction(e)
	case *actionlint.ExecRun:
		rule.checkScript(e)
	}

	return nil
}

func (rule *RuleToctou) checkCheckoutAction(e *actionlint.ExecAction) {
	if e.Uses == nil || !strings.HasPrefix(e.Uses.Value, "actions/checkout") {
		return
	}

	ref := e.Inputs["ref"]
	if ref == nil {
		return
	}

	value := ref.Value.Value
	if common.ToctouRefRegexp.MatchString(value) && !common.ToctouSHARegexp.MatchString(value) {
		rule.Errorf(
			ref.Value.Pos,
			"TOCTOU: %q checks out a mutable reference to a PR in a workflow triggered by %q, the PR can change between the approval and the checkout. Check out a commit SHA.",
			value,
			rule.trigger,
		)
	}
}

func (rule *RuleToctou) checkScript(e *actionlint.ExecRun) {
	reportInScript(
		&rule.RuleBase, e.Run, common.ToctouScriptRegexp, nil,
		"TOCTOU: the head of a PR is checked out in a script of a workflow triggered by \""+rule.trigger+"\", the PR can change between the approval and the checkout. Check out a commit SHA.",
	)
}
