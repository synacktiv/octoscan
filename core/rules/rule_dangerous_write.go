package rules

import (
	"github.com/synacktiv/octoscan/common"

	"github.com/rhysd/actionlint"
)

type RuleDangerousWrite struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
}

// NewRuleDangerousWrite creates new RuleDangerousWrite instance.
func NewRuleDangerousWrite(filterTriggers []string) *RuleDangerousWrite {
	return &RuleDangerousWrite{
		RuleBase: actionlint.NewRuleBase(
			"dangerous-write",
			"Check for dangerous write operation on $GITHUB_OUTPUT or $GITHUB_ENV.",
		),
		filterTriggers: filterTriggers,
		skip:           false,
	}
}

func (rule *RuleDangerousWrite) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleDangerousWrite) VisitStep(n *actionlint.Step) error {

	if rule.skip {
		return nil
	}

	e, ok := n.Exec.(*actionlint.ExecRun)
	if !ok {
		return nil
	}

	rule.checkWrite(e.Run.Value, e.Run.Pos)

	return nil
}

func (rule *RuleDangerousWrite) checkWrite(script string, p *actionlint.Pos) {
	// handle by rule_dangerous_expression.go with needsOutputData and stepsOutputData I think
	rule.checkWriteToGitHubOutput(script, p)
	rule.checkWriteToGitHubEnv(script, p)
}

func (rule *RuleDangerousWrite) checkWriteToGitHubOutput(script string, p *actionlint.Pos) {
	rule.checkWriteToGitHubOutputPwsh(script, p)
	rule.checkWriteToGitHubOutputBash(script, p)
}

func (rule *RuleDangerousWrite) checkWriteToGitHubEnv(script string, p *actionlint.Pos) {
	rule.checkWriteToGitHubEnvPwsh(script, p)
	rule.checkWriteToGitHubEnvBash(script, p)
}

func (rule *RuleDangerousWrite) checkWriteToGitHubOutputPwsh(script string, p *actionlint.Pos) {
	posArray := searchInScript(script, common.GitHubOutputPwshRegexp)

	for _, pos := range posArray {
		err := &actionlint.ExprError{
			Message: "Write to \"$GITHUB_OUTPUT\" in a powershell script. It might be a false positive, The regexp must be improved",
			Offset:  0,
			Line:    pos.Line,
			Column:  pos.Col,
		}
		err.Column -= len("GITHUB_OUTPUT")
		rule.exprError(err, p.Line, p.Col)

	}
}

func (rule *RuleDangerousWrite) checkWriteToGitHubOutputBash(script string, p *actionlint.Pos) {
	posArray := searchInScript(script, common.GitHubOutputBashRegexp)

	for _, pos := range posArray {
		err := &actionlint.ExprError{
			Message: "Write to \"$GITHUB_OUTPUT\" in a bash script.",
			Offset:  0,
			Line:    pos.Line,
			Column:  pos.Col,
		}
		err.Column -= len("GITHUB_OUTPUT")
		rule.exprError(err, p.Line, p.Col)

	}
}

func (rule *RuleDangerousWrite) checkWriteToGitHubEnvPwsh(script string, p *actionlint.Pos) {
	posArray := searchInScript(script, common.GitHubEnvPwshRegexp)

	for _, pos := range posArray {
		err := &actionlint.ExprError{
			Message: "Write to \"$GITHUB_ENV\" in a powershell script. It might be a false positive, The regexp must be improved",
			Offset:  0,
			Line:    pos.Line,
			Column:  pos.Col,
		}
		err.Column -= len("GITHUB_ENV")
		rule.exprError(err, p.Line, p.Col)

	}
}

func (rule *RuleDangerousWrite) checkWriteToGitHubEnvBash(script string, p *actionlint.Pos) {
	posArray := searchInScript(script, common.GitHubEnvBashRexexp)

	for _, pos := range posArray {
		err := &actionlint.ExprError{
			Message: "Write to \"$GITHUB_ENV\" in a bash script.",
			Offset:  0,
			Line:    pos.Line,
			Column:  pos.Col,
		}
		err.Column -= len("GITHUB_ENV")
		rule.exprError(err, p.Line, p.Col)

	}
}

func (rule *RuleDangerousWrite) exprError(err *actionlint.ExprError, lineBase, colBase int) {
	pos := exprLineColToPos(err.Line, err.Column, lineBase, colBase)
	rule.Error(pos, err.Message)
}
