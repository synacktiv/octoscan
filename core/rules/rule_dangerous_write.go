package rules

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/rhysd/actionlint"
)

type RuleDangerousWrite struct {
	actionlint.RuleBase
}

// NewRuleDangerousCheckout creates new RuleDangerousCheckout instance.
func NewRuleDangerousWrite() *RuleDangerousWrite {

	return &RuleDangerousWrite{
		RuleBase: actionlint.NewRuleBase(
			"dangerous-write",
			"Check for dangerous write operation on $GITHUB_OUTPUT or $GITHUB_ENV.",
		),
	}
}

// VisitStep is callback when visiting Step node.
func (rule *RuleDangerousWrite) VisitStep(n *actionlint.Step) error {

	e, ok := n.Exec.(*actionlint.ExecRun)
	if !ok {
		return nil
	}

	rule.checkWrite(e.Run.Value, e.Run.Pos)

	return nil
}

func (rule *RuleDangerousWrite) checkWrite(script string, p *actionlint.Pos) {
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
	basicRegExp, err := regexp.Compile(`(?m)(?i:env):GITHUB_OUTPUT`)
	if err != nil {
		return
	}

	pos := searchInScript(script, basicRegExp)

	if pos != nil {
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
	basicRegExp, err := regexp.Compile(`(?m)>>\s*"*\${*GITHUB_OUTPUT`)
	if err != nil {
		return
	}

	pos := searchInScript(script, basicRegExp)

	if pos != nil {
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
	basicRegExp, err := regexp.Compile(`(?m)(?i:env):GITHUB_ENV`)
	if err != nil {
		return
	}

	pos := searchInScript(script, basicRegExp)

	if pos != nil {
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
	basicRegExp, err := regexp.Compile(`(?m)>>\s*"*\${*GITHUB_ENV`)
	if err != nil {
		return
	}

	pos := searchInScript(script, basicRegExp)

	if pos != nil {
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

func searchInScript(script string, re *regexp.Regexp) *actionlint.Pos {
	line := 0
	scanner := bufio.NewScanner(strings.NewReader(script))
	for scanner.Scan() {

		col := re.FindStringIndex(scanner.Text())
		if col != nil {

			return &actionlint.Pos{
				Line: line,
				Col:  col[1],
			}

		}
		line++
	}

	return nil
}

func (rule *RuleDangerousWrite) exprError(err *actionlint.ExprError, lineBase, colBase int) {
	pos := exprLineColToPos(err.Line, err.Column, lineBase, colBase)
	rule.Error(pos, err.Message)
}

// TODO improve multilines scripts
// run: |
//
//	ENV=""
//
// with the previous example the script line start before the pos of the Run action
func exprLineColToPos(line, col, lineBase, colBase int) *actionlint.Pos {
	// Line and column in ExprError are 1-based

	if line != 0 {
		line++
	}

	return &actionlint.Pos{
		Line: line + lineBase,
		Col:  col + colBase,
	}
}
