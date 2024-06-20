package rules

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/synacktiv/octoscan/common"

	"github.com/rhysd/actionlint"
)

func searchInScript(script string, re *regexp.Regexp) []*actionlint.Pos {
	line := 0
	res := []*actionlint.Pos{}

	if len(strings.Split(script, "\n")) != 1 {
		line++
	}

	scanner := bufio.NewScanner(strings.NewReader(script))
	for scanner.Scan() {
		col := re.FindStringIndex(scanner.Text())
		if col != nil {
			res = append(res, &actionlint.Pos{
				Line: line,
				Col:  col[1],
			})
		}
		line++
	}

	return res
}

func exprError(rule *actionlint.RuleBase, err *actionlint.ExprError, lineBase, colBase int) {
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
	return &actionlint.Pos{
		Line: line + lineBase,
		Col:  col + colBase,
	}
}

func containsExpression(s string) bool {
	i := strings.Index(s, "${{")

	return i >= 0 && i < strings.Index(s, "}}")
}

func skipAnalysis(n *actionlint.Workflow, triggers []string) bool {
	if len(triggers) > 0 {
		for _, event := range n.On {
			if common.IsStringInArray(triggers, event.EventName()) {
				// don't skip, skip is false by default
				return false
			}
		}

		return true
	}

	return false
}

func checkForSpecificActions(rule *actionlint.RuleBase, exec *actionlint.ExecAction, actions []string) {
	for _, action := range actions {
		checkForSpecificAction(rule, exec, action)
	}
}

func checkForSpecificAction(rule *actionlint.RuleBase, exec *actionlint.ExecAction, action string) {
	spec := exec.Uses.Value

	if strings.HasPrefix(spec, action) {
		rule.Errorf(
			exec.Uses.Pos,
			"Use of action %q",
			spec,
		)
	}
}
