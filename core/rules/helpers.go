package rules

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/rhysd/actionlint"
)

func searchInScript(script string, re *regexp.Regexp) *actionlint.Pos {
	line := 0

	if len(strings.Split(script, "\n")) != 1 {
		line++
	}

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
