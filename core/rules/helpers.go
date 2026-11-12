package rules

import (
	"bufio"
	"regexp"
	"slices"
	"strings"

	"github.com/rhysd/actionlint"
)

func searchInScript(script string, re *regexp.Regexp) []*actionlint.Pos {
	return searchInScriptExcept(script, re, nil)
}

// searchInScriptExcept is searchInScript ignoring the lines matching except (may be nil).
func searchInScriptExcept(script string, re, except *regexp.Regexp) []*actionlint.Pos {
	line := 0
	res := []*actionlint.Pos{}

	// multi-line scripts start on the line after "run: |"
	if strings.Contains(script, "\n") {
		line++
	}

	scanner := bufio.NewScanner(strings.NewReader(script))
	for scanner.Scan() {
		text := scanner.Text()

		col := re.FindStringIndex(text)
		if col != nil && (except == nil || !except.MatchString(text)) {
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
	if len(triggers) == 0 {
		return false
	}

	return !slices.ContainsFunc(n.On, func(event actionlint.Event) bool {
		return slices.Contains(triggers, event.EventName())
	})
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

// expressionSegments returns the content of every "${{ }}" of s. When bare is true and s has none,
// the whole of s is returned: it is an "if:" condition, which does not need the "${{ }}".
func expressionSegments(s string, bare bool) []string {
	if !strings.Contains(s, "${{") {
		if bare {
			return []string{s}
		}

		return nil
	}

	var res []string

	for {
		_, rest, found := strings.Cut(s, "${{")
		if !found {
			return res
		}

		inner, after, closed := strings.Cut(rest, "}}")
		res = append(res, inner)

		if !closed {
			return res
		}

		s = after
	}
}

// parseExpr parses the content of a "${{ }}", it returns nil when it is not valid.
func parseExpr(src string) actionlint.ExprNode {
	expr, err := actionlint.NewExprParser().Parse(actionlint.NewExprLexer(src + "}}"))
	if err != nil {
		return nil
	}

	return expr
}

// forEachEnvString calls f on every value of env.
func forEachEnvString(env *actionlint.Env, f func(*actionlint.String)) {
	if env == nil {
		return
	}

	if env.Expression != nil {
		f(env.Expression)
	}

	for _, v := range env.Vars {
		if v.Value != nil {
			f(v.Value)
		}
	}
}
