package rules

import (
	"regexp"
	"slices"
	"strings"

	"github.com/rhysd/actionlint"
)

// reportInScript reports an error at the start of every line of str that matches re (and does not match except, which
// may be nil), once per line.
func reportInScript(rule *actionlint.RuleBase, str *actionlint.String, re, except *regexp.Regexp, msg string) {
	offset := 0 // of the line in the value

	for _, line := range strings.Split(str.Value, "\n") {
		if loc := re.FindStringIndex(line); loc != nil && (except == nil || !except.MatchString(line)) {
			rule.Error(posInString(str.Value, str.Pos, str.Quoted, offset+loc[0]), msg)
		}

		offset += len(line) + 1
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

// exprSegment is the content of a "${{ }}" and where it starts in the string.
type exprSegment struct {
	text   string
	offset int
}

// expressionSegmentsAt returns the content of every "${{ }}" of s. When bare is true and s has none,
// the whole of s is returned: it is an "if:" condition, which does not need the "${{ }}".
func expressionSegmentsAt(s string, bare bool) []exprSegment {
	if !strings.Contains(s, "${{") {
		if bare {
			return []exprSegment{{s, 0}}
		}

		return nil
	}

	var res []exprSegment

	base := 0

	for {
		i := strings.Index(s, "${{")
		if i < 0 {
			return res
		}

		rest := s[i+3:]
		start := base + i + 3

		end := strings.Index(rest, "}}")
		if end < 0 {
			return append(res, exprSegment{rest, start})
		}

		res = append(res, exprSegment{rest[:end], start})
		base = start + end + 2
		s = rest[end+2:]
	}
}

// expressionSegments is expressionSegmentsAt without the offsets.
func expressionSegments(s string, bare bool) []string {
	var res []string

	for _, seg := range expressionSegmentsAt(s, bare) {
		res = append(res, seg.text)
	}

	return res
}

// posInString returns the position of a byte offset of a string value, ready to be reported.
//
// The AST does not have the indentation of a block scalar ("run: |"): the content starts on the line after the key and
// its columns are not in the AST. The column of the lines of such a string is reported as the negative of its
// column counted from the first non-blank character of the line, and core.FixPositions replaces it with the real
// column with the source.
func posInString(value string, pos *actionlint.Pos, quoted bool, offset int) *actionlint.Pos {
	offset = min(offset, len(value))

	if !strings.Contains(value, "\n") {
		col := pos.Col + offset
		if quoted {
			col++ // when the string is quoted like 'foo' or "foo", column should be incremented
		}

		return &actionlint.Pos{Line: pos.Line, Col: col}
	}

	before := value[:offset]
	lineStart := strings.LastIndex(before, "\n") + 1
	line := value[lineStart:]
	blanks := len(line) - len(strings.TrimLeft(line, " \t"))

	return &actionlint.Pos{
		Line: pos.Line + 1 + strings.Count(before, "\n"),
		Col:  -max(offset-lineStart-blanks+1, 1),
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

// forEnvVars calls f on every variable of env.
func forEnvVars(env *actionlint.Env, f func(name string, value *actionlint.String)) {
	if env == nil {
		return
	}

	for _, v := range env.Vars {
		if v.Value != nil {
			f(v.Name.Value, v.Value)
		}
	}
}
