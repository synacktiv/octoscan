/*
the MIT License

Copyright (c) 2021 rhysd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

/*
this is a copy of https://github.com/rhysd/actionlint/blob/main/rule_expression.go
I need to add new UntrustedInput and check for expression injection in some fileds but not all.
*/

package rules

import (
	"strings"

	"github.com/rhysd/actionlint"
)

// var envUntrustedInputSearchRoots = actionlint.NewUntrustedInputMap("env")

var needsOutputData = actionlint.NewUntrustedInputMap("needs",
	actionlint.NewUntrustedInputMap("**",
		actionlint.NewUntrustedInputMap("outputs",
			actionlint.NewUntrustedInputMap("**"),
		),
	),
)

var stepsOutputData = actionlint.NewUntrustedInputMap("steps",
	actionlint.NewUntrustedInputMap("**",
		actionlint.NewUntrustedInputMap("outputs",
			actionlint.NewUntrustedInputMap("**"),
		),
	),
)

var CustomUntrustedInputSearchRoots = []*actionlint.UntrustedInputMap{
	// envUntrustedInputSearchRoots,
	needsOutputData,
	stepsOutputData,
}

type RuleExpressionInjection struct {
	actionlint.RuleBase
	customUntrustedInputSearchRoots actionlint.UntrustedInputSearchRoots
	filterTriggers                  []string
	skip                            bool
	filterRun                       bool
}

// NewRuleExpressionInjection creates new RuleExpressionInjection instance.
func NewRuleExpressionInjection(filterTriggers []string, filterRun bool) *RuleExpressionInjection {
	return &RuleExpressionInjection{
		RuleBase: actionlint.NewRuleBase(
			"expression-injection",
			"Check expression injection.",
		),
		// note that the map is overloaded in init.go
		customUntrustedInputSearchRoots: actionlint.BuiltinUntrustedInputs,
		filterTriggers:                  filterTriggers,
		skip:                            false,
		filterRun:                       filterRun,
	}
}

func (rule *RuleExpressionInjection) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleExpressionInjection) VisitStep(n *actionlint.Step) error {

	if rule.skip {
		return nil
	}

	// rule.checkString(n.Name, "jobs.<job_id>.steps.name")

	switch e := n.Exec.(type) {
	case *actionlint.ExecRun:
		rule.checkString(e.Run, "jobs.<job_id>.steps.run")
		// rule.checkString(e.Shell, "")
		rule.checkString(e.WorkingDirectory, "jobs.<job_id>.steps.working-directory")
	case *actionlint.ExecAction:

		if !rule.filterRun {
			rule.checkString(e.Uses, "")

			for _, i := range e.Inputs {
				rule.checkString(i.Value, "jobs.<job_id>.steps.with")
			}

			rule.checkString(e.Entrypoint, "")
			rule.checkString(e.Args, "")
		}

	}

	// rule.checkEnv(n.Env, "jobs.<job_id>.steps.env") // env: at step level can refer 'env' context (#158)

	// if n.ID != nil {
	// 	if n.ID.ContainsExpression() {
	// 		rule.checkString(n.ID, "")
	// 	}
	// }

	return nil
}

// I merged checkString and checkScriptString for now
func (rule *RuleExpressionInjection) checkString(str *actionlint.String, workflowKey string) {
	if str == nil {
		return
	}

	rule.checkExprsIn(str.Value, str.Pos, str.Quoted, true, workflowKey)
}

func (rule *RuleExpressionInjection) checkEnv(env *actionlint.Env, workflowKey string) {
	if env == nil {
		return
	}

	if env.Vars != nil {
		for _, e := range env.Vars {
			rule.checkString(e.Name, workflowKey)
			rule.checkString(e.Value, workflowKey)
		}
		return
	}
}

func (rule *RuleExpressionInjection) checkExprsIn(s string, pos *actionlint.Pos, quoted, checkUntrusted bool, workflowKey string) {
	// TODO: Line number is not correct when the string contains newlines.

	line, col := pos.Line, pos.Col
	if quoted {
		col++ // when the string is quoted like 'foo' or "foo", column should be incremented
	}

	if len(strings.Split(s, "\n")) != 1 {
		line++
	}

	offset := 0
	for {
		idx := strings.Index(s, "${{")
		if idx == -1 {
			break
		}

		start := idx + 3 // 3 means removing "${{"
		s = s[start:]
		offset += start
		col := col + offset

		offsetAfter, ok := rule.checkSemantics(s, line, col, checkUntrusted, workflowKey)
		if !ok {
			return
		}

		s = s[offsetAfter:]
		offset += offsetAfter
	}
}

func (rule *RuleExpressionInjection) checkSemantics(src string, line, col int, checkUntrusted bool, workflowKey string) (int, bool) {
	l := actionlint.NewExprLexer(src)
	p := actionlint.NewExprParser()
	expr, err := p.Parse(l)
	if err != nil {
		return l.Offset(), false
	}

	ok := rule.checkExprNode(expr, line, col, checkUntrusted, workflowKey)
	return l.Offset(), ok
}

func (rule *RuleExpressionInjection) exprError(err *actionlint.ExprError, lineBase, colBase int) {
	pos := convertExprLineColToPos(err.Line, err.Column, lineBase, colBase)
	rule.Error(pos, err.Message)
}

func (rule *RuleExpressionInjection) checkExprNode(expr actionlint.ExprNode, line, col int, checkUntrusted bool, workflowKey string) bool {
	errs := rule.checkExpressionInjection(expr)
	for _, err := range errs {
		rule.exprError(err, line, col)
	}

	return len(errs) == 0
}

func convertExprLineColToPos(line, col, lineBase, colBase int) *actionlint.Pos {
	// Line and column in ExprError are 1-based
	return &actionlint.Pos{
		Line: line - 1 + lineBase,
		Col:  col - 1 + colBase,
	}
}

func (rule *RuleExpressionInjection) checkExpressionInjection(expr actionlint.ExprNode) []*actionlint.ExprError {
	errs := []*actionlint.ExprError{}

	untrusted := actionlint.NewUntrustedInputChecker(rule.customUntrustedInputSearchRoots)
	untrusted.Init()

	inspectExprNode(expr, untrusted)

	untrusted.OnVisitEnd()
	errs = append(errs, untrusted.Errs()...)

	return errs
}

// that's crapy code but the rule_expression.go from actionlint enfore all expression checks
// I just want insecure checks but I can't add new methods to non local package
func inspectExprNode(expr actionlint.ExprNode, untrusted *actionlint.UntrustedInputChecker) {
	defer untrusted.OnVisitNodeLeave(expr)

	switch e := expr.(type) {
	case *actionlint.ObjectDerefNode:
		checkObjectDeref(e, untrusted)
	case *actionlint.IndexAccessNode:
		checkIndexAccess(e, untrusted)
	case *actionlint.ArrayDerefNode:
		checkArrayDeref(e, untrusted)
	case *actionlint.FuncCallNode:
		checkFuncCall(e, untrusted)
	}
}

func checkObjectDeref(n *actionlint.ObjectDerefNode, untrusted *actionlint.UntrustedInputChecker) {
	inspectExprNode(n.Receiver, untrusted)
}

func checkIndexAccess(n *actionlint.IndexAccessNode, untrusted *actionlint.UntrustedInputChecker) {
	inspectExprNode(n.Index, untrusted)
	inspectExprNode(n.Operand, untrusted)
}

func checkArrayDeref(n *actionlint.ArrayDerefNode, untrusted *actionlint.UntrustedInputChecker) {
	inspectExprNode(n.Receiver, untrusted)
}

func checkFuncCall(n *actionlint.FuncCallNode, untrusted *actionlint.UntrustedInputChecker) {
	for _, a := range n.Args {
		inspectExprNode(a, untrusted)
	}
}

// VisitWorkflowPost is callback when visiting Workflow node after visiting its children
func (rule *RuleExpressionInjection) VisitWorkflowPost(n *actionlint.Workflow) error {

	if !rule.skip {
		cleanLogMessages(rule.Errs())
	}

	return nil
}

func cleanLogMessages(errs []*actionlint.Error) {
	for _, e := range errs {
		msg := strings.Split(e.Message, ". ")
		e.Message = "Expression injection, " + msg[0] + "."
	}
}
