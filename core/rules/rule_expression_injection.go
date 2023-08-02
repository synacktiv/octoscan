package rules

import (
	"strings"

	"github.com/rhysd/actionlint"
)

var envUntrustedInputSearchRoots = actionlint.NewUntrustedInputMap("env")

var needsOutputData = actionlint.NewUntrustedInputMap("needs",
	actionlint.NewUntrustedInputMap("*",
		actionlint.NewUntrustedInputMap("outputs",
			actionlint.NewUntrustedInputMap("*"),
		),
	),
)

var stepsOutputData = actionlint.NewUntrustedInputMap("needs",
	actionlint.NewUntrustedInputMap("*",
		actionlint.NewUntrustedInputMap("outputs",
			actionlint.NewUntrustedInputMap("*"),
		),
	),
)

var customUntrustedInputSearchRoots = []*actionlint.UntrustedInputMap{
	envUntrustedInputSearchRoots,
	needsOutputData,
	stepsOutputData,
}

type RuleExpressionInjection struct {
	actionlint.RuleBase
	customUntrustedInputSearchRoots actionlint.UntrustedInputSearchRoots
}

// NewRuleExpression creates new RuleExpression instance.
func NewRuleExpressionInjection() *RuleExpressionInjection {

	untrustedInputSearchRoots := actionlint.BuiltinUntrustedInputs

	for _, e := range customUntrustedInputSearchRoots {
		untrustedInputSearchRoots.AddRoot(e)
	}

	return &RuleExpressionInjection{
		RuleBase: actionlint.NewRuleBase(
			"expression-injection",
			"Check expression injection.",
		),
		customUntrustedInputSearchRoots: untrustedInputSearchRoots,
	}
}

// VisitStep is callback when visiting Step node.
func (rule *RuleExpressionInjection) VisitStep(n *actionlint.Step) error {
	rule.checkString(n.Name, "jobs.<job_id>.steps.name")

	switch e := n.Exec.(type) {
	case *actionlint.ExecRun:
		rule.checkString(e.Run, "jobs.<job_id>.steps.run")
		rule.checkString(e.Shell, "")
		rule.checkString(e.WorkingDirectory, "jobs.<job_id>.steps.working-directory")
	case *actionlint.ExecAction:
		rule.checkString(e.Uses, "")
		for _, i := range e.Inputs {
			rule.checkString(i.Value, "jobs.<job_id>.steps.with")
		}
		rule.checkString(e.Entrypoint, "")
		rule.checkString(e.Args, "")

	}

	rule.checkEnv(n.Env, "jobs.<job_id>.steps.env") // env: at step level can refer 'env' context (#158)

	if n.ID != nil {
		if n.ID.ContainsExpression() {
			rule.checkString(n.ID, "")
		}
	}

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
