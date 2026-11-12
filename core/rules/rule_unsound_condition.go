package rules

import (
	"regexp"
	"strings"

	"github.com/rhysd/actionlint"
)

var exprSegmentRegexp = regexp.MustCompile(`(?s)\$\{\{.*?\}\}`)

type RuleUnsoundCondition struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
}

// NewRuleUnsoundCondition creates new RuleUnsoundCondition instance.
func NewRuleUnsoundCondition(filterTriggers []string) *RuleUnsoundCondition {
	return &RuleUnsoundCondition{
		RuleBase: actionlint.NewRuleBase(
			"unsound-condition",
			"Check for \"if:\" conditions that can be bypassed or that are always true.",
		),
		filterTriggers: filterTriggers,
	}
}

func (rule *RuleUnsoundCondition) VisitWorkflowPre(n *actionlint.Workflow) error {
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	return nil
}

func (rule *RuleUnsoundCondition) VisitJobPre(n *actionlint.Job) error {
	if !rule.skip {
		rule.checkCondition(n.If)
	}

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleUnsoundCondition) VisitStep(n *actionlint.Step) error {
	if !rule.skip {
		rule.checkCondition(n.If)
	}

	return nil
}

func (rule *RuleUnsoundCondition) checkCondition(cond *actionlint.String) {
	if cond == nil {
		return
	}

	at := func(offset int) *actionlint.Pos { return posInString(cond.Value, cond.Pos, cond.Quoted, offset) }

	// "${{ }}" mixed with text: the condition is a non-empty string, so it is always true.
	// This includes the trailing newline added by the "|" and ">" block scalars.
	if strings.Contains(cond.Value, "${{") && exprSegmentRegexp.ReplaceAllString(cond.Value, "") != "" {
		rule.Errorf(
			at(strings.Index(cond.Value, "${{")),
			"The condition %q mixes \"${{ }}\" with other text, it is a non-empty string and always evaluates to true.",
			strings.TrimSpace(cond.Value),
		)
	}

	for _, seg := range expressionSegmentsAt(cond.Value, true) {
		if expr := parseExpr(seg.text); expr != nil {
			rule.checkExpr(expr, func(node actionlint.ExprNode) *actionlint.Pos { return at(seg.offset + node.Token().Offset) })
		}
	}
}

func (rule *RuleUnsoundCondition) checkExpr(expr actionlint.ExprNode, at func(actionlint.ExprNode) *actionlint.Pos) {
	actionlint.VisitExprNode(expr, func(node, _ actionlint.ExprNode, entering bool) {
		if !entering {
			return
		}

		switch n := node.(type) {
		case *actionlint.FuncCallNode:
			// contains('main develop', github.ref): a substring test, not a membership test
			if strings.EqualFold(n.Callee, "contains") && len(n.Args) == 2 {
				if _, ok := n.Args[0].(*actionlint.StringNode); ok && !isLiteral(n.Args[1]) {
					rule.Error(at(n), "Arguments of \"contains\" are reversed: it checks if the context is a substring of the literal, not if it is one of its values.")
				}
			}
		case *actionlint.LogicalOpNode:
			// cond && '' || other: when the middle value is falsy, "other" is always returned
			if n.Kind == actionlint.LogicalOpNodeKindOr {
				if and, ok := n.Left.(*actionlint.LogicalOpNode); ok && and.Kind == actionlint.LogicalOpNodeKindAnd && isFalsyLiteral(and.Right) {
					rule.Error(at(n), "Unsound ternary: the value between \"&&\" and \"||\" is falsy so the right hand side is always returned.")
				}
			}
		}
	})
}

func isLiteral(n actionlint.ExprNode) bool {
	switch n.(type) {
	case *actionlint.StringNode, *actionlint.IntNode, *actionlint.FloatNode, *actionlint.BoolNode, *actionlint.NullNode:
		return true
	}

	return false
}

func isFalsyLiteral(n actionlint.ExprNode) bool {
	switch v := n.(type) {
	case *actionlint.StringNode:
		return v.Value == ""
	case *actionlint.IntNode:
		return v.Value == 0
	case *actionlint.FloatNode:
		return v.Value == 0
	case *actionlint.BoolNode:
		return !v.Value
	case *actionlint.NullNode:
		return true
	}

	return false
}
