package rules

import (
	"regexp"
	"strings"

	"github.com/rhysd/actionlint"
)

type RuleDebugJSExec struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
}

// NewRuleDebugJSExec creates new RuleDebugJSExec instance.
func NewRuleDebugJSExec(filterTriggers []string) *RuleDebugJSExec {
	return &RuleDebugJSExec{
		RuleBase: actionlint.NewRuleBase(
			"debug-js-exec",
			"Check for workflow that execute system commands in JS scripts.",
		),
		filterTriggers: filterTriggers,
		skip:           false,
	}
}

func (rule *RuleDebugJSExec) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleDebugJSExec) VisitStep(n *actionlint.Step) error {
	if rule.skip {
		return nil
	}

	e, ok := n.Exec.(*actionlint.ExecAction)
	if !ok {
		return nil
	}

	rule.checkJSExec(e)

	return nil
}

var jsExecRegexp = regexp.MustCompile(`(?m)exec.exec\(`)

func (rule *RuleDebugJSExec) checkJSExec(exec *actionlint.ExecAction) {
	spec := exec.Uses.Value

	if strings.HasPrefix(spec, "actions/github-script") {
		if script := exec.Inputs["script"]; script != nil {
			reportInScript(&rule.RuleBase, script.Value, jsExecRegexp, nil, "Use of \"exec.exec()\" in \"actions/github-script\" action.")
		}
	}
}
