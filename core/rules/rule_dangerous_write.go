package rules

import (
	"regexp"

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

	rule.checkWrite(e.Run)

	return nil
}

func (rule *RuleDangerousWrite) checkWrite(script *actionlint.String) {
	// handle by rule_dangerous_expression.go with needsOutputData and stepsOutputData I think
	for _, c := range []struct {
		re, except *regexp.Regexp
		msg        string
	}{
		{common.GitHubOutputPwshRegexp, nil, "Write to \"$GITHUB_OUTPUT\" in a powershell script. It might be a false positive, The regexp must be improved"},
		{common.GitHubOutputBashRegexp, common.LiteralEchoRegexp, "Write to \"$GITHUB_OUTPUT\" in a bash script."},
		{common.GitHubEnvPwshRegexp, nil, "Write to \"$GITHUB_ENV\" in a powershell script. It might be a false positive, The regexp must be improved"},
		{common.GitHubEnvBashRexexp, common.LiteralEchoRegexp, "Write to \"$GITHUB_ENV\" in a bash script."},
	} {
		reportInScript(&rule.RuleBase, script, c.re, c.except, c.msg)
	}
}
