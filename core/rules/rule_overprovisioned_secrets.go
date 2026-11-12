package rules

import (
	"regexp"

	"github.com/rhysd/actionlint"
)

var (
	secretsDumpRegexp    = regexp.MustCompile(`(?i)\btoJSON\(\s*secrets\s*\)`)
	secretsDynamicRegexp = regexp.MustCompile(`(?i)\bsecrets\s*\[\s*[^'"\s\]]`)
)

type RuleOverprovisionedSecrets struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
}

// NewRuleOverprovisionedSecrets creates new RuleOverprovisionedSecrets instance.
func NewRuleOverprovisionedSecrets(filterTriggers []string) *RuleOverprovisionedSecrets {
	return &RuleOverprovisionedSecrets{
		RuleBase: actionlint.NewRuleBase(
			"overprovisioned-secrets",
			"Check for dumps (toJSON(secrets)) and dynamic accesses (secrets[...]) of the secrets context.",
		),
		filterTriggers: filterTriggers,
	}
}

func (rule *RuleOverprovisionedSecrets) VisitWorkflowPre(n *actionlint.Workflow) error {
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	if !rule.skip {
		forEachEnvString(n.Env, rule.check)
	}

	return nil
}

func (rule *RuleOverprovisionedSecrets) VisitJobPre(n *actionlint.Job) error {
	if rule.skip {
		return nil
	}

	forEachEnvString(n.Env, rule.check)

	if n.WorkflowCall != nil {
		for _, input := range n.WorkflowCall.Inputs {
			rule.check(input.Value)
		}
	}

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleOverprovisionedSecrets) VisitStep(n *actionlint.Step) error {
	if rule.skip {
		return nil
	}

	forEachEnvString(n.Env, rule.check)
	rule.check(n.If)

	switch e := n.Exec.(type) {
	case *actionlint.ExecRun:
		rule.check(e.Run)
	case *actionlint.ExecAction:
		for _, input := range e.Inputs {
			rule.check(input.Value)
		}
	}

	return nil
}

func (rule *RuleOverprovisionedSecrets) check(str *actionlint.String) {
	if str == nil {
		return
	}

	for _, expr := range expressionSegments(str.Value, false) {
		if secretsDumpRegexp.MatchString(expr) {
			rule.Error(str.Pos, "The whole \"secrets\" context is dumped with \"toJSON(secrets)\", every secret of the repository is exposed to this step.")
		}

		if secretsDynamicRegexp.MatchString(expr) {
			rule.Error(str.Pos, "A secret is accessed dynamically with \"secrets[...]\", any secret might be selected. Reference the needed secrets by name.")
		}
	}
}
