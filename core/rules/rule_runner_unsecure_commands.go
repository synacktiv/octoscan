package rules

import (
	"github.com/rhysd/actionlint"
)

type RuleUnsecureCommands struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
}

// NewRuleUnsecureCommands creates new RuleUnsecureCommands instance.
func NewRuleUnsecureCommands(filterTriggers []string) *RuleUnsecureCommands {
	return &RuleUnsecureCommands{
		RuleBase: actionlint.NewRuleBase(
			"unsecure-commands",
			"Check 'ACTIONS_ALLOW_UNSECURE_COMMANDS' env variable.",
		),
		filterTriggers: filterTriggers,
		skip:           false,
	}
}

func (rule *RuleUnsecureCommands) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	if rule.skip {
		return nil
	}

	rule.checkEnv(n.Env)

	return nil
}

func (rule *RuleUnsecureCommands) VisitJobPre(n *actionlint.Job) error {
	if rule.skip {
		return nil
	}

	rule.checkEnv(n.Env)

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleUnsecureCommands) VisitStep(n *actionlint.Step) error {
	if rule.skip {
		return nil
	}

	rule.checkEnv(n.Env)

	return nil
}

func (rule *RuleUnsecureCommands) checkEnv(env *actionlint.Env) {
	if env == nil {
		return
	}

	unsecureCommandEnvVar := env.Vars["actions_allow_unsecure_commands"]
	if unsecureCommandEnvVar != nil {
		rule.Errorf(
			unsecureCommandEnvVar.Name.Pos,
			"environment variable name %q is set.",
			unsecureCommandEnvVar.Name.Value,
		)
	}
}
