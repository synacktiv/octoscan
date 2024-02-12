package rules

import (
	"octoscan/common"

	"github.com/rhysd/actionlint"
)

type RuleUnsecureCommands struct {
	actionlint.RuleBase
	filterTriggersWithExternalInteractions bool
	skip                                   bool
}

// NewRuleUnsecureCommands creates new RuleUnsecureCommands instance.
func NewRuleUnsecureCommands(filterTriggersWithExternalInteractions bool) *RuleUnsecureCommands {
	return &RuleUnsecureCommands{
		RuleBase: actionlint.NewRuleBase(
			"unsecure-commands",
			"Check 'ACTIONS_ALLOW_UNSECURE_COMMANDS' env variable.",
		),
		filterTriggersWithExternalInteractions: filterTriggersWithExternalInteractions,
		skip:                                   false,
	}
}

func (rule *RuleUnsecureCommands) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	if rule.filterTriggersWithExternalInteractions {
		for _, event := range n.On {
			if common.IsStringInArray(common.TriggerWithExternalData, event.EventName()) {
				rule.checkEnv(n.Env)

				return nil
			}
		}

		rule.skip = true
	}

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
