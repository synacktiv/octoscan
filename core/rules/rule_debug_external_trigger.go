package rules

import (
	"octoscan/common"

	"github.com/rhysd/actionlint"
)

type RuleDebugExternalTrigger struct {
	actionlint.RuleBase
	filterTriggers []string
}

// NewRuleDebugExternalTrigger creates new RuleDebugExternalTrigger instance.
func NewRuleDebugExternalTrigger(filterTriggers []string) *RuleDebugExternalTrigger {
	return &RuleDebugExternalTrigger{
		RuleBase: actionlint.NewRuleBase(
			"debug-external-trigger",
			"Check for workflow that can be externally triggered.",
		),
		filterTriggers: filterTriggers,
	}
}

func (rule *RuleDebugExternalTrigger) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	for _, event := range n.On {
		if common.IsStringInArray(rule.filterTriggers, event.EventName()) {
			if n.Name != nil {
				rule.Errorf(
					n.Name.Pos,
					"Use of action with %q workflow trigger.",
					event.EventName(),
				)
			}
			// only trigger once even if both trigger are defined
			return nil
		}
	}

	return nil
}
