package rules

import (
	"strings"

	"github.com/rhysd/actionlint"
)

type RuleDangerousAction struct {
	actionlint.RuleBase
	// jobsCache map[string][]string
}

var dangerousActions = []string{
	"dawidd6/action-download-artifact",
	"aochmann/actions-download-artifact",
	"bettermarks/action-artifact-download",
	"blablacar/action-download-last-artifact",
}

// NewRuleDangerousAction creates new RuleDangerousAction instance.
func NewRuleDangerousAction() *RuleDangerousAction {
	return &RuleDangerousAction{
		RuleBase: actionlint.NewRuleBase(
			"dangerous-action",
			"Check for dangerous actions.",
		),
		// jobsCache: map[string][]string{},
	}
}

// VisitStep is callback when visiting Step node.
func (rule *RuleDangerousAction) VisitStep(n *actionlint.Step) error {
	e, ok := n.Exec.(*actionlint.ExecAction)
	if !ok || e.Uses == nil {
		return nil
	}

	spec := e.Uses.Value

	rule.checkDangerousActions(spec, e)

	return nil
}

// VisitWorkflowPost is callback when visiting Workflow node after visiting its children.
//func (rule *RuleDangerousAction) VisitWorkflowPost(n *actionlint.Workflow) error {
//	for _, e := range n.On {
//		rule.checkUploadArtifactAfterPR(e)
//	}
//	return nil
//}

//func (rule *RuleDangerousAction) checkUploadArtifactAfterPR(event actionlint.Event) {
//
//	switch e := event.(type) {
//	case *actionlint.WebhookEvent:
//		rule.checkWebhookEvent(e)
//	default:
//		panic("unreachable")
//	}
//}

// https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#webhook-events
//func (rule *RuleDangerousAction) checkWebhookEvent(event *actionlint.WebhookEvent) {
//	hook := event.Hook.Value
//
//	_, ok := actionlint.AllWebhookTypes[hook]
//	if !ok {
//		return
//	}
//
//	if hook == "pull_request" {
//		if len(event.Workflows) == 0 {
//			//rule.Error(event.Pos, "no workflow is configured for \"workflow_run\" event")
//		}
//	}
//
//}

func (rule *RuleDangerousAction) checkDangerousActions(spec string, exec *actionlint.ExecAction) {
	for _, action := range dangerousActions {
		if strings.HasPrefix(spec, action) {
			rule.Errorf(
				exec.Uses.Pos,
				"Use of dangerous action %q",
				spec,
			)
		}
	}
}

// func (rule *RuleDangerousAction) fillJobsCache(n *actionlint.Job) {
// 	externalActionsCache := []string{}
// 	for _, step := range n.Steps {
// 		e, ok := step.Exec.(*actionlint.ExecAction)
// 		if !ok || e.Uses == nil {
// 			continue
// 		}
// 		externalActionsCache = append(externalActionsCache, e.Uses.Value)
// 	}
//
// 	rule.jobsCache[n.ID.Value] = externalActionsCache
// }
