package rules

import (
	"octoscan/common"
	"regexp"
	"strings"

	"github.com/rhysd/actionlint"
)

type RuleDangerousAction struct {
	actionlint.RuleBase
	filterTriggersWithExternalInteractions bool
	skip                                   bool
	// jobsCache map[string][]string
}

var dangerousActions = []string{
	"dawidd6/action-download-artifact",
	"aochmann/actions-download-artifact",
	"bettermarks/action-artifact-download",
	"blablacar/action-download-last-artifact",
}

// NewRuleDangerousAction creates new RuleDangerousAction instance.
func NewRuleDangerousAction(filterTriggersWithExternalInteractions bool) *RuleDangerousAction {
	return &RuleDangerousAction{
		RuleBase: actionlint.NewRuleBase(
			"dangerous-action",
			"Check for dangerous actions.",
		),
		filterTriggersWithExternalInteractions: filterTriggersWithExternalInteractions,
		skip:                                   false,
		// jobsCache: map[string][]string{},
	}
}

func (rule *RuleDangerousAction) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	if rule.filterTriggersWithExternalInteractions {
		for _, event := range n.On {
			if common.IsStringInArray(common.TriggerWithExternalData, event.EventName()) {
				// don't skip, skip is false by default
				return nil
			}
		}

		rule.skip = true
	}

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleDangerousAction) VisitStep(n *actionlint.Step) error {
	if rule.skip {
		return nil
	}

	e, ok := n.Exec.(*actionlint.ExecAction)
	if !ok || e.Uses == nil {
		return nil
	}

	rule.checkDangerousActions(e)
	rule.checkDownloadInGitHubScript(e)

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

func (rule *RuleDangerousAction) checkDangerousActions(exec *actionlint.ExecAction) {
	spec := exec.Uses.Value

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

func (rule *RuleDangerousAction) checkDownloadInGitHubScript(exec *actionlint.ExecAction) {
	spec := exec.Uses.Value

	if strings.HasPrefix(spec, "actions/github-script") {
		basicRegExp := regexp.MustCompile(`(?m)downloadArtifact`)
		script := exec.Inputs["script"]

		if script != nil {
			pos := searchInScript(script.Value.Value, basicRegExp)

			if pos != nil {
				err := &actionlint.ExprError{
					Message: "Use of \"downloadArtifact\" in \"actions/github-script\" action.",
					Offset:  0,
					Line:    pos.Line,
					Column:  pos.Col,
				}
				err.Column -= len("downloadArtifact")
				rule.exprError(err, script.Value.Pos.Line, script.Value.Pos.Col)
			}
		}
	}
}

func (rule *RuleDangerousAction) exprError(err *actionlint.ExprError, lineBase, colBase int) {
	pos := exprLineColToPos(err.Line, err.Column, lineBase, colBase)
	rule.Error(pos, err.Message)
}
