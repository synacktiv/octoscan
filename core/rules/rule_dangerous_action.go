package rules

import (
	"octoscan/common"
	"regexp"
	"strings"

	"github.com/rhysd/actionlint"
)

type RuleDangerousAction struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
	// jobsCache map[string][]string
}

var downloadArtifactActionExternal = []string{
	"dawidd6/action-download-artifact",
	"aochmann/actions-download-artifact",
	"bettermarks/action-artifact-download",
}

var downloadArtifactActionLocal = []string{
	"blablacar/action-download-last-artifact",
}

var dangerousActions = downloadArtifactActionLocal // append(downloadArtifactActionLocal)

// NewRuleDangerousAction creates new RuleDangerousAction instance.
func NewRuleDangerousAction(filterTriggers []string) *RuleDangerousAction {
	return &RuleDangerousAction{
		RuleBase: actionlint.NewRuleBase(
			"dangerous-action",
			"Check for dangerous actions.",
		),
		filterTriggers: filterTriggers,
		skip:           false,
		// jobsCache: map[string][]string{},
	}
}

func (rule *RuleDangerousAction) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleDangerousAction) VisitStep(n *actionlint.Step) error {
	if rule.skip {
		return nil
	}

	switch e := n.Exec.(type) {
	case *actionlint.ExecRun:
		rule.checkDownloadArtifacts(e)

	case *actionlint.ExecAction:
		// trigger alert if action is present
		checkForSpecificActions(&rule.RuleBase, e, dangerousActions)

		// check download actions and verify if external artifacts are used
		rule.checkDownloadActions(e)

		rule.checkDownloadInGitHubScript(e)
	}

	return nil
}

func (rule *RuleDangerousAction) checkDownloadActions(exec *actionlint.ExecAction) {
	spec := exec.Uses.Value

	for _, action := range downloadArtifactActionExternal {
		if strings.HasPrefix(spec, action) {
			if exec.Inputs["repo"] != nil {
				rule.Errorf(
					exec.Inputs["repo"].Value.Pos,
					"Use of action %q with external artifact",
					spec,
				)
			} else {
				rule.Errorf(
					exec.Uses.Pos,
					"Use of action %q",
					spec,
				)
			}
		}
	}
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
			posArray := searchInScript(script.Value.Value, basicRegExp)

			for _, pos := range posArray {
				err := &actionlint.ExprError{
					Message: "Use of \"downloadArtifact\" in \"actions/github-script\" action.",
					Offset:  0,
					Line:    pos.Line,
					Column:  pos.Col,
				}
				err.Column -= len("downloadArtifact")
				exprError(&rule.RuleBase, err, script.Value.Pos.Line, script.Value.Pos.Col)
			}
		}
	}
}

func (rule *RuleDangerousAction) checkDownloadArtifacts(exec *actionlint.ExecRun) {
	script := exec.Run.Value
	p := exec.Run.Pos

	posArray := searchInScript(script, common.GHCliDownloadArtifactsRexexp)

	for _, pos := range posArray {
		err := &actionlint.ExprError{
			Message: "Use of \"gh run download\" in a script.",
			Offset:  0,
			Line:    pos.Line,
			Column:  pos.Col,
		}
		err.Column -= len("gh run download ")
		exprError(&rule.RuleBase, err, p.Line, p.Col)
	}
}
