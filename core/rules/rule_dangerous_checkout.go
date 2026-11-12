package rules

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/synacktiv/octoscan/common"

	"github.com/rhysd/actionlint"
)

type RuleDangerousCheckout struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
	// pull_request_target and workflow_run: the events where actions/checkout refuses fork PR code since v7
	privilegedEvent bool
}

// NewRuleDangerousCheckout creates new RuleDangerousCheckout instance.
func NewRuleDangerousCheckout(filterTriggers []string) *RuleDangerousCheckout {
	return &RuleDangerousCheckout{
		RuleBase: actionlint.NewRuleBase(
			"dangerous-checkout",
			"Check for dangerous checkout.",
		),
		filterTriggers: filterTriggers,
		skip:           false,
	}
}

func (rule *RuleDangerousCheckout) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)
	rule.privilegedEvent = slices.ContainsFunc(n.On, func(e actionlint.Event) bool {
		return e.EventName() == "pull_request_target" || e.EventName() == "workflow_run"
	})

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleDangerousCheckout) VisitStep(n *actionlint.Step) error {

	if rule.skip {
		return nil
	}

	switch e := n.Exec.(type) {
	case *actionlint.ExecRun:
		rule.checkManualCheckout(e)
	case *actionlint.ExecAction:
		rule.checkCheckoutAction(e)
	}

	return nil
}

func (rule *RuleDangerousCheckout) checkCheckoutAction(action *actionlint.ExecAction) {
	if action.Uses.ContainsExpression() {
		// Cannot parse specification made with interpolation. Give up
		return
	}

	spec := action.Uses.Value

	// search for checkout action
	if !strings.HasPrefix(spec, "actions/checkout") {
		return
	}

	// since v7 this input is required to check out fork PR code in a privileged event, setting it is a deliberate opt-out
	if optOut := action.Inputs["allow-unsafe-pr-checkout"]; optOut != nil && !strings.EqualFold(strings.TrimSpace(optOut.Value.Value), "false") {
		rule.Errorf(
			optOut.Value.Pos,
			"Use of 'actions/checkout' with 'allow-unsafe-pr-checkout': the protection against checkouts of fork pull requests is disabled.",
		)
	}

	// basicRegExp := regexp.MustCompile(`github.event.pull_request`)
	if ref := action.Inputs["ref"]; ref != nil && !common.StaticRefRegexp.MatchString(ref.Value.Value) {
		rule.Errorf(
			ref.Value.Pos,
			"Use of 'actions/checkout' with a custom ref.%s",
			rule.protectionNote(spec),
		)
	}

	// the default branch of the fork is attacker controlled too
	if repo := action.Inputs["repository"]; repo != nil && common.ForkRepositoryRegexp.MatchString(repo.Value.Value) {
		rule.Errorf(
			repo.Value.Pos,
			"Use of 'actions/checkout' with the repository of a pull request.%s",
			rule.protectionNote(spec),
		)
	}
}

// protectionNote tells if the checkout action refuses the fork PR checkouts of privileged events.
// Only the floating major tags (v2+) got the protection of v7 backported, pinned versions need to be v7 or later.
func (rule *RuleDangerousCheckout) protectionNote(spec string) string {
	if !rule.privilegedEvent {
		return ""
	}

	_, ref, _ := strings.Cut(spec, "@")

	if major, err := strconv.Atoi(strings.TrimPrefix(ref, "v")); err == nil && strings.HasPrefix(ref, "v") {
		if major >= 2 {
			return fmt.Sprintf(" %q refuses fork pull request code in this event unless 'allow-unsafe-pr-checkout' is set.", spec)
		}

		return fmt.Sprintf(" %q does not have the fork pull request protection of actions/checkout v7.", spec)
	}

	return fmt.Sprintf(" %q is pinned: it has the fork pull request protection only if it is actions/checkout v7 or later.", spec)
}

func (rule *RuleDangerousCheckout) checkManualCheckout(action *actionlint.ExecRun) {
	rule.checkGitManualCheckout(action)
	rule.checkGHCliManualCheckout(action)
}

func (rule *RuleDangerousCheckout) checkGitManualCheckout(action *actionlint.ExecRun) {
	// the name of a created branch is not a ref to check out, blank it keeping the offsets
	script := *action.Run
	script.Value = common.GitNewBranchRegexp.ReplaceAllStringFunc(script.Value, func(m string) string {
		keep := len(common.GitNewBranchRegexp.FindStringSubmatch(m)[1])

		return m[:keep] + strings.Repeat("_", len(m)-keep)
	})

	reportInScript(&rule.RuleBase, &script, common.GitCheckoutBashRexexp, nil, "Use of \"git checkout\" in a bash script with a potentially dangerous reference.")
}

func (rule *RuleDangerousCheckout) checkGHCliManualCheckout(action *actionlint.ExecRun) {
	reportInScript(&rule.RuleBase, action.Run, common.GHCliCheckoutBashRexexp, nil, "Use of \"gh pr checkout\" in a bash script with a potentially dangerous reference.")
}
