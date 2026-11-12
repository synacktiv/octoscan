package rules

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/synacktiv/octoscan/common"

	"github.com/rhysd/actionlint"
)

// stolen from actionlint.PopularActions
var knownOrgs = []string{
	"aochmann",
	"bettermarks",
	"blablacar",
	"8398a7",
	"actions",
	"actions-cool",
	"actions-rs",
	"aws-actions",
	"azure",
	"Azure",
	"bahmutov",
	"codecov",
	"dawidd6",
	"dessant",
	"docker",
	"dorny",
	"dtolnay",
	"EnricoMi",
	"enriikke",
	"erlef",
	"game-ci",
	"getsentry",
	"github",
	"githubocto",
	"golangci",
	"goreleaser",
	"gradle",
	"haskell",
	"JamesIves",
	"marvinpinto",
	"microsoft",
	"mikepenz",
	"msys2",
	"ncipollo",
	"nwtgck",
	"octokit",
	"peaceiris",
	"peter-evans",
	"preactjs",
	"ReactiveCircus",
	"reviewdog",
	"rhysd",
	"ridedott",
	"rtCamp",
	"ruby",
	"shivammathur",
	"softprops",
	"subosito",
	"Swatinem",
	"treosh",
	"wearerequired",
}

type actionUse struct {
	spec string
	pos  *actionlint.Pos
}

type RuleRepoJacking struct {
	actionlint.RuleBase
	actionsByOwner map[string][]actionUse
}

// NewRuleRepoJacking creates new RuleRepoJacking instance.
func NewRuleRepoJacking() *RuleRepoJacking {
	return &RuleRepoJacking{
		RuleBase: actionlint.NewRuleBase(
			"repo-jacking",
			"Verify that external actions are pointing to a valid GitHub user or organization.",
		),
		actionsByOwner: make(map[string][]actionUse),
	}
}

// VisitStep is callback when visiting Step node.
func (rule *RuleRepoJacking) VisitStep(n *actionlint.Step) error {
	e, ok := n.Exec.(*actionlint.ExecAction)
	if !ok || e.Uses == nil {
		return nil
	}

	spec := e.Uses.Value

	// Parse {owner}/{repo}@{ref} or {owner}/{repo}/{path}@{ref}
	// "./" and "$/" are references to the caller repository
	owner, _, found := strings.Cut(spec, "/")
	if !found || owner == "." || owner == "$" || strings.HasPrefix(spec, "docker://") {
		return nil
	}

	rule.actionsByOwner[owner] = append(rule.actionsByOwner[owner], actionUse{spec, e.Uses.Pos})

	return nil
}

// VisitWorkflowPost is callback when visiting Workflow node after visiting its children
func (rule *RuleRepoJacking) VisitWorkflowPost(n *actionlint.Workflow) error {
	for owner, uses := range rule.actionsByOwner {
		// don't fetch known org to prevent multiple access to the API
		if slices.Contains(knownOrgs, owner) {
			continue
		}

		requestURL := "https://github.com/" + owner

		status, err := fetchStatus(requestURL)
		if err != nil {
			rule.Errorf(
				&actionlint.Pos{Line: 0, Col: 0},
				"Error while fetching %q: %q. Check you internet connectivity.",
				requestURL,
				err,
			)

			// the other owners might still be reachable
			continue
		}

		// raise an error for all associated actions call
		if status != http.StatusOK {
			for _, use := range uses {
				rule.Errorf(
					use.pos,
					"Got a %d status code while fetching %q. You might be able to perform a repo-jacking attack to takeover the %q action.",
					status,
					requestURL,
					use.spec,
				)
			}
		}
	}

	return nil
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

// fetchStatus returns the status code of url, waiting and retrying while GitHub answers 429.
func fetchStatus(url string) (int, error) {
	const maxRetries = 10

	for sleepTime := 1; ; sleepTime++ {
		res, err := httpClient.Get(url)
		if err != nil {
			return 0, err
		}

		res.Body.Close()

		if res.StatusCode != http.StatusTooManyRequests || sleepTime > maxRetries {
			return res.StatusCode, nil
		}

		common.Log.Debug(fmt.Sprintf("Got 429 while fetching GitHub sleeping %d seconds.", sleepTime))
		time.Sleep(time.Duration(sleepTime) * time.Second)
	}
}
