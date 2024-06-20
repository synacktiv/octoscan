package rules

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/synacktiv/octoscan/common"

	"github.com/rhysd/actionlint"
)

// stolen from actionlint.PopularActions
var knwonOrgs = []string{
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

type RuleRepoJacking struct {
	actionlint.RuleBase
	allActions map[string][]map[string]*actionlint.Pos
}

// NewRuleRepoJacking creates new RuleRepoJacking instance.
func NewRuleRepoJacking() *RuleRepoJacking {
	return &RuleRepoJacking{
		RuleBase: actionlint.NewRuleBase(
			"repo-jacking",
			"Verify that external actions are pointing to a valid GitHub user or organization.",
		),
		allActions: make(map[string][]map[string]*actionlint.Pos),
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
	idx := strings.IndexRune(spec, '/')

	if idx != -1 && !strings.HasPrefix(spec, "./") && !strings.HasPrefix(spec, "docker://") {
		owner := spec[:idx]

		rule.allActions[owner] = append(rule.allActions[owner], map[string]*actionlint.Pos{spec: e.Uses.Pos})
	}

	return nil
}

// VisitWorkflowPost is callback when visiting Workflow node after visiting its children
func (rule *RuleRepoJacking) VisitWorkflowPost(n *actionlint.Workflow) error {
	for key, value := range rule.allActions {
		// don't fetch known org to prevent multiple access to the API
		if isKnownOrg(key) {
			continue
		}

		requestURL := fmt.Sprintf("https://github.com/%s", key)
		res, err := http.Get(requestURL)

		if err != nil {
			rule.Errorf(
				&actionlint.Pos{Line: 0, Col: 0},
				"Error while fetching %q: %q. Check you internet connectivity.",
				requestURL,
				err,
			)

			return err
		}

		var sleepTime = 1

		// retry while getting 429 status code
		for res.StatusCode == http.StatusTooManyRequests {
			common.Log.Debug(fmt.Sprintf("Got 429 while fetching GitHub sleeping %d seconds.", sleepTime))
			time.Sleep(time.Duration(sleepTime) * time.Second)
			sleepTime++

			requestURL := fmt.Sprintf("https://github.com/%s", key)
			res, err = http.Get(requestURL)

			if err != nil {
				rule.Errorf(
					&actionlint.Pos{Line: 0, Col: 0},
					"Error while fetching %q: %q. Check you internet connectivity.",
					requestURL,
					err,
				)
			}
		}

		// raise an error for all associated actions call
		if res.StatusCode != http.StatusOK {

			for _, actions := range value {
				for action, pos := range actions {
					rule.Errorf(
						pos,
						"Got a %d status code while fetching %q. You might be able to perform a repo-jacking attack to takeover the %q action.",
						res.StatusCode,
						requestURL,
						action,
					)
				}
			}
		}
	}

	return nil
}

func isKnownOrg(org string) bool {
	for _, known := range knwonOrgs {
		if known == org {
			return true
		}
	}

	return false
}
