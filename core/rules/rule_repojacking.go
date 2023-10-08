package rules

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/rhysd/actionlint"
)

type RuleRepoJacking struct {
	actionlint.RuleBase
}

// NewRuleDangerousAction creates new RuleDangerousAction instance.
func NewRuleRepoJacking() *RuleRepoJacking {
	return &RuleRepoJacking{
		RuleBase: actionlint.NewRuleBase(
			"repo-jacking",
			"Verify that used actions are pointing to a valid GitHub user or organization.",
		),
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

	if idx != -1 {
		owner := spec[:idx]

		requestURL := fmt.Sprintf("https://github.com/%s", owner)
		res, err := http.Get(requestURL)

		if err != nil {
			rule.Errorf(
				e.Uses.Pos,
				"Error while fetching %q: %q. Check you internet connectivity.",
				requestURL,
				err,
			)
		} else if res.StatusCode != http.StatusOK {
			rule.Errorf(
				e.Uses.Pos,
				"Got a %d status code while fetching %q. You might be able to perform a repo-jacking attack to takeover the %q action.",
				res.StatusCode,
				requestURL,
				spec,
			)
		}

		res.Body.Close()
	}

	return nil
}
