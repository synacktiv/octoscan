package rules

import (
	"slices"
	"strings"

	"github.com/rhysd/actionlint"
)

type RuleDangerousArtefact struct {
	actionlint.RuleBase
	filterTriggers       []string
	skip                 bool
	persistedCredentials bool // a checkout of the job left the token in .git/config
}

// paths that include the whole workspace
var sensitivePaths = []string{
	".",
	"./",
	".\\",
	"..",
	"*",
	"**",
	"./**",
	".*",
	"~",
}

// NewRuleOIDCAction creates new RuleOIDCAction instance.
func NewRuleRuleDangerousArtefact(filterTriggers []string) *RuleDangerousArtefact {
	return &RuleDangerousArtefact{
		RuleBase: actionlint.NewRuleBase(
			"dangerous-artefact",
			"Check for workflow that upload artefacts containing sensitive files.",
		),
		filterTriggers: filterTriggers,
		skip:           false,
	}
}

func (rule *RuleDangerousArtefact) VisitWorkflowPre(n *actionlint.Workflow) error {
	// check on event and set skip if needed
	rule.skip = skipAnalysis(n, rule.filterTriggers)

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleDangerousArtefact) VisitStep(n *actionlint.Step) error {
	if rule.skip {
		return nil
	}

	e, ok := n.Exec.(*actionlint.ExecAction)
	if !ok || e.Uses == nil {
		return nil
	}

	spec := e.Uses.Value

	switch {
	case strings.HasPrefix(spec, "actions/checkout"):
		// the token is persisted in .git/config unless it is explicitly disabled
		persist := e.Inputs["persist-credentials"]
		if persist == nil || !strings.EqualFold(strings.TrimSpace(persist.Value.Value), "false") {
			rule.persistedCredentials = true
		}
	case strings.HasPrefix(spec, "actions/upload-artifact"):
		rule.checkUpload(e)
	}

	return nil
}

// ponytail: upload-artifact v4 skips hidden files by default so a broad path only leaks .git with
// include-hidden-files, we report it anyway, narrow down if it is too noisy.
func (rule *RuleDangerousArtefact) checkUpload(e *actionlint.ExecAction) {
	path := e.Inputs["path"]
	if path == nil {
		return
	}

	offset := 0 // of the line in the value

	for _, line := range strings.Split(path.Value.Value, "\n") {
		p := strings.TrimSpace(line)
		pos := posInString(path.Value.Value, path.Value.Pos, path.Value.Quoted, offset+strings.Index(line, p))
		offset += len(line) + 1

		switch {
		case p == "" || strings.HasPrefix(p, "!"):
		case includesGitDir(p):
			rule.Errorf(
				pos,
				"Use of action 'actions/upload-artifact' with a path including the .git directory %q%s",
				p,
				rule.credentialsNote(),
			)
		case slices.Contains(sensitivePaths, p):
			rule.Errorf(
				pos,
				"Use of action 'actions/upload-artifact' with a sensitive path %q%s",
				p,
				rule.credentialsNote(),
			)
		}
	}
}

func (rule *RuleDangerousArtefact) credentialsNote() string {
	if rule.persistedCredentials {
		return ", a previous checkout persists the credentials in .git/config (set \"persist-credentials: false\")"
	}

	return ""
}

func includesGitDir(p string) bool {
	return slices.Contains(strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }), ".git")
}

func (rule *RuleDangerousArtefact) VisitJobPost(job *actionlint.Job) error {
	// reset for each job
	rule.persistedCredentials = false

	return nil
}
