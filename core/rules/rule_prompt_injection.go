package rules

import (
	"regexp"
	"strings"

	"github.com/rhysd/actionlint"
)

// Actions that run an AI agent (lowercase "owner/repo"). The agents have tools, a shell most of the time,
// and the secrets of the job: what an attacker writes in their prompt is a remote code execution.
//
// Based on the research of Aikido (PromptPwnd), Depi (Codex) and Adnan Khan (Clinejection).
var aiAgentActions = []string{
	"anthropics/claude-code-action",
	"anthropics/claude-code-base-action",
	"anthropics/claude-code-security-review",
	"openai/codex-action",
	"google-github-actions/run-gemini-cli",
	"google-gemini/gemini-cli-action",
	"actions/ai-inference",
}

// a bare "Bash" tool: any command (a restricted tool looks like "Bash(git status:*)")
var bareBashToolRegexp = regexp.MustCompile(`(?:^|[\s"',=])Bash(?:[\s"',]|$)`)

type RulePromptInjection struct {
	actionlint.RuleBase
	filterTriggers []string
	skip           bool
	// only the github context: env and the outputs of the steps are not untrusted by themselves in a prompt
	roots        actionlint.UntrustedInputSearchRoots
	workflowEnv  map[string]string // names of the variables holding untrusted data -> the untrusted input
	jobEnv       map[string]string
	aiSteps      map[string]string // id of the steps running an AI agent -> the action
	aiOutputExpr *regexp.Regexp    // steps.<id>.outputs of the AI steps of the job
}

// NewRulePromptInjection creates new RulePromptInjection instance.
func NewRulePromptInjection(filterTriggers []string) *RulePromptInjection {
	return &RulePromptInjection{
		RuleBase: actionlint.NewRuleBase(
			"prompt-injection",
			"Check for AI agents that process untrusted input, that anyone can trigger or that have dangerous tools.",
		),
		filterTriggers: filterTriggers,
		roots:          actionlint.UntrustedInputSearchRoots{"github": actionlint.BuiltinUntrustedInputs["github"]},
	}
}

func (rule *RulePromptInjection) VisitWorkflowPre(n *actionlint.Workflow) error {
	rule.skip = skipAnalysis(n, rule.filterTriggers)
	rule.workflowEnv = rule.untrustedVars(n.Env)

	return nil
}

func (rule *RulePromptInjection) VisitJobPre(n *actionlint.Job) error {
	rule.jobEnv = rule.untrustedVars(n.Env)
	rule.aiSteps = map[string]string{}
	rule.aiOutputExpr = nil

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RulePromptInjection) VisitStep(n *actionlint.Step) error {
	if rule.skip {
		return nil
	}

	switch e := n.Exec.(type) {
	case *actionlint.ExecAction:
		if e.Uses == nil {
			return nil
		}

		if agent := aiAgentName(e.Uses.Value); agent != "" {
			scope := map[string]string{}
			for _, vars := range []map[string]string{rule.workflowEnv, rule.jobEnv, rule.untrustedVars(n.Env)} {
				for name, input := range vars {
					scope[name] = input
				}
			}

			rule.checkAgent(e, agent, scope)

			if n.ID != nil {
				rule.aiSteps[strings.ToLower(n.ID.Value)] = agent
				rule.aiOutputExpr = nil // rebuilt on the next use
			}
		} else if strings.HasPrefix(strings.ToLower(e.Uses.Value), "actions/github-script") && e.Inputs["script"] != nil {
			rule.checkAgentOutput(e.Inputs["script"].Value)
		}
	case *actionlint.ExecRun:
		rule.checkAgentOutput(e.Run)
	}

	return nil
}

// aiAgentName returns the name of the AI agent action used by spec, empty if it is not one.
func aiAgentName(spec string) string {
	path, _, _ := strings.Cut(strings.ToLower(spec), "@")

	for _, agent := range aiAgentActions {
		if path == agent || strings.HasPrefix(path, agent+"/") {
			return agent
		}
	}

	return ""
}

// untrustedRef is an untrusted input ("github.event.issue.title") and where it is in a string.
type untrustedRef struct {
	path   string
	offset int
}

// untrustedPaths returns the untrusted inputs used in the "${{ }}" of s.
func (rule *RulePromptInjection) untrustedPaths(s string) []untrustedRef {
	var res []untrustedRef

	for _, seg := range expressionSegmentsAt(s, false) {
		expr := parseExpr(seg.text)
		if expr == nil {
			continue
		}

		checker := actionlint.NewUntrustedInputChecker(rule.roots)
		checker.Init()
		inspectExprNode(expr, checker)
		checker.OnVisitEnd()

		for _, err := range checker.Errs() {
			// the message starts with the quoted path
			if quoted, _, found := strings.Cut(strings.TrimPrefix(err.Message, `"`), `"`); found {
				// the path is written as is, except with the index syntax: github['event']
				res = append(res, untrustedRef{quoted, seg.offset + max(strings.Index(seg.text, quoted), 0)})
			}
		}
	}

	return res
}

// untrustedVars returns the variables of env that hold untrusted data. They protect from a command injection
// but not from a prompt injection: the agent still reads the value.
func (rule *RulePromptInjection) untrustedVars(env *actionlint.Env) map[string]string {
	res := map[string]string{}

	forEnvVars(env, func(name string, value *actionlint.String) {
		if paths := rule.untrustedPaths(value.Value); len(paths) > 0 {
			res[name] = paths[0].path
		}
	})

	return res
}

func (rule *RulePromptInjection) checkAgent(e *actionlint.ExecAction, agent string, scope map[string]string) {
	for _, input := range e.Inputs {
		rule.checkInputUntrusted(input, agent, scope)
	}

	value := func(name string) *actionlint.String {
		if input := e.Inputs[name]; input != nil {
			return input.Value
		}

		return nil
	}

	switch agent {
	case "anthropics/claude-code-action", "anthropics/claude-code-base-action":
		if v := value("allowed_non_write_users"); v != nil && strings.Contains(v.Value, "*") {
			rule.Errorf(v.Pos, "%s can be triggered by anyone (\"allowed_non_write_users: *\"): any issue or comment is a prompt injection with access to secrets.", agent)
		}

		// the base action has its own input for the tools, the other has them in the arguments
		if v := value("allowed_tools"); v != nil {
			if loc := bareBashToolRegexp.FindStringIndex(v.Value); loc != nil {
				rule.Errorf(posInString(v.Value, v.Pos, v.Quoted, loc[0]+strings.Index(v.Value[loc[0]:loc[1]], "Bash")), "%s is allowed to run any shell command (the \"Bash\" tool without a restriction): a prompt injection is a remote code execution. Allow only the commands needed, like \"Bash(git status:*)\".", agent)
			}
		}

		if v := value("claude_args"); v != nil {
			if i := strings.Index(v.Value, "--dangerously-skip-permissions"); i >= 0 {
				rule.Errorf(posInString(v.Value, v.Pos, v.Quoted, i), "%s runs with \"--dangerously-skip-permissions\": the agent runs any tool without asking.", agent)
			}

			if loc := bareBashToolRegexp.FindStringIndex(v.Value); loc != nil {
				// the match includes the character before "Bash"
				rule.Errorf(posInString(v.Value, v.Pos, v.Quoted, loc[0]+strings.Index(v.Value[loc[0]:loc[1]], "Bash")), "%s is allowed to run any shell command (the \"Bash\" tool without a restriction): a prompt injection is a remote code execution. Allow only the commands needed, like \"Bash(git status:*)\".", agent)
			}
		}
	case "openai/codex-action":
		if v := value("allow-users"); v != nil && strings.Contains(v.Value, "*") {
			note := ""
			if sandbox := value("sandbox"); sandbox != nil && strings.EqualFold(strings.TrimSpace(sandbox.Value), "read-only") {
				note = ` The "read-only" sandbox limits the impact.`
			}

			rule.Errorf(v.Pos, "%s can be triggered by anyone (\"allow-users: *\"): any issue or comment is a prompt injection with access to secrets.%s", agent, note)
		}

		if v := value("safety-strategy"); v != nil && strings.EqualFold(strings.TrimSpace(v.Value), "unsafe") {
			rule.Errorf(v.Pos, "%s runs with \"safety-strategy: unsafe\": the agent has full access to the runner.", agent)
		}

		if v := value("sandbox"); v != nil && strings.EqualFold(strings.TrimSpace(v.Value), "danger-full-access") {
			rule.Errorf(v.Pos, "%s runs with \"sandbox: danger-full-access\": the agent has full access to the runner.", agent)
		}
	case "google-github-actions/run-gemini-cli", "google-gemini/gemini-cli-action":
		for _, input := range e.Inputs {
			if i := strings.Index(input.Value.Value, "run_shell_command"); i >= 0 {
				rule.Errorf(posInString(input.Value.Value, input.Value.Pos, input.Value.Quoted, i), "%s is given a shell tool (\"run_shell_command\"): a prompt injection can run commands, even a restricted list like \"gh issue edit\" is enough to leak the tokens.", agent)
			}
		}
	case "actions/ai-inference":
		if v := value("enable-github-mcp"); v != nil && strings.EqualFold(strings.TrimSpace(v.Value), "true") {
			rule.Errorf(v.Pos, "%s has the GitHub MCP server enabled: a prompt injection can use your GitHub token through the tools of the server.", agent)
		}
	}
}

// checkInputUntrusted reports the untrusted data given to the agent, directly or through a variable.
func (rule *RulePromptInjection) checkInputUntrusted(input *actionlint.Input, agent string, scope map[string]string) {
	if input.Value == nil {
		return
	}

	value := input.Value

	for _, ref := range rule.untrustedPaths(value.Value) {
		rule.Errorf(posInString(value.Value, value.Pos, value.Quoted, ref.offset), "Prompt injection: the untrusted input %q is given to %s in %q.", ref.path, agent, input.Name.Value)
	}

	for name, path := range scope {
		if loc := regexp.MustCompile(`(?:\$\{?|\benv\.)` + regexp.QuoteMeta(name) + `\b`).FindStringIndex(value.Value); loc != nil {
			rule.Errorf(
				posInString(value.Value, value.Pos, value.Quoted, loc[0]),
				"Prompt injection: the variable %q holds the untrusted input %q and is given to %s in %q. A variable protects from a command injection, not from a prompt injection.",
				name, path, agent, input.Name.Value,
			)
		}
	}
}

// checkAgentOutput reports the output of an AI step that is used in a script: it is untrusted too.
func (rule *RulePromptInjection) checkAgentOutput(str *actionlint.String) {
	if str == nil || len(rule.aiSteps) == 0 {
		return
	}

	if rule.aiOutputExpr == nil {
		ids := make([]string, 0, len(rule.aiSteps))
		for id := range rule.aiSteps {
			ids = append(ids, regexp.QuoteMeta(id))
		}

		rule.aiOutputExpr = regexp.MustCompile(`(?i)\bsteps\.(` + strings.Join(ids, "|") + `)\.outputs\b`)
	}

	for _, src := range expressionSegments(str.Value, false) {
		if m := rule.aiOutputExpr.FindStringSubmatch(src); m != nil {
			rule.Errorf(
				str.Pos,
				"The output of the AI agent step %q (%s) is used in a script. It is attacker controlled when the agent read untrusted input: pass it through an environment variable and validate it.",
				m[1], rule.aiSteps[strings.ToLower(m[1])],
			)
		}
	}
}
