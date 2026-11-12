package core

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/rhysd/actionlint"
	"github.com/synacktiv/octoscan/common"
)

// step builds a workflow with the given triggers and one step (already indented by 6 spaces).
func step(on, stepYAML string) string {
	return "on: " + on + "\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + stepYAML
}

// ruleCase is one positive (want > 0) or negative (want == 0) sample of a rule.
type ruleCase struct {
	name string
	src  string
	want int
}

func runCases(t *testing.T, rule string, cases []ruleCase) {
	t.Helper()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := len(lint(t, rule, c.src)); got != c.want {
				t.Fatalf("%s: got %d findings, want %d", rule, got, c.want)
			}
		})
	}
}

func TestRuleDangerousAction(t *testing.T) {
	const on = "pull_request_target"

	runCases(t, "dangerous-action", []ruleCase{
		{"external download action", step(on, "      - uses: dawidd6/action-download-artifact@v6\n"), 1},
		{"external download action with repo", step(on, "      - uses: dawidd6/action-download-artifact@v6\n        with:\n          repo: foo/bar\n"), 1},
		{"local download action", step(on, "      - uses: blablacar/action-download-last-artifact@v1\n"), 1},
		{"gh run download", step(on, "      - run: gh run download 1234\n"), 1},
		{"downloadArtifact in github-script", step(on, "      - uses: actions/github-script@v7\n        with:\n          script: |\n            await github.rest.actions.downloadArtifact({})\n"), 1},
		{"official download-artifact", step(on, "      - uses: actions/download-artifact@v4\n"), 0},
		{"gh run list", step(on, "      - run: gh run list\n"), 0},
	})
}

func TestRuleDangerousCheckout(t *testing.T) {
	const on = "pull_request_target"

	runCases(t, "dangerous-checkout", []ruleCase{
		{"checkout action with PR ref", step(on, "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"), 1},
		{"checkout action with static ref", step(on, "      - uses: actions/checkout@v4\n        with:\n          ref: main\n"), 0},
		{"checkout action without ref", step(on, "      - uses: actions/checkout@v4\n"), 0},
		{"git checkout with variable", step(on, "      - run: git checkout $REF\n"), 1},
		{"gh pr checkout with variable", step(on, "      - run: gh pr checkout $PR\n"), 1},
		{"git checkout static", step(on, "      - run: git checkout main\n"), 0},
	})
}

func TestRuleDangerousCheckoutPRProtection(t *testing.T) {
	co := func(uses, input string) string {
		return "      - uses: " + uses + "\n        with:\n          " + input + "\n"
	}
	const prHead = "ref: ${{ github.event.pull_request.head.sha }}"

	runCases(t, "dangerous-checkout", []ruleCase{
		// opt-out of the protection of actions/checkout v7
		{"opt-out", step("pull_request_target", co("actions/checkout@v7", "allow-unsafe-pr-checkout: true")), 1},
		{"opt-out with an expression", step("pull_request_target", co("actions/checkout@v7", "allow-unsafe-pr-checkout: ${{ inputs.unsafe }}")), 1},
		{"opt-out and PR ref", step("pull_request_target", "      - uses: actions/checkout@v7\n        with:\n          allow-unsafe-pr-checkout: true\n          "+prHead+"\n"), 2},
		{"opt-out explicitly disabled", step("pull_request_target", co("actions/checkout@v7", "allow-unsafe-pr-checkout: false")), 0},
		// repository of the fork
		{"fork repository", step("pull_request_target", co("actions/checkout@v7", "repository: ${{ github.event.pull_request.head.repo.full_name }}")), 1},
		{"fork repository of a workflow_run", step("workflow_run", co("actions/checkout@v7", "repository: ${{ github.event.workflow_run.head_repository.full_name }}")), 1},
		{"base repository", step("pull_request_target", co("actions/checkout@v7", "repository: ${{ github.repository }}")), 0},
		{"static other repository", step("pull_request_target", co("actions/checkout@v7", "repository: octocat/hello")), 0},
	})

	notes := []struct{ name, on, uses, want string }{
		{"floating major refuses", "pull_request_target", "actions/checkout@v4", "refuses fork pull request code"},
		{"v7 refuses", "workflow_run", "actions/checkout@v7", "refuses fork pull request code"},
		{"v1 is not protected", "pull_request_target", "actions/checkout@v1", "does not have the fork pull request protection"},
		{"pinned SHA", "pull_request_target", "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", "is pinned"},
		{"patch version", "pull_request_target", "actions/checkout@v4.2.2", "is pinned"},
		{"event without the protection", "issue_comment", "actions/checkout@v4", ""},
	}

	for _, n := range notes {
		t.Run("note "+n.name, func(t *testing.T) {
			errs := lint(t, "dangerous-checkout", step(n.on, co(n.uses, prHead)))
			if len(errs) != 1 {
				t.Fatalf("got %d findings, want 1", len(errs))
			}

			if n.want == "" && strings.Contains(errs[0].Message, "protection") {
				t.Fatalf("unexpected note: %s", errs[0].Message)
			}

			if !strings.Contains(errs[0].Message, n.want) {
				t.Fatalf("message %q does not contain %q", errs[0].Message, n.want)
			}
		})
	}
}

func TestRuleExpressionInjection(t *testing.T) {
	runCases(t, "expression-injection", []ruleCase{
		{"untrusted input in run", step("issues", "      - run: echo \"${{ github.event.issue.title }}\"\n"), 1},
		{"untrusted input in action input", step("issues", "      - uses: actions/foo@v1\n        with:\n          x: ${{ github.event.issue.title }}\n"), 1},
		{"untrusted input in github-script", step("issues", "      - uses: actions/github-script@v7\n        with:\n          script: |\n            console.log(\"${{ github.event.issue.title }}\")\n"), 1},
		{"trusted input", step("issues", "      - run: echo \"${{ github.sha }}\"\n"), 0},
		{"input passed through env", step("issues", "      - run: echo \"$TITLE\"\n        env:\n          TITLE: ${{ github.event.issue.title }}\n"), 0},
	})
}

func TestRuleDangerousWrite(t *testing.T) {
	runCases(t, "dangerous-write", []ruleCase{
		{"bash output", step("push", "      - run: echo \"a=$B\" >> \"$GITHUB_OUTPUT\"\n"), 1},
		{"bash env", step("push", "      - run: echo \"a=$B\" >> \"$GITHUB_ENV\"\n"), 1},
		{"pwsh output", step("push", "      - shell: pwsh\n        run: echo \"a=$env:B\" >> $env:GITHUB_OUTPUT\n"), 1},
		{"pwsh env", step("push", "      - shell: pwsh\n        run: echo \"a=$env:B\" >> $env:GITHUB_ENV\n"), 1},
		{"literal value", step("push", "      - run: echo \"a=b\" >> \"$GITHUB_OUTPUT\"\n"), 0},
		{"no write", step("push", "      - run: echo hello\n"), 0},
	})
}

func TestRuleLocalAction(t *testing.T) {
	runCases(t, "local-action", []ruleCase{
		{"local action", step("push", "      - uses: ./.github/actions/foo\n"), 1},
		{"self repository action", step("push", "      - uses: $/.github/actions/foo\n"), 1},
		{"local reusable workflow", "on: push\njobs:\n  j:\n    uses: ./.github/workflows/foo.yml\n", 1},
		{"external action", step("push", "      - uses: actions/checkout@v4\n"), 0},
	})
}

func TestRuleDangerousArtefact(t *testing.T) {
	up := func(path string) string {
		return "      - uses: actions/upload-artifact@v4\n        with:\n          name: a\n          path: " + path + "\n"
	}
	checkout := func(persist string) string {
		if persist == "" {
			return "      - uses: actions/checkout@v4\n"
		}

		return "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: " + persist + "\n"
	}

	runCases(t, "dangerous-artefact", []ruleCase{
		{"upload the whole workspace", step("push", up(".")), 1},
		{"upload ./", step("push", up("./")), 1},
		{"upload everything with a glob", step("push", up("'**'")), 1},
		{"upload home", step("push", up("'~'")), 1},
		{"upload hidden files glob", step("push", up("'.*'")), 1},
		{"upload .git", step("push", up(".git/")), 1},
		{"upload .git config", step("push", up("./.git/config")), 1},
		{"upload .git nested in a glob", step("push", up("'**/.git/**'")), 1},
		{"multi-line paths, one is sensitive", step("push", up("|\n            dist/\n            .git")), 1},
		{"upload a build dir", step("push", up("dist/")), 0},
		{"upload .github dir is not .git", step("push", up(".github/")), 0},
		{"excluded .git", step("push", up("|\n            dist/\n            !.git")), 0},
		{"other action", step("push", checkout("")), 0},
		// artipacked: the checkout leaves the token in .git/config
		{"persisted credentials and broad path", step("push", checkout("")+up(".")), 1},
		{"explicit persisted credentials and .git", step("push", checkout("true")+up(".git")), 1},
		{"credentials not persisted and narrow path", step("push", checkout("false")+up("dist/")), 0},
	})

	// the note about the persisted credentials is what tells the artipacked case apart
	for persist, want := range map[string]bool{"": true, "false": false} {
		errs := lint(t, "dangerous-artefact", step("push", checkout(persist)+up(".")))
		if len(errs) != 1 || strings.Contains(errs[0].Message, "persist-credentials") != want {
			t.Fatalf("persist-credentials=%q: unexpected findings %v", persist, errs)
		}
	}
}

func TestRuleUnsecureCommands(t *testing.T) {
	const env = "ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n"

	runCases(t, "unsecure-commands", []ruleCase{
		{"workflow level", "on: push\nenv:\n  " + env + "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n", 1},
		{"job level", "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      " + env + "    steps:\n      - run: echo\n", 1},
		{"step level", step("push", "      - run: echo\n        env:\n          "+env), 1},
		{"other variable", step("push", "      - run: echo\n        env:\n          FOO: bar\n"), 0},
	})
}

func TestRuleBotCheck(t *testing.T) {
	cond := func(c string) string { return step("pull_request_target", "      - if: "+c+"\n        run: echo\n") }

	runCases(t, "bot-check", []ruleCase{
		{"job if", "on: pull_request_target\njobs:\n  j:\n    if: github.actor == 'dependabot[bot]'\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n", 1},
		{"step if", cond(`github.actor == 'dependabot[bot]'`), 1},
		{"no spaces", cond(`github.actor=='dependabot[bot]'`), 1},
		{"expression syntax", cond(`${{ github.actor == 'dependabot[bot]' }}`), 1},
		{"double quotes", cond(`github.actor == "dependabot[bot]"`), 1},
		{"not equal", cond(`github.actor != 'dependabot[bot]'`), 1},
		{"triggering_actor", cond(`github.triggering_actor == 'renovate[bot]'`), 1},
		{"reversed operands", cond(`${{ 'dependabot[bot]' == github.actor }}`), 1},
		{"sender login", cond(`github.event.sender.login == 'dependabot[bot]'`), 1},
		{"pull request author", cond(`github.event.pull_request.user.login == 'dependabot[bot]'`), 1},
		{"sender type", cond(`github.event.sender.type == 'Bot'`), 1},
		{"contains", cond(`contains(github.actor, '[bot]')`), 1},
		{"endsWith", cond(`endsWith(github.actor, '[bot]')`), 1},
		{"bot first in an or", cond(`github.actor == 'dependabot[bot]' || github.actor == 'octocat'`), 1},
		{"human actor", cond(`github.actor == 'octocat'`), 0},
		{"bot name compared to something else", cond(`github.actor == 'octocat' || github.event.x == 'a[bot]'`), 0},
		{"not the github context", cond(`githubXactor == 'a[bot]'`), 0},
		{"no condition", step("pull_request_target", "      - run: echo\n"), 0},
	})
}

func TestRuleCredentials(t *testing.T) {
	job := func(pw string) string {
		return "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    container:\n      image: foo:1\n      credentials:\n        username: u\n        password: " + pw + "\n    steps:\n      - run: echo\n"
	}

	runCases(t, "credentials", []ruleCase{
		{"hardcoded password", job("hunter2"), 1},
		{"secret", job("${{ secrets.PASSWORD }}"), 0},
	})
}

func TestRuleShellcheck(t *testing.T) {
	path, err := exec.LookPath("shellcheck")
	if err != nil {
		t.Skip("shellcheck is not installed")
	}

	opts := &actionlint.LinterOptions{Shellcheck: path}

	for src, want := range map[string]int{
		step("push", "      - run: echo $FOO\n"):     1, // SC2086
		step("push", "      - run: echo \"$FOO\"\n"): 0,
	} {
		if got := len(lintOpts(t, "shellcheck", src, opts)); got != want {
			t.Fatalf("got %d findings, want %d for:\n%s", got, want, src)
		}
	}
}

func TestRuleDebugExternalTrigger(t *testing.T) {
	FilterTriggers = common.TriggerWithExternalData

	t.Cleanup(func() { FilterTriggers = []string{} })

	runCases(t, "debug-external-trigger", []ruleCase{
		{"external trigger", "name: wf\n" + step("issue_comment", "      - run: echo\n"), 1},
		{"internal trigger", "name: wf\n" + step("push", "      - run: echo\n"), 0},
	})
}

func TestRuleDebugArtefacts(t *testing.T) {
	runCases(t, "debug-artefacts", []ruleCase{
		{"upload", step("push", "      - uses: actions/upload-artifact@v4\n        with:\n          path: out\n"), 1},
		{"download", step("push", "      - uses: actions/download-artifact@v4\n"), 0},
	})
}

func TestRuleDebugJSExec(t *testing.T) {
	gs := func(script string) string {
		return step("push", "      - uses: actions/github-script@v7\n        with:\n          script: |\n            "+script+"\n")
	}

	runCases(t, "debug-js-exec", []ruleCase{
		{"exec.exec", gs("await exec.exec('ls')"), 1},
		{"no exec", gs("console.log(1)"), 0},
	})
}

func TestRuleDebugOIDCAction(t *testing.T) {
	runCases(t, "debug-oidc-action", []ruleCase{
		{"aws", step("push", "      - uses: aws-actions/configure-aws-credentials@v4\n"), 1},
		{"azure", step("push", "      - uses: azure/login@v2\n"), 1},
		{"other", step("push", "      - uses: actions/checkout@v4\n"), 0},
	})
}

// --filter-triggers must silence the rules for the other triggers.
func TestFilterTriggers(t *testing.T) {
	FilterTriggers = []string{"pull_request_target"}

	t.Cleanup(func() { FilterTriggers = []string{} })

	const run = "      - run: echo \"a=$B\" >> \"$GITHUB_OUTPUT\"\n"

	runCases(t, "dangerous-write", []ruleCase{
		{"matching trigger", step("pull_request_target", run), 1},
		{"other trigger", step("push", run), 0},
	})
}

func TestRuleOverprovisionedSecrets(t *testing.T) {
	run := func(script string) string { return step("push", "      - run: "+script+"\n") }

	runCases(t, "overprovisioned-secrets", []ruleCase{
		{"toJSON in run", run(`echo '${{ toJSON(secrets) }}'`), 1},
		{"toJSON case and spaces", run(`echo '${{ tojson( secrets ) }}'`), 1},
		{"toJSON in env", step("push", "      - run: echo\n        env:\n          ALL: ${{ toJSON(secrets) }}\n"), 1},
		{"toJSON in action input", step("push", "      - uses: actions/foo@v1\n        with:\n          x: ${{ toJSON(secrets) }}\n"), 1},
		{"toJSON in workflow env", "on: push\nenv:\n  ALL: ${{ toJSON(secrets) }}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n", 1},
		{"toJSON in reusable workflow input", "on: push\njobs:\n  j:\n    uses: org/repo/.github/workflows/a.yml@v1\n    with:\n      s: ${{ toJSON(secrets) }}\n", 1},
		{"dynamic access with an expression", run(`echo '${{ secrets[format('"'"'KEY_{0}'"'"', matrix.env)] }}'`), 1},
		{"dynamic access with a matrix value", run(`echo '${{ secrets[matrix.name] }}'`), 1},
		{"static access", run(`echo '${{ secrets.TOKEN }}'`), 0},
		{"static indexed access", run(`echo '${{ secrets['"'"'TOKEN'"'"'] }}'`), 0},
		{"toJSON of another context", run(`echo '${{ toJSON(github.event) }}'`), 0},
		{"shell array outside of an expression", run(`echo "${secrets[0]}"`), 0},
	})
}

func TestRuleToctou(t *testing.T) {
	co := func(ref string) string {
		return "      - uses: actions/checkout@v4\n        with:\n          ref: " + ref + "\n"
	}

	runCases(t, "toctou", []ruleCase{
		{"comment and PR number", step("issue_comment", co("refs/pull/${{ github.event.issue.number }}/head")), 1},
		{"comment and merge ref", step("issue_comment", co("refs/pull/${{ github.event.issue.number }}/merge")), 1},
		{"dispatch input", step("workflow_dispatch", co("${{ inputs.ref }}")), 1},
		{"dispatch event input", step("workflow_dispatch", co("${{ github.event.inputs.pr }}")), 1},
		{"branch name after a label", "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + co("${{ github.event.pull_request.head.ref }}"), 1},
		{"gh pr checkout after a comment", step("issue_comment", "      - run: gh pr checkout ${{ github.event.issue.number }}\n"), 1},
		{"fetch of the PR head", step("workflow_dispatch", "      - run: git fetch origin pull/$PR/head\n"), 1},
		{"commit SHA input", step("workflow_dispatch", co("${{ inputs.sha }}")), 0},
		{"head sha", step("issue_comment", co("${{ github.event.pull_request.head.sha }}")), 0},
		{"static ref", step("workflow_dispatch", co("main")), 0},
		{"no ref", step("issue_comment", "      - uses: actions/checkout@v4\n"), 0},
		{"no approval step before the workflow", step("push", co("refs/pull/${{ github.event.number }}/head")), 0},
		{"pull_request_target without label gate", step("pull_request_target", co("${{ github.event.pull_request.head.ref }}")), 0},
		{"other script in a dispatch", step("workflow_dispatch", "      - run: git checkout main\n"), 0},
	})
}

func TestRuleUnsoundCondition(t *testing.T) {
	cond := func(c string) string { return step("push", "      - if: "+c+"\n        run: echo\n") }

	runCases(t, "unsound-condition", []ruleCase{
		// contains
		{"contains with reversed arguments", cond(`contains('refs/heads/main refs/heads/dev', github.ref)`), 1},
		{"contains with reversed arguments in an expression", cond(`${{ contains('main dev', github.ref_name) }}`), 1},
		{"contains with a function name in another case", cond(`CONTAINS('main dev', github.ref_name)`), 1},
		{"contains in the right order", cond(`contains(github.event.pull_request.labels.*.name, 'safe')`), 0},
		{"contains of two literals", cond(`contains('abc', 'b')`), 0},
		// always true
		{"expression followed by text", cond(`${{ github.actor == 'octocat' }} && github.ref == 'refs/heads/main'`), 1},
		{"text before an expression", cond(`always() && ${{ github.actor == 'octocat' }}`), 1},
		{"two expressions", cond(`${{ github.actor == 'a' }} ${{ github.actor == 'b' }}`), 1},
		{"block scalar keeps its trailing newline", step("push", "      - if: |\n          ${{ github.actor == 'octocat' }}\n        run: echo\n"), 1},
		{"folded block scalar keeps its trailing newline", step("push", "      - if: >\n          ${{ github.actor == 'octocat' }}\n        run: echo\n"), 1},
		{"stripped block scalar", step("push", "      - if: |-\n          ${{ github.actor == 'octocat' }}\n        run: echo\n"), 0},
		{"only an expression", cond(`${{ github.actor == 'octocat' }}`), 0},
		{"no braces", cond(`github.actor == 'octocat' && github.ref == 'refs/heads/main'`), 0},
		// ternary
		{"falsy empty string", cond(`${{ github.ref == 'refs/heads/main' && '' || 'other' }}`), 1},
		{"falsy zero", cond(`github.event_name == 'push' && 0 || 1`), 1},
		{"falsy false", cond(`github.event_name == 'push' && false || true`), 1},
		{"falsy null", cond(`github.event_name == 'push' && null || 'x'`), 1},
		{"truthy middle value", cond(`github.event_name == 'push' && 'a' || 'b'`), 0},
		{"and without or", cond(`github.event_name == 'push' && ''`), 0},
		// job level
		{"job level condition", "on: push\njobs:\n  j:\n    if: contains('main dev', github.ref_name)\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n", 1},
		{"no condition", step("push", "      - run: echo\n"), 0},
	})
}
