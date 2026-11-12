package core

import (
	"os/exec"
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
	const up = "      - uses: actions/upload-artifact@v4\n        with:\n          name: a\n          path: "

	runCases(t, "dangerous-artefact", []ruleCase{
		{"upload the whole workspace", step("push", up+".\n"), 1},
		{"upload ./", step("push", up+"./\n"), 1},
		{"upload a build dir", step("push", up+"dist/\n"), 0},
		{"other action", step("push", "      - uses: actions/checkout@v4\n"), 0},
	})
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
