package core

import (
	"fmt"
	"strings"
	"testing"
)

// The position of a finding must be the start of the offending construct, whatever the way the value is written in
// the YAML: "key: value", quoted, "|", "|-", ">", offending line first or nested in the script.

type posForm struct {
	name string
	// value is what follows "key:" for the lines of the script
	value func(keyIndent int, lines []string) string
}

func block(indicator string, indent func(i int) int) func(int, []string) string {
	return func(k int, lines []string) string {
		var b strings.Builder

		b.WriteString(" " + indicator + "\n")

		for i, l := range lines {
			b.WriteString(strings.Repeat(" ", k+indent(i)) + l + "\n")
		}

		return strings.TrimRight(b.String(), "\n")
	}
}

var multiLineForms = []posForm{
	{"block |", block("|", func(int) int { return 2 })},
	{"block |-", block("|-", func(int) int { return 2 })},
	{"block with a deeper indentation", block("|", func(int) int { return 4 })},
	{"folded >", block(">", func(int) int { return 2 })},
}

// posCase is a rule, a context for a value and the construct that must be pointed at.
type posCase struct {
	rule string
	// build returns the workflow, kv is "key:" followed by the value
	build func(kv string) string
	key   string
	// keyIndent is the column (0-based) of the key
	keyIndent int
	// lines of the value, the offending one is lines[at]
	lines  []string
	at     int
	needle string // the construct, unique in the workflow
	// singleLine: the value can be written as "key: value" (the lines are joined)
	singleLine bool
	// noFold: the lines are not joined by the rule (a list of paths)
	noFold bool
}

func runStep(rule, offending, needle string) posCase {
	return posCase{
		rule: rule,
		build: func(kv string) string {
			return step("pull_request_target", "      - "+kv+"\n")
		},
		key: "run:", keyIndent: 8, lines: []string{"echo one", offending, "echo two"}, at: 1,
		needle: needle, singleLine: true,
	}
}

func TestPositionsOfAllRules(t *testing.T) {
	scriptRun := func(rule, on, offending, needle string) posCase {
		c := runStep(rule, offending, needle)
		c.build = func(kv string) string { return step(on, "      - "+kv+"\n") }

		return c
	}

	cases := []posCase{
		scriptRun("dangerous-write", "push", `echo "a=$B" >> "$GITHUB_OUTPUT"`, `>> "$GITHUB_OUTPUT"`),
		scriptRun("dangerous-write", "push", `echo "a=$B" >> "$GITHUB_ENV"`, `>> "$GITHUB_ENV"`),
		{
			rule:  "dangerous-write",
			build: func(kv string) string { return step("push", "      - shell: pwsh\n        "+kv+"\n") },
			key:   "run:", keyIndent: 8, lines: []string{"echo one", `echo "a=$env:B" >> $env:GITHUB_OUTPUT`}, at: 1,
			needle: "env:GITHUB_OUTPUT", singleLine: true,
		},
		scriptRun("dangerous-checkout", "pull_request_target", `git checkout $REF`, `git checkout $REF`),
		scriptRun("dangerous-checkout", "pull_request_target", `gh pr checkout $PR`, `gh pr checkout $PR`),
		scriptRun("dangerous-action", "pull_request_target", `gh run download 1234`, `gh run download 1234`),
		scriptRun("toctou", "issue_comment", `gh pr checkout 1234`, `gh pr checkout 1234`),
		scriptRun("overprovisioned-secrets", "push", `echo '${{ toJSON(secrets) }}'`, `toJSON(secrets)`),
		scriptRun("expression-injection", "issues", `echo "${{ github.event.issue.title }}"`, `github.event.issue.title`),
		{
			rule: "dangerous-action",
			build: func(kv string) string {
				return step("pull_request_target", "      - uses: actions/github-script@v7\n        with:\n          "+kv+"\n")
			},
			key: "script:", keyIndent: 10, lines: []string{"const a = 1", "await github.rest.actions.downloadArtifact({})", "const b = 2"}, at: 1,
			needle: "downloadArtifact",
		},
		{
			rule: "debug-js-exec",
			build: func(kv string) string {
				return step("pull_request_target", "      - uses: actions/github-script@v7\n        with:\n          "+kv+"\n")
			},
			key: "script:", keyIndent: 10, lines: []string{"const a = 1", "await exec.exec('ls')", "const b = 2"}, at: 1,
			needle: "exec.exec(",
		},
		{
			rule: "prompt-injection",
			build: func(kv string) string {
				return step("issues", "      - uses: anthropics/claude-code-action@v1\n        with:\n          "+kv+"\n")
			},
			key: "prompt:", keyIndent: 10, lines: []string{"Review this", "Title: ${{ github.event.issue.title }}", "Thanks"}, at: 1,
			needle: "github.event.issue.title", singleLine: true,
		},
		{
			rule: "prompt-injection",
			build: func(kv string) string {
				return step("issues", "      - uses: anthropics/claude-code-action@v1\n        with:\n          "+kv+"\n")
			},
			key: "claude_args:", keyIndent: 10, lines: []string{"--model opus", `--allowedTools "Bash,Read"`, "--max-turns 5"}, at: 1,
			needle: "Bash,Read", singleLine: true,
		},
		{
			rule: "prompt-injection",
			build: func(kv string) string {
				return step("issues", "      - uses: anthropics/claude-code-action@v1\n        with:\n          "+kv+"\n")
			},
			key: "claude_args:", keyIndent: 10, lines: []string{"--model opus", "--dangerously-skip-permissions", "--max-turns 5"}, at: 1,
			needle: "--dangerously-skip-permissions", singleLine: true,
		},
		{
			rule: "prompt-injection",
			build: func(kv string) string {
				return step("issues", "      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          "+kv+"\n")
			},
			key: "settings:", keyIndent: 10, lines: []string{"{", `"coreTools": ["run_shell_command(echo)"]`, "}"}, at: 1,
			needle: "run_shell_command",
		},
		{
			rule: "debug-artefacts",
			build: func(kv string) string {
				return step("push", "      - uses: actions/upload-artifact@v4\n        with:\n          name: a\n          "+kv+"\n")
			},
			key: "path:", keyIndent: 10, lines: []string{"dist/", "out/", "logs/"}, at: 0,
			needle: "dist/", noFold: true, // one finding for the whole input
		},
		{
			rule: "dangerous-artefact",
			build: func(kv string) string {
				return step("push", "      - uses: actions/upload-artifact@v4\n        with:\n          name: a\n          "+kv+"\n")
			},
			key: "path:", keyIndent: 10, lines: []string{"dist/", ".git/config", "out/"}, at: 1,
			needle: ".git/config", noFold: true,
		},
		{
			rule:  "bot-check",
			build: func(kv string) string { return step("pull_request_target", "      - "+kv+"\\n        run: echo\n") },
			key:   "if:", keyIndent: 8, lines: []string{"github.actor == 'dependabot[bot]'"}, at: 0,
			needle: "github.actor", singleLine: true,
		},
		{
			rule:  "unsound-condition",
			build: func(kv string) string { return step("push", "      - "+kv+"\\n        run: echo\n") },
			key:   "if:", keyIndent: 8, lines: []string{"contains('main dev', github.ref)"}, at: 0,
			needle: "contains(", singleLine: true,
		},
		{
			rule:  "unsound-condition",
			build: func(kv string) string { return step("push", "      - "+kv+"\\n        run: echo\n") },
			key:   "if:", keyIndent: 8, lines: []string{"github.event_name == 'push' && contains('main dev', github.ref)"}, at: 0,
			needle: "contains(", singleLine: true,
		},
		{
			rule:  "unsound-condition",
			build: func(kv string) string { return step("push", "      - "+kv+"\\n        run: echo\n") },
			key:   "if:", keyIndent: 8, lines: []string{"always() && (github.event_name == 'push' && '' || 'x')"}, at: 0,
			needle: "github.event_name", singleLine: true,
		},
		{
			rule:  "unsound-condition",
			build: func(kv string) string { return step("push", "      - "+kv+"\\n        run: echo\n") },
			key:   "if:", keyIndent: 8, lines: []string{"github.event_name == 'push' && '' || 'x'"}, at: 0,
			needle: "github.event_name", singleLine: true,
		},
	}

	for _, c := range cases {
		forms := multiLineForms
		if c.singleLine {
			forms = append([]posForm{
				{"key: value", func(_ int, l []string) string { return " " + l[0] }},
				{"key: 'value'", func(_ int, l []string) string { return " '" + l[0] + "'" }},
				{"block |- with a single line", func(k int, l []string) string {
					return block("|-", func(int) int { return 2 })(k, []string{l[c.at]})
				}},
				// the offending line first, then the others
				{"block, offending line first", func(k int, l []string) string {
					return block("|", func(int) int { return 2 })(k, append([]string{l[c.at]}, l[:c.at]...))
				}},
			}, forms...)
		}

		for _, f := range forms {
			// not valid YAML: a plain value can't have ": " and a quoted value can't have a quote
			offending := c.lines[c.at]
			if f.name == "folded >" && c.noFold {
				continue
			}

			if (f.name == "key: value" && strings.Contains(offending, ": ")) || (f.name == "key: 'value'" && strings.Contains(offending, "'")) {
				continue
			}

			lines := c.lines
			if f.name == "key: value" || f.name == "key: 'value'" {
				lines = []string{c.lines[c.at]}
			}

			kv := c.key + f.value(c.keyIndent, lines)
			src := strings.ReplaceAll(c.build(kv), `\n`, "\n")

			// "if:" is a mapping key in a list item: the key is indented like the others
			name := fmt.Sprintf("%s/%s/%s", c.rule, strings.Fields(c.needle)[0], f.name)
			t.Run(name, func(t *testing.T) {
				errs := fixed(t, c.rule, src)
				if len(errs) == 0 {
					t.Fatalf("no finding in:\n%s", src)
				}

				wantLine, wantCol := where(t, src, c.needle, 0)
				for _, e := range errs {
					ok := e.Line == wantLine && (wantCol < 0 || e.Column == wantCol)
					if !ok {
						t.Errorf("at %d:%d, want %d:%d\n%s", e.Line, e.Column, wantLine, wantCol, src)
					}
				}
			})
		}
	}
}
