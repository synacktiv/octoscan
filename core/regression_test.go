package core

import (
	"io"
	"testing"

	"github.com/rhysd/actionlint"
)

// lint runs the octoscan rules (offline ones, debug ones included) on src and returns the findings of the given rule.
func lint(t *testing.T, rule, src string) []*actionlint.Error {
	t.Helper()

	return lintOpts(t, rule, src, &actionlint.LinterOptions{})
}

func lintOpts(t *testing.T, rule, src string, opts *actionlint.LinterOptions) []*actionlint.Error {
	t.Helper()

	Internetavailable = false // no network in tests
	DebugRules = true

	t.Cleanup(func() { DebugRules = false })

	opts.OnRulesCreated = OnRulesCreated

	l, err := actionlint.NewLinter(io.Discard, opts)
	if err != nil {
		t.Fatal(err)
	}

	errs, err := l.Lint("test.yml", []byte(src), nil)
	if err != nil {
		t.Fatal(err)
	}

	var res []*actionlint.Error

	for _, e := range errs {
		if e.Kind == rule {
			res = append(res, e)
		}
	}

	return res
}

const pr = "on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"

func TestFalsePositives(t *testing.T) {
	tests := []struct {
		name  string
		issue string
		rule  string
		src   string
		skip  string // set while the issue is still open
	}{
		{"branch creation is not a checkout", "#20", "dangerous-checkout",
			pr + "      - run: git checkout -b \"release-${VERSION}\"\n", ""},
		{"literal write to GITHUB_OUTPUT", "#30", "dangerous-write",
			pr + "      - run: |\n          if git diff --quiet; then\n            echo \"uncommitted_changes=false\" >> \"$GITHUB_OUTPUT\"\n          fi\n", ""},
		{"ubuntu-24.04-arm runner", "#28", "runner-label",
			pr + "      - run: echo\n", ""},
		{"windows-11-arm runner", "#39", "runner-label",
			"on: push\njobs:\n  j:\n    runs-on: windows-11-arm\n    steps:\n      - run: echo\n", ""},
		{"expression as action input", "#36", "expression-injection",
			pr + "      - uses: actions/github-script@v7\n        with:\n          title: ${{ github.event.pull_request.title }}\n", ""},
	}

	// #28 needs the arm label itself
	tests[2].src = "on: push\njobs:\n  j:\n    runs-on: ubuntu-24.04-arm\n    steps:\n      - run: echo\n"

	for _, tt := range tests {
		t.Run(tt.issue+" "+tt.name, func(t *testing.T) {
			if tt.skip != "" {
				t.Skip(tt.skip)
			}

			if tt.issue == "#36" { // closed by --filter-run
				FilterRun = true
				defer func() { FilterRun = false }()
			}

			if errs := lint(t, tt.rule, tt.src); len(errs) != 0 {
				t.Fatalf("unexpected findings: %v", errs)
			}
		})
	}
}

func TestKnownVulnerability(t *testing.T) {
	tests := []struct {
		uses string
		want int
	}{
		{"OZI-Project/publish@v1.13.3", 1},
		{"ozi-project/publish@v1.13.3", 1}, // case-insensitive
		{"OZI-Project/publish/sub/dir@v1.13.3", 1},
		{"OZI-Project/publish@v1.13.6", 0}, // fixed
		{"OZI-Project/publish@v1", 0},      // moving tag, assumed patched
		{"OZI-Project/publish@vnext", 0},   // unparsable ref must not panic
		{"OZI-Project/publish-other@v1.13.3", 0},
		{"actions/checkout@v4", 0},
	}

	for _, tt := range tests {
		t.Run(tt.uses, func(t *testing.T) {
			src := pr + "      - uses: " + tt.uses + "\n"
			if got := len(lint(t, "known-vulnerability", src)); got != tt.want {
				t.Fatalf("got %d findings, want %d", got, tt.want)
			}
		})
	}
}

// The false positive fixes must not hide real findings.
func TestStillDetected(t *testing.T) {
	tests := []struct{ rule, run string }{
		{"dangerous-checkout", `git checkout "$REF"`},
		{"dangerous-checkout", `git checkout -b new "$REF"`},
		{"dangerous-write", `echo "x=$FOO" >> "$GITHUB_OUTPUT"`},
		{"dangerous-write", `echo "x=${{ github.event.issue.title }}" >> "$GITHUB_OUTPUT"`},
		{"dangerous-write", `cat file >> "$GITHUB_ENV"`},
	}

	for _, tt := range tests {
		t.Run(tt.run, func(t *testing.T) {
			if len(lint(t, tt.rule, pr+"      - run: |\n          "+tt.run+"\n")) == 0 {
				t.Fatal("expected a finding")
			}
		})
	}
}

func TestLocalActionSelfRepository(t *testing.T) {
	if len(lint(t, "local-action", pr+"      - uses: $/.github/actions/foo\n")) != 1 {
		t.Fatal("expected one finding")
	}
}

func TestRunnerLabels(t *testing.T) {
	tests := []struct {
		runsOn string
		want   int
	}{
		{"ubuntu-26.04", 0},
		{"ubuntu-26.04-arm", 0},
		{"windows-11-vs2026-arm", 0},
		{"macos-latest", 0},
		{"[windows-latest, windows-2025]", 0}, // same image
		{"[macos-latest, macos-26]", 0},       // same image
		{"[ubuntu-latest, ubuntu-24.04]", 0},  // same image
		{"[ubuntu-26.04, ubuntu-24.04]", 1},   // conflict
		{"[macos-latest, macos-15]", 1},       // macos-latest is macOS 26 now
		{"ubuntu-20.04", 0},                   // retired GitHub-hosted label
		{"my-self-hosted-runner", 1},
		{"[self-hosted, linux]", 1}, // self-hosted is not a default label
	}

	for _, tt := range tests {
		t.Run(tt.runsOn, func(t *testing.T) {
			src := "on: push\njobs:\n  j:\n    runs-on: " + tt.runsOn + "\n    steps:\n      - run: echo\n"
			if got := len(lint(t, "runner-label", src)); got != tt.want {
				t.Fatalf("got %d findings, want %d", got, tt.want)
			}
		})
	}
}
