package core

import (
	"io"
	"testing"

	"github.com/rhysd/actionlint"
	"github.com/synacktiv/octoscan/core/rules"
)

// lint runs the offline octoscan rules on src and returns the findings of the given rule.
func lint(t *testing.T, rule, src string) []*actionlint.Error {
	t.Helper()

	Internetavailable = false // no network in tests

	l, err := actionlint.NewLinter(io.Discard, &actionlint.LinterOptions{OnRulesCreated: OnRulesCreated})
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
			pr + "      - run: git checkout -b \"release-${VERSION}\"\n", "open issue"},
		{"literal write to GITHUB_OUTPUT", "#30", "dangerous-write",
			pr + "      - run: |\n          if git diff --quiet; then\n            echo \"uncommitted_changes=false\" >> \"$GITHUB_OUTPUT\"\n          fi\n", "open issue"},
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

// #41: "$/" refers to the caller repository, it must not be treated as an external owner.
func TestRepoJackingSelfRepository(t *testing.T) {
	src := pr + "      - uses: $/.github/actions/foo\n      - uses: ./local\n"

	w, perr := actionlint.Parse([]byte(src))
	if len(perr) != 0 {
		t.Fatal(perr)
	}

	rule := rules.NewRuleRepoJacking()
	for _, s := range w.Jobs["j"].Steps {
		if err := rule.VisitStep(s); err != nil {
			t.Fatal(err)
		}
	}

	if got := rule.Owners(); len(got) != 0 {
		t.Fatalf("self-repository actions collected as owners: %v", got)
	}
}
