package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/rhysd/actionlint"
	"github.com/synacktiv/octoscan/common"
)

var expectRegexp = regexp.MustCompile(`(?m)^# expect: ([a-z-]+)=(\d+)$`)

// The files of testdata are vulnerable workflows to run octoscan against. They have to keep finding what they say:
// "# expect: <rule>=<number of findings of the rule in the file>".
func TestVulnerableExamples(t *testing.T) {
	const root = "../testdata"

	files, err := filepath.Glob(filepath.Join(root, "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no examples in %s: %v", root, err)
	}

	covered := map[string]bool{}

	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}

		expects := expectRegexp.FindAllStringSubmatch(string(src), -1)
		if len(expects) != 1 {
			t.Errorf("%s needs one \"# expect: <rule>=<n>\" line", file)

			continue
		}

		rule := expects[0][1]
		want, _ := strconv.Atoi(expects[0][2])
		covered[rule] = true

		t.Run(filepath.Base(file), func(t *testing.T) {
			if _, ok := RulesSwitch[rule]; !ok {
				t.Fatalf("%q is not a rule", rule)
			}

			if rule == "repo-jacking" {
				t.Skip("needs Internet: octoscan scan testdata/repo-jacking.yml")
			}

			opts := &actionlint.LinterOptions{}

			if rule == "shellcheck" {
				path, err := exec.LookPath("shellcheck")
				if err != nil {
					t.Skip("shellcheck is not installed")
				}

				opts.Shellcheck = path
			}

			// the rule only looks at these workflows with the filter of "--filter-triggers external"
			if rule == "debug-external-trigger" {
				FilterTriggers = common.TriggerWithExternalData

				t.Cleanup(func() { FilterTriggers = []string{} })
			}

			if got := len(lintOpts(t, rule, string(src), opts)); got != want {
				t.Fatalf("%d findings of %q, the example expects %d: run ./octoscan scan %s", got, rule, want, filepath.Join("testdata", filepath.Base(file)))
			}
		})
	}

	// every rule has its examples
	for rule := range RulesSwitch {
		if !covered[rule] {
			t.Errorf("no example in %s for the rule %q", root, rule)
		}
	}
}
