package core

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/rhysd/actionlint"
)

// where returns the 1-based line and column of the nth (0-based) occurrence of needle in src.
func where(t *testing.T, src, needle string, n int) (int, int) {
	t.Helper()

	idx := -1
	for i := 0; i <= n; i++ {
		next := strings.Index(src[idx+1:], needle)
		if next < 0 {
			t.Fatalf("%q occurs less than %d times", needle, n+1)
		}

		idx += 1 + next
	}

	before := src[:idx]

	return strings.Count(before, "\n") + 1, idx - (strings.LastIndex(before, "\n") + 1) + 1
}

func fixed(t *testing.T, rule, src string) []*actionlint.Error {
	t.Helper()

	errs := lint(t, rule, src)
	FixPositionsWith(errs, func(string) ([]byte, error) { return []byte(src), nil })

	return errs
}

// The findings in a block scalar are on the line of the expression, under the expression, with a snippet.
func TestPositionsInBlockScalars(t *testing.T) {
	const src = `on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          prompt: |
            Issue number: ${{ github.event.issue.number }}

            Issue title:
            ${{ github.event.issue.title }}

            Issue body:
            ${{ github.event.issue.body }}
      - run: |
          echo "title is ${{ github.event.issue.title }}"
          echo
          echo "body is ${{ github.event.issue.body }}"
`

	for _, rule := range []string{"expression-injection", "prompt-injection"} {
		t.Run(rule, func(t *testing.T) {
			errs := fixed(t, rule, src)

			// the prompt and the script, a finding by untrusted input
			var want [][2]int

			for _, c := range []struct {
				path string
				n    int
			}{{"github.event.issue.title", 0}, {"github.event.issue.body", 0}, {"github.event.issue.title", 1}, {"github.event.issue.body", 1}} {
				if rule == "prompt-injection" && c.n == 1 {
					continue // the agent is not the script
				}

				l, col := where(t, src, c.path, c.n)
				want = append(want, [2]int{l, col})
			}

			if len(errs) != len(want) {
				t.Fatalf("got %d findings, want %d: %v", len(errs), len(want), errs)
			}

			for i, e := range errs {
				if e.Line != want[i][0] || e.Column != want[i][1] {
					t.Errorf("finding %d is at %d:%d, want %d:%d (%s)", i, e.Line, e.Column, want[i][0], want[i][1], e.Message)
				}
			}
		})
	}
}

// Before the source is read the line is already right: only the column of the block scalars is relative.
func TestLineOfFindingsInBlockScalars(t *testing.T) {
	src := step("issues", "      - run: |\n          echo one\n          echo two\n          echo \"${{ github.event.issue.title }}\"\n")

	errs := lint(t, "expression-injection", src)
	if len(errs) != 1 {
		t.Fatalf("got %d findings", len(errs))
	}

	if want, _ := where(t, src, "github.event.issue.title", 0); errs[0].Line != want {
		t.Fatalf("line %d, want %d", errs[0].Line, want)
	}

	// the indentation of the block is not in the AST: the column is negative, counted from the first character of the line
	if want := -(strings.Index(`echo "${{ github.event.issue.title }}"`, "github") + 1); errs[0].Column != want {
		t.Fatalf("column %d, want %d (relative to the content)", errs[0].Column, want)
	}
}

// Single-line values are right without the source, quoted or not.
func TestColumnOfFindingsInSingleLines(t *testing.T) {
	for _, run := range []string{
		`echo "${{ github.event.issue.title }}"`,
		`'echo "${{ github.event.issue.title }}"'`,
		`"echo ${{ github.event.issue.title }}"`,
	} {
		src := step("issues", "      - run: "+run+"\n")

		errs := lint(t, "expression-injection", src)
		if len(errs) != 1 {
			t.Fatalf("%s: got %d findings", run, len(errs))
		}

		line, col := where(t, src, "github.event.issue.title", 0)
		if errs[0].Line != line || errs[0].Column != col {
			t.Errorf("%s: at %d:%d, want %d:%d", run, errs[0].Line, errs[0].Column, line, col)
		}
	}
}

func TestSnippetIsDisplayed(t *testing.T) {
	src := step("issues", "      - run: |\n          echo one\n          echo \"${{ github.event.issue.title }}\"\n          echo \"${{ github.event.issue.body }}\"\n")

	errs := fixed(t, "expression-injection", src)
	if len(errs) != 2 {
		t.Fatalf("got %d findings", len(errs))
	}

	for _, e := range errs {
		var out bytes.Buffer

		e.PrettyPrint(&out, []byte(src))

		lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
		if len(lines) != 4 {
			t.Fatalf("no snippet for %q:\n%s", e.Message, out.String())
		}

		// the caret is under the expression
		path := strings.Split(e.Message, `"`)[1]
		if strings.Index(lines[2], path) != strings.Index(lines[3], "^") {
			t.Errorf("the caret is not under %q:\n%s", path, out.String())
		}
	}
}

func TestFixPositions(t *testing.T) {
	src := "first\n      second line\n      - run: |-\n          echo \"a=$B\" >> \"$GITHUB_OUTPUT\"\n      - run: |\n          echo one\n            echo nested\n"
	read := func(string) ([]byte, error) { return []byte(src), nil }

	tests := []struct {
		name         string
		err          actionlint.Error
		wantL, wantC int
	}{
		{"relative column is added to the indentation", actionlint.Error{Filepath: "f", Line: 6, Column: -6, Kind: "k"}, 6, 16},
		{"relative column of a nested line", actionlint.Error{Filepath: "f", Line: 7, Column: -6, Kind: "k"}, 7, 18},
		{"relative column of the first character", actionlint.Error{Filepath: "f", Line: 2, Column: -1, Kind: "k"}, 2, 7},
		{"column after the end of the line is moved to the text", actionlint.Error{Filepath: "f", Line: 2, Column: 5760, Kind: "k"}, 2, 7},
		{"valid column is kept", actionlint.Error{Filepath: "f", Line: 2, Column: 9, Kind: "k"}, 2, 9},
		// "- run: |-" at the column 14 of the line 3: the value is the line 4 and starts at the column 11
		{"single-line block: the line after the key", actionlint.Error{Filepath: "f", Line: 3, Column: 14 + 5, Kind: "k"}, 4, 16},
		{"single-line block: the first character of the value", actionlint.Error{Filepath: "f", Line: 3, Column: 14, Kind: "k"}, 4, 11},
		{"single-line block: before the indicator is kept", actionlint.Error{Filepath: "f", Line: 3, Column: 9, Kind: "k"}, 3, 9},
		{"line out of the file is kept", actionlint.Error{Filepath: "f", Line: 99, Column: 5, Kind: "k"}, 99, 5},
		{"error without a line is kept", actionlint.Error{Filepath: "f", Line: 0, Column: 5, Kind: "k"}, 0, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := tt.err
			FixPositionsWith([]*actionlint.Error{&e}, read)

			if e.Line != tt.wantL || e.Column != tt.wantC {
				t.Fatalf("at %d:%d, want %d:%d", e.Line, e.Column, tt.wantL, tt.wantC)
			}
		})
	}

	t.Run("unreadable file is kept", func(t *testing.T) {
		e := actionlint.Error{Filepath: "f", Line: 2, Column: 5760, Kind: "k"}
		FixPositionsWith([]*actionlint.Error{&e}, func(string) ([]byte, error) { return nil, errors.New("no") })

		if e.Column != 5760 {
			t.Fatalf("column %d", e.Column)
		}
	})
}

func TestShellcheckPositions(t *testing.T) {
	path, err := exec.LookPath("shellcheck")
	if err != nil {
		t.Skip("shellcheck is not installed")
	}

	opts := &actionlint.LinterOptions{Shellcheck: path}

	for _, c := range []struct{ name, step, needle string }{
		{"block", "      - run: |\n          echo ok\n          read line\n", "read line"},
		{"block with a dedent of 4", "      - run: |\n            echo ok\n            for f in `ls`; do echo \"$f\"; done\n", "`ls`"},
		{"one line", "      - run: echo $FOO\n", "$FOO"},
		{"one line, quoted", "      - run: 'echo $FOO'\n", "$FOO"},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := step("push", c.step)

			errs := lintOpts(t, "shellcheck", src, opts)
			if len(errs) == 0 {
				t.Fatal("no finding")
			}

			FixPositionsWith(errs, func(string) ([]byte, error) { return []byte(src), nil })

			wantLine, wantCol := where(t, src, c.needle, 0)
			for _, e := range errs {
				if e.Line != wantLine || e.Column < wantCol-1 || e.Column > wantCol+len(c.needle) {
					t.Errorf("at %d:%d, want %d:%d (%s)", e.Line, e.Column, wantLine, wantCol, e.Message)
				}
			}
		})
	}
}
