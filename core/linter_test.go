package core

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rhysd/actionlint"
)

const (
	// flagged by unsecure-commands only
	workflowUnsecure = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n    steps:\n      - run: echo\n"
	// flagged by expression-injection only
	workflowInjection = "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n"
)

func write(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func scanDir(t *testing.T, dir string) map[string]int {
	t.Helper()

	Internetavailable = false

	l, err := actionlint.NewLinter(io.Discard, &actionlint.LinterOptions{OnRulesCreated: OnRulesCreated})
	if err != nil {
		t.Fatal(err)
	}

	errs, err := (&OctoLinter{Linter: *l}).LintRepositoryRecurse(dir)
	if err != nil {
		t.Fatal(err)
	}

	kinds := map[string]int{}
	for _, e := range errs {
		kinds[e.Kind]++
	}

	return kinds
}

// A folder of workflows must be scanned for what it contains: not as the repository that contains the folder (examples
// of a project, folders of the "dl" command) and not skipped when there is no repository.
func TestScanFolders(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, ".git", "HEAD"), "ref: refs/heads/main\n")
	write(t, filepath.Join(root, ".github", "workflows", "root.yml"), workflowUnsecure)
	write(t, filepath.Join(root, "examples", "a", ".github", "workflows", "nested.yml"), workflowInjection)

	t.Run("the root of a repository", func(t *testing.T) {
		if got := scanDir(t, root); got["unsecure-commands"] != 1 {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("a folder inside a repository", func(t *testing.T) {
		got := scanDir(t, filepath.Join(root, "examples", "a"))
		if got["expression-injection"] != 1 || got["unsecure-commands"] != 0 {
			t.Fatalf("scanned the workflows of the repository instead of the folder: %v", got)
		}
	})

	t.Run("a folder with the folders of the workflows to scan", func(t *testing.T) {
		got := scanDir(t, filepath.Join(root, "examples"))
		if got["expression-injection"] != 1 {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("a folder of workflow files", func(t *testing.T) {
		flat := t.TempDir()
		write(t, filepath.Join(flat, "a.yml"), workflowInjection)
		write(t, filepath.Join(flat, "b.yaml"), workflowUnsecure)
		write(t, filepath.Join(flat, "readme.md"), "not a workflow")

		got := scanDir(t, flat)
		if got["expression-injection"] != 1 || got["unsecure-commands"] != 1 {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("the yaml files of a repository are not workflows", func(t *testing.T) {
		repo := t.TempDir()
		write(t, filepath.Join(repo, ".git", "HEAD"), "ref: refs/heads/main\n")
		write(t, filepath.Join(repo, ".github", "workflows", "ci.yml"), workflowUnsecure)
		write(t, filepath.Join(repo, "docker-compose.yml"), workflowInjection)

		if got := scanDir(t, repo); got["expression-injection"] != 0 || got["unsecure-commands"] != 1 {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("a folder with no repository", func(t *testing.T) {
		bare := t.TempDir()
		write(t, filepath.Join(bare, ".github", "workflows", "a.yml"), workflowInjection)
		write(t, filepath.Join(bare, ".github", "workflows", "b.yaml"), workflowInjection)

		if got := scanDir(t, bare); got["expression-injection"] != 2 {
			t.Fatalf("got %v", got)
		}
	})
}
