package main

import (
	"fmt"
	"os"

	"octoscan/common"
	"octoscan/core"

	"github.com/docopt/docopt-go"
	"github.com/rhysd/actionlint"
)

var usage = `octoscan

Usage:
	octoscan scan [options] <target>
	octoscan scan [options] <target> [--json --oneline -i <pattern>...]

Options:
	-h, --help
	-v, --version
	-d, --debug
	--verbose

Args:
	<target>					Target File or directory to scan
	--json						Json output
	--oneline					Use one line per one error. Useful for reading error messages from programs
	-i, --ignore <pattern>		Regular expression matching to error messages you want to ignore. The pattern value is repeatable

`

func runScanner(args docopt.Opts, opts *actionlint.LinterOptions) error {
	opts.OnRulesCreated = core.OnRulesCreated
	opts.Shellcheck = "shellcheck"

	// Add default ignore pattern
	// by default actionlint add error when parsing Workflows files
	opts.IgnorePatterns = append(opts.IgnorePatterns, "unexpected key \".+\" for ")
	opts.IgnorePatterns = append(opts.IgnorePatterns, args["<pattern>"].([]string)...)

	opts.LogWriter = os.Stderr

	l, err := actionlint.NewLinter(os.Stdout, opts)
	if err != nil {
		return err
	}

	file, _ := args.String("<target>")

	if common.IsDirectory(file) {
		octoLinter := &core.OctoLinter{Linter: *l}
		octoLinter.LintRepositoryRecurse(file)
	} else {
		l.LintFile(file, nil)
	}

	return nil
}

func main() {
	var opts actionlint.LinterOptions

	parser := &docopt.Parser{}
	args, _ := parser.ParseArgs(usage, nil, "octoscan version 0.1")

	if d, _ := args.Bool("--debug"); d {
		opts.Debug = true
	}

	if v, _ := args.Bool("--verbose"); v {
		opts.Verbose = true
	}

	if v, _ := args.Bool("--oneline"); v {
		opts.Oneline = true
	}

	if v, _ := args.Bool("--json"); v {
		opts.Format = "{{json .}}"
	}

	err := runScanner(args, &opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
}
