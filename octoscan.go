package main

import (
	"octoscan/common"
	"octoscan/core"
	"os"

	"github.com/docopt/docopt-go"
	"github.com/rhysd/actionlint"
)

var usage = `octoscan

Usage:
	octoscan [options] --file <file>

Options:
	-h, --help
	-v, --version
	-d, --debug
	--verbose

Args:
	-f, --file <file>

`

func runScanner(args *docopt.Opts, opts *actionlint.LinterOptions) ([]*actionlint.Error, error) {

	opts.OnRulesCreated = core.OnRulesCreated
	opts.Shellcheck = "shellcheck"

	// Add default ignore pattern
	// by default actionlint add error when parsing Workflows files
	opts.IgnorePatterns = append(opts.IgnorePatterns, "unexpected key \".+\" for ")
	opts.LogWriter = os.Stderr

	l, err := actionlint.NewLinter(os.Stdout, opts)
	if err != nil {
		return nil, err
	}

	file, _ := args.String("<file>")

	return l.LintFile(file, nil)
}

func main() {

	var opts actionlint.LinterOptions

	parser := &docopt.Parser{}
	args, _ := parser.ParseArgs(usage, nil, "octoscan version 0.1")

	if d, _ := args.Bool("--debug"); d {
		opts.Debug = true
	}

	common.Log.Debug(args)

	if v, _ := args.Bool("--verbose"); v {
		opts.Verbose = true
	}

	runScanner(&args, &opts)

}
