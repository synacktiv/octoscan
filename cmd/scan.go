package cmd

import (
	"octoscan/common"
	"octoscan/core"
	"os"
	"strings"

	"github.com/docopt/docopt-go"
	"github.com/rhysd/actionlint"
)

var usageScan = `octoscan

Usage:
	octoscan scan [options] <target>
	octoscan scan [options] <target> [--debug-rules --filter-external --filter-run --ignore=<pattern> ((--disable-rules | --enable-rules ) <rules>)]

Options:
	-h, --help
	-v, --version
	-d, --debug
	--verbose
	--json						Json
	--oneline					Use one line per one error. Useful for reading error messages from programs

Args:
	<target>					Target File or directory to scan
	--filter-external				Filter triggers that can have external user input
	--filter-run					Search for expression injection only in run shell scripts.
	--ignore <pattern>				Regular expression matching to error messages you want to ignore.
	--disable-rules <rules>				Disable specific rules. Split on ","
	--enable-rules <rules>				Enable specific rules, this with disable all other rules. Split on ","
	--debug-rules					Enable debug rules.

`

func checkInternet(args docopt.Opts) {
	checkInternet := true

	if args["--enable-rules"] != false && !strings.Contains(args["<rules>"].(string), "repo-jacking") {
		checkInternet = false
	}

	if args["--disable-rules"] != false && strings.Contains(args["<rules>"].(string), "repo-jacking") {
		checkInternet = false
	}

	if checkInternet {
		err := common.IsInternetAvailable()
		if err != nil {
			common.Log.Info("Could not connect to Internet, skipping \"repo-jacking\" rule.")

			core.Internetavailable = false
		}
	}
}

func runScanner(args docopt.Opts, opts *actionlint.LinterOptions) error {
	opts.Shellcheck = "shellcheck"
	// Add default ignore pattern
	// by default actionlint add error when parsing Workflows files
	opts.IgnorePatterns = append(opts.IgnorePatterns, "unexpected key \".+\" for ")

	if args["--ignore"] != nil {
		opts.IgnorePatterns = append(opts.IgnorePatterns, args["--ignore"].(string))
	}

	opts.LogWriter = os.Stderr

	opts.OnRulesCreated = core.OnRulesCreated

	checkInternet(args)

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

func Scan(inputArgs []string) error {
	var opts actionlint.LinterOptions

	parser := &docopt.Parser{}
	args, _ := parser.ParseArgs(usageScan, inputArgs, "")

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

	if v, _ := args.Bool("--filter-external"); v {
		core.FilterExternalTriggers = true
	}

	if v, _ := args.Bool("--disable-rules"); v {
		core.FilterRules(false, strings.Split(args["<rules>"].(string), ","))
	}

	if v, _ := args.Bool("--enable-rules"); v {
		core.FilterRules(true, strings.Split(args["<rules>"].(string), ","))
	}

	if v, _ := args.Bool("--debug-rules"); v {
		core.DebugRules = true
	}

	if v, _ := args.Bool("--filter-run"); v {
		core.FilterRun = true
	}

	return runScanner(args, &opts)
}
