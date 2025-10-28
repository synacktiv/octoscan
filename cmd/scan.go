package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/synacktiv/octoscan/common"
	"github.com/synacktiv/octoscan/core"

	"github.com/docopt/docopt-go"
	"github.com/fatih/color"
	"github.com/rhysd/actionlint"
)

var usageScan = `octoscan

Usage:
	octoscan scan [options] --list-rules
	octoscan scan [options] <target>
	octoscan scan [options] <target> [--debug-rules --filter-triggers=<triggers> --filter-run --ignore=<pattern> ((--disable-rules | --enable-rules ) <rules>) --config-file <config>]

Options:
	-h, --help
	-v, --version
	-d, --debug
	--verbose
	--format <format>  				Output format, json, sarif or custom template to format error messages in Go template syntax. See https://github.com/rhysd/actionlint/tree/main/docs/usage.md#format
	--oneline  					Use one line per one error. Useful for reading error messages from programs

Args:
	<target>					Target File or directory to scan
	--filter-triggers <triggers>			Scan workflows with specific triggers (comma separated list: "push,pull_request_target" or pre-configured: external/allnopr)
	--filter-run					Search for expression injection only in run shell scripts.
	--ignore <pattern>				Regular expression matching to error messages you want to ignore.
	--disable-rules <rules>				Disable specific rules. Split on ","
	--enable-rules <rules>				Enable specific rules, this will disable all other rules. Split on ","
	--debug-rules					Enable debug rules.
	--config-file <config>				Config file.

Examples:
	$ octoscan scan ci.yml --disable-rules shellcheck,local-action --filter-triggers external
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

func runScanner(args docopt.Opts) int {
	var errs []*actionlint.Error
	opts := setScannerArgs(args)

	checkInternet(args)

	l, err := actionlint.NewLinter(os.Stdout, &opts)
	if err != nil {
		return common.ExitStatusFailure
	}

	file, _ := args.String("<target>")

	if common.IsDirectory(file) {
		octoLinter := &core.OctoLinter{Linter: *l}
		errs, err = octoLinter.LintRepositoryRecurse(file)
	} else {
		errs, err = l.LintFile(file, nil)
	}

	if err != nil {
		common.Log.Error(err)

		return common.ExitStatusFailure
	}

	if args["--format"] != nil {
		switch format := args["--format"].(string); format {
		case "json":
			opts.Format = "{{json .}}"
		case "sarif":
			opts.Format = string(common.SarifTemplate)
		default:
			opts.Format = format
		}
		// Now we can use our own formatter on all the errors.
		err = core.DisplayErrors(os.Stdout, opts.Format, errs)
	}

	if err != nil {
		common.Log.Error(err)

		return common.ExitStatusFailure
	}

	if len(errs) > 0 {
		return common.ExitStatusSuccessProblemFound // Linter found some issues, yay!
	}

	return common.ExitStatusSuccessNoProblem
}

func listRules() int {
	yellow := color.New(color.FgYellow)
	core.DebugRules = true
	rules := &[]actionlint.Rule{}

	common.Log.Info("Available rules")

	availableRules := core.OnRulesCreated(*rules)
	for _, rule := range availableRules {
		//nolint
		fmt.Printf("- %v\n", yellow.Sprintf(rule.Name()))
		//nolint
		fmt.Printf("\t%v\n", rule.Description())
	}

	return common.ExitStatusSuccessNoProblem
}

func setCoreParameter(args docopt.Opts) {
	if args["--filter-triggers"] != nil {
		if args["--filter-triggers"].(string) == "external" {
			core.FilterTriggers = common.TriggerWithExternalData
		} else if args["--filter-triggers"].(string) == "allnopr" {
			core.FilterTriggers = common.AllTriggers
		} else {
			core.FilterTriggers = strings.Split(args["--filter-triggers"].(string), ",")
		}
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
}

func setScannerArgs(args docopt.Opts) actionlint.LinterOptions {
	var opts actionlint.LinterOptions

	if d, _ := args.Bool("--debug"); d {
		opts.Debug = true
	}

	if v, _ := args.Bool("--verbose"); v {
		opts.Verbose = true
	}

	if v, _ := args.Bool("--oneline"); v {
		opts.Oneline = true
	}

	/*
		This is a hacky trick to disable the formatter of actionlint otherwise it will use
		a new formatter for each repo and this not what we want. We want to use the same
		formatter for all the repo. It's far from being perfect but I don't know how to do it.
	*/
	if args["--format"] != nil {
		opts.Format = "{{\"\"}}"
	}

	setCoreParameter(args)

	opts.Shellcheck = "shellcheck"
	// Add default ignore pattern
	// by default actionlint add error when parsing Workflows files
	opts.IgnorePatterns = append(opts.IgnorePatterns, common.SyntaxCheckErrors...)

	if args["--ignore"] != nil {
		opts.IgnorePatterns = append(opts.IgnorePatterns, args["--ignore"].(string))
	}

	opts.LogWriter = os.Stderr
	opts.OnRulesCreated = core.OnRulesCreated

	if args["--config-file"] != false {
		opts.ConfigFile = args["<config>"].(string)
	}

	return opts
}

func Scan(inputArgs []string) int {
	parser := &docopt.Parser{}
	args, _ := parser.ParseArgs(usageScan, inputArgs, "")

	// debug
	// common.Log.Info(args)

	if v, _ := args.Bool("--list-rules"); v {
		return listRules()
	}

	return runScanner(args)

}
