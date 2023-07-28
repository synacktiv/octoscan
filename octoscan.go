package main

import (
	"octoscan/common"
	"octoscan/core/scanner"
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

func runScanner(args *docopt.Opts, opts *scanner.ScannerOptions) ([]*actionlint.Error, error) {

	l, err := scanner.NewScanner(os.Stdout, opts)
	if err != nil {
		return nil, err
	}

	file, _ := args.String("<file>")

	return l.ScanFile(file, nil)
}

func main() {

	var opts scanner.ScannerOptions

	parser := &docopt.Parser{}
	args, _ := parser.ParseArgs(usage, nil, "octoscan version 0.1")

	if d, _ := args.Bool("--debug"); d {
		common.Log.SetLevel(common.LogLevelDebug)
	}

	common.Log.Debug(args)

	if v, _ := args.Bool("--verbose"); v {
		common.Log.SetLevel(common.LogLevelVerbose)
	}

	runScanner(&args, &opts)

}
