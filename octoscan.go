package main

import (
	"fmt"
	"octoscan/cmd"
	"octoscan/common"
	"os"

	"github.com/docopt/docopt-go"
)

var usage = `octoscan

Usage:
	octoscan [-hv] <command> [<args>...]

Options:
	-h, --help
	-v, --version

Commands:
	dl			Download workflows files from GitHub
	scan			Scan workflows


`

func main() {
	parser := &docopt.Parser{OptionsFirst: true}
	args, _ := parser.ParseArgs(usage, nil, "octoscan version 0.1")

	cmd, _ := args.String("<command>")
	cmdArgs := args["<args>"].([]string)

	err := runCommand(cmd, cmdArgs)
	if err != nil {
		os.Exit(1)
	}
}

func runCommand(command string, args []string) error {
	argv := append([]string{command}, args...)

	switch command {
	case "scan":
		return cmd.Scan(argv)
	case "dl":
		return cmd.Download(argv)
	default:
		common.Log.Info(fmt.Sprintf("%s is not a octoscan command. See 'octoscan --help'", command))

		return nil
	}
}
