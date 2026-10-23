package main

import (
	"fmt"
	"os"

	"github.com/synacktiv/octoscan/cmd"
	"github.com/synacktiv/octoscan/common"

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
	version			Print the version


`

func main() {
	parser := &docopt.Parser{OptionsFirst: true}
	args, _ := parser.ParseArgs(usage, nil, "octoscan version "+versionString())

	cmd, _ := args.String("<command>")
	cmdArgs := args["<args>"].([]string)

	err := runCommand(cmd, cmdArgs)
	os.Exit(err)
}

func runCommand(command string, args []string) int {
	argv := append([]string{command}, args...)

	switch command {
	case "scan":
		return cmd.Scan(argv)
	case "dl":
		return cmd.Download(argv)
	case "version":
		fmt.Println("octoscan version " + versionString())

		return common.ExitStatusSuccessNoProblem
	default:
		common.Log.Info(fmt.Sprintf("%s is not a octoscan command. See 'octoscan --help'", command))

		return common.ExitStatusFailure
	}
}
