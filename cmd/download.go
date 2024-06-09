package cmd

import (
	"octoscan/common"
	"octoscan/core"
	"strings"

	"github.com/docopt/docopt-go"
)

var usageDownload = `Octoscan.

Usage:
	octoscan dl [options] --org <org> [--repo <repo> --token <pat> --default-branch --path <path> --output-dir <dir>]

Options:
	-h, --help  						Show help
	-d, --debug  						Debug output
	--verbose  						Verbose output
	--org <org> 						Organizations to target
	--repo <repo>						Repository to target
	--token <pat>						GHP to authenticate to GitHub
	--default-branch  					Only download workflows from the default branch
	--max-branches <num>  					Limit the number of branches to download
	--path <path>						GitHub file path to download [default: .github/workflows]
	--output-dir <dir>					Output dir where to download files [default: octoscan-output]

`

func runDownloader(args docopt.Opts) error {
	var err error

	path, _ := args.String("--path")
	org, _ := args.String("--org")
	dir, _ := args.String("--output-dir")
	token, _ := args.String("--token")
	repo, _ := args.String("--repo")
	maxBranches, _ := args.Int("--max-branches")

	path = strings.Trim(path, "/")
	// docopt is not working with the default arg I don't know why !
	if path == "" {
		path = ".github/workflows"
	}

	if dir == "" {
		dir = "octoscan-output"
	}

	ghOpts := core.GitHubOptions{
		Path:              path,
		Org:               org,
		OutputDir:         dir,
		Token:             token,
		DefaultBranchOnly: args["--default-branch"].(bool),
		MaxBranches:       maxBranches,
	}

	gh := core.NewGitHub(ghOpts)

	if repo != "" {
		err = gh.DownloadRepo(repo)
	} else {
		err = gh.Download()
	}

	return err
}

func Download(inputArgs []string) error {
	parser := &docopt.Parser{}
	args, _ := parser.ParseArgs(usageDownload, inputArgs, "")

	if d, _ := args.Bool("--debug"); d {
		common.Log.SetLevel(common.LogLevelDebug)
	}

	if v, _ := args.Bool("--verbose"); v {
		common.Log.SetLevel(common.LogLevelVerbose)
	}

	common.Log.Debug(args)

	return runDownloader(args)
}
