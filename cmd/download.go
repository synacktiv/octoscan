package cmd

import (
	"strings"

	"github.com/synacktiv/octoscan/common"
	"github.com/synacktiv/octoscan/core"

	"github.com/docopt/docopt-go"
)

var usageDownload = `Octoscan.

Usage:
	octoscan dl [options] --org <org> [--repo <repo> --token <pat> --default-branch --max-branches <num> --path <path> --output-dir <dir> --include-archives]

Options:
	-h, --help  						Show help
	-d, --debug  						Debug output
	--verbose  						Verbose output
	--org <org>  						Organizations to target
	--repo <repo>  						Repository to target
	--token <pat>  						GHP to authenticate to GitHub
	--default-branch  					Only download workflows from the default branch
	--max-branches <num>  					Limit the number of branches to download
	--path <path>  						GitHub file path to download [default: .github/workflows]
	--output-dir <dir>  					Output dir where to download files [default: octoscan-output]
	--include-archives  					Also download archived repositories

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

	ghOpts := core.GitHubOptions{
		Path:              path,
		Org:               org,
		OutputDir:         dir,
		Token:             token,
		DefaultBranchOnly: args["--default-branch"].(bool),
		MaxBranches:       maxBranches,
		IncludeArchives:   args["--include-archives"].(bool),
	}

	gh := core.NewGitHub(ghOpts)

	if repo != "" {
		err = gh.DownloadRepo(repo)
	} else {
		err = gh.Download()
	}

	return err
}

func Download(inputArgs []string) int {
	parser := &docopt.Parser{}
	args, _ := parser.ParseArgs(usageDownload, inputArgs, "")

	if d, _ := args.Bool("--debug"); d {
		common.Log.SetLevel(common.LogLevelDebug)
	}

	if v, _ := args.Bool("--verbose"); v {
		common.Log.SetLevel(common.LogLevelVerbose)
	}

	common.Log.Debug(args)

	err := runDownloader(args)
	if err != nil {
		return common.ExitStatusFailure
	}

	return common.ExitStatusSuccessNoProblem
}
