package core

import (
	"context"
	"fmt"
	"net/http"
	"octoscan/common"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
)

type GitHub struct {
	client    *github.Client
	ctx       context.Context
	path      string
	org       string
	outputDir string
}

type GitHubOptions struct {
	Proxy     bool
	Token     string
	Path      string
	Org       string
	OutputDir string
}

func NewGitHub(opts GitHubOptions) *GitHub {
	var tc *http.Client

	ctx := context.Background()

	if opts.Token != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: opts.Token})
		tc = oauth2.NewClient(ctx, ts)
	}

	return &GitHub{
		client:    github.NewClient(tc),
		ctx:       ctx,
		path:      opts.Path,
		org:       opts.Org,
		outputDir: opts.OutputDir,
	}
}

func (gh *GitHub) Download() error {
	common.Log.Info(fmt.Sprintf("Downloading files of org: %s", gh.org))

	repos, _, err := gh.client.Repositories.List(gh.ctx, "", nil)

	if err != nil {
		common.Log.Error(fmt.Sprintf("Fail to list repositories of org %s: %v", gh.org, err))

		return err
	}

	for _, repo := range repos {
		if strings.EqualFold(repo.GetOwner().GetLogin(), gh.org) {
			err = gh.DownloadRepo(repo.GetName())
			if err != nil {
				common.Log.Error(fmt.Sprintf("Error while downloading files of repo: %s", repo.GetName()))
			}
		}
	}

	return nil
}

func (gh *GitHub) DownloadRepo(repo string) error {
	common.Log.Info(fmt.Sprintf("Downloading files of repo: %s", repo))

	branches, _, err := gh.client.Repositories.ListBranches(gh.ctx, gh.org, repo, nil)
	if err != nil {
		common.Log.Error(fmt.Sprintf("Fail to list branches of repository %s: %v", repo, err))

		return err
	}

	for _, branch := range branches {
		err := gh.DownloadContentFromBranch(repo, branch.GetName(), gh.path)
		if err != nil {
			common.Log.Error(err)
		}
	}

	return nil
}

func (gh *GitHub) DownloadContentFromBranch(repo string, branch string, path string) error {
	fileContent, directoryContent, res, err := gh.client.Repositories.GetContents(gh.ctx, gh.org, repo, path, &github.RepositoryContentGetOptions{Ref: branch})

	if res != nil && res.Status != "200 OK" {
		common.Log.Debug(fmt.Sprintf("Fail to get %s of repository %s (%s): path doesn't exist", path, repo, branch))

		return nil
	}

	if err != nil {
		return fmt.Errorf("fail to get %s of repository %s (%s): %w", path, repo, branch, err)
	}

	// create the dir for output
	fp := filepath.Join(gh.outputDir, repo, branch)
	_ = os.MkdirAll(fp, 0755)

	// used for the scanner
	_, _ = os.Create(filepath.Join(fp, ".git"))

	if fileContent != nil {
		return gh.saveFileContent(fileContent, repo, branch)
	} else if directoryContent != nil {
		// TODO doing it twice need to change
		return gh.downloadDirectory(repo, branch, path)
	}

	return nil
}

func (gh *GitHub) downloadFile(repo string, branch string, path string) error {
	fileContent, _, _, err := gh.client.Repositories.GetContents(gh.ctx, gh.org, repo, path, &github.RepositoryContentGetOptions{Ref: branch})

	if err != nil {
		// GitHub go fail to handle request and try to get file that doesn't exist from other branches
		common.Log.Verbose(fmt.Sprintf("Fail to get %s of repository %s (%s): %v", path, repo, branch, err))

		return err
	}

	return gh.saveFileContent(fileContent, repo, branch)
}

func (gh *GitHub) downloadDirectory(repo string, branch string, path string) error {
	_, directoryContent, _, err := gh.client.Repositories.GetContents(gh.ctx, gh.org, repo, path, &github.RepositoryContentGetOptions{Ref: branch})

	if err != nil {
		return err
	}

	for _, element := range directoryContent {
		switch element.GetType() {
		case "dir":
			err = gh.downloadDirectory(repo, branch, element.GetPath())
			if err != nil {
				return err
			}
		case "file":
			err = gh.downloadFile(repo, branch, element.GetPath())
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown type %s", element.GetType())
		}
	}

	return nil
}

func (gh *GitHub) saveFileContent(fileContent *github.RepositoryContent, repo string, branch string) error {
	content, err := fileContent.GetContent()
	if err != nil {
		return fmt.Errorf("fail to get file %s from repo %s (%s): %w", *fileContent.Name, repo, branch, err)
	}

	if content == "" {
		common.Log.Error(fmt.Sprintf("fail to get file content %s from repo %s (%s): empty content", *fileContent.Name, repo, branch))
	}

	return saveFileToDisk(content, filepath.Join(gh.outputDir, repo, branch, fileContent.GetPath()))
}

func saveFileToDisk(content string, path string) error {
	// create the dir for output
	// TODO
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	err := os.WriteFile(path, []byte(content), 0600)

	if err != nil {
		return fmt.Errorf("error writing file (%s): %w", path, err)
	}

	return nil
}
