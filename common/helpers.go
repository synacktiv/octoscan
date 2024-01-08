package common

import (
	"net/http"
	"os"
	"regexp"
	"time"
)

// regexp for rules

var LettersRegexp = regexp.MustCompile("^[a-zA-Z]+$")
var GitHubOutputPwshRegexp = regexp.MustCompile(`(?m)(?i:env):GITHUB_OUTPUT`)
var GitHubOutputBashRegexp = regexp.MustCompile(`(?m)>>\s*"*\${*GITHUB_OUTPUT`)
var GitHubEnvPwshRegexp = regexp.MustCompile(`(?m)(?i:env):GITHUB_ENV`)
var GitHubEnvBashRexexp = regexp.MustCompile(`(?m)>{1,2}\s*"*\${*GITHUB_ENV`)

// GitCheckoutBashRexexp It’s not possible to include a backtick in a raw string literal (https://yourbasic.org/golang/multiline-string/)
var GitCheckoutBashRexexp = regexp.MustCompile(`(?m)git checkout.*(\$|` + regexp.QuoteMeta("`") + `)`)

var TriggerWithExternalData = []string{
	"issues", // might need to verify this one
	"issue_comment",
	"pull_request_target",
	"workflow_run",
}

func IsDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}

	return fileInfo.IsDir()
}

func IsStringInArray(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func IsInternetAvailable() error {
	url := "https://github.com"
	timeout := 5 * time.Second

	client := http.Client{
		Timeout: timeout,
	}

	// Create a new HTTP GET request to the specified URL
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	// Perform the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
