package common

import (
	"net/http"
	"os"
	"time"
)

func IsDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}

	return fileInfo.IsDir()
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
