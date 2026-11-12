// Command ghsa regenerates core/rules/assets/ghsa.json from the GitHub Advisory Database.
//
//	go run ./tools/ghsa > core/rules/assets/ghsa.json   (set GITHUB_TOKEN to avoid the anonymous rate limit)
//
// Only what the known-vulnerability rule needs is kept, the full advisories are far too big to embed.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
)

type advisory struct {
	ID              string `json:"ghsa_id"`
	WithdrawnAt     any    `json:"withdrawn_at"`
	Vulnerabilities []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Range string `json:"vulnerable_version_range"`
		Fixed string `json:"first_patched_version"`
	} `json:"vulnerabilities"`
}

// Entry is the compact format read by the rule.
type entry struct {
	ID      string `json:"id"`
	Package string `json:"package"`
	Range   string `json:"range"`
	Fixed   string `json:"fixed,omitempty"`
}

var nextLink = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var out []entry

	url := "https://api.github.com/advisories?ecosystem=actions&type=reviewed&per_page=100"

	for url != "" {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Accept", "application/vnd.github+json")

		if t := os.Getenv("GITHUB_TOKEN"); t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
		}

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}

		var page []advisory

		err = json.NewDecoder(res.Body).Decode(&page)
		link := res.Header.Get("Link")
		status := res.StatusCode
		res.Body.Close()

		if status != http.StatusOK {
			return fmt.Errorf("%s: unexpected status %d", url, status)
		}

		if err != nil {
			return err
		}

		for _, a := range page {
			if a.WithdrawnAt != nil {
				continue
			}

			for _, v := range a.Vulnerabilities {
				if v.Package.Name != "" && v.Range != "" {
					out = append(out, entry{a.ID, v.Package.Name, v.Range, v.Fixed})
				}
			}
		}

		url = ""
		if m := nextLink.FindStringSubmatch(link); m != nil {
			url = m[1]
		}
	}

	// stable output keeps the diffs of future updates readable
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}

		return out[i].Package < out[j].Package
	})

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")

	return enc.Encode(out)
}
