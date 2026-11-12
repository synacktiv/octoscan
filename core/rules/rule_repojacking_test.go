package rules

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rhysd/actionlint"
)

type fakeTransport map[string]int // URL -> status

func (f fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	status, ok := f[r.URL.String()]
	if !ok {
		return nil, io.ErrUnexpectedEOF // unknown URL: simulates a network error
	}

	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(""))}, nil
}

func repoJackingErrors(t *testing.T, transport http.RoundTripper, uses ...string) []*actionlint.Error {
	t.Helper()

	old := httpClient.Transport
	httpClient.Transport = transport

	ResetStatusCache()

	t.Cleanup(func() { httpClient.Transport = old })

	src := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"
	for _, u := range uses {
		src += "      - uses: " + u + "\n"
	}

	w, perr := actionlint.Parse([]byte(src))
	if len(perr) != 0 {
		t.Fatal(perr)
	}

	rule := NewRuleRepoJacking()
	for _, s := range w.Jobs["j"].Steps {
		if err := rule.VisitStep(s); err != nil {
			t.Fatal(err)
		}
	}

	if err := rule.VisitWorkflowPost(w); err != nil {
		t.Fatal(err)
	}

	return rule.Errs()
}

func TestRepoJacking(t *testing.T) {
	transport := fakeTransport{
		"https://github.com/ghost":   http.StatusNotFound,
		"https://github.com/octocat": http.StatusOK,
	}

	tests := []struct {
		name string
		uses []string
		want int
	}{
		{"unregistered owner", []string{"ghost/act@v1"}, 1},
		{"unregistered owner used twice", []string{"ghost/act@v1", "ghost/other/path@v2"}, 2},
		{"existing owner", []string{"octocat/act@v1"}, 0},
		{"known org is not fetched", []string{"actions/checkout@v4"}, 0}, // would be a network error otherwise
		{"local action", []string{"./foo"}, 0},
		{"self repository action", []string{"$/foo"}, 0},
		{"docker image", []string{"docker://alpine:3"}, 0},
		// a network error is reported once and must not stop the other owners from being checked
		{"network error then 404", []string{"unreachable/act@v1", "ghost/act@v1"}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(repoJackingErrors(t, transport, tt.uses...)); got != tt.want {
				t.Fatalf("got %d errors, want %d", got, tt.want)
			}
		})
	}
}
