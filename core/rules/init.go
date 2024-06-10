package rules

import (
	"encoding/json"

	"github.com/rhysd/actionlint"
)

// static init to prevent concurrent write
func init() {
	initRuleExpressionInjection()
	initGHSAVulnerabilityArray()
}

// overload the actionlint.BuiltinUntrustedInputs to add new inputs
func initRuleExpressionInjection() {
	untrustedInputSearchRoots := actionlint.BuiltinUntrustedInputs

	for _, e := range CustomUntrustedInputSearchRoots {
		untrustedInputSearchRoots.AddRoot(e)
	}
}

func initGHSAVulnerabilityArray() {
	_ = json.Unmarshal(GHSAJson, &GHSAVulnerabilities)
}
