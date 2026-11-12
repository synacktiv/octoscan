package rules

import (
	"github.com/rhysd/actionlint"
)

// static init to prevent concurrent write
func init() {
	initRuleExpressionInjection()
}

// overload the actionlint.BuiltinUntrustedInputs to add new inputs
func initRuleExpressionInjection() {
	untrustedInputSearchRoots := actionlint.BuiltinUntrustedInputs

	for _, e := range CustomUntrustedInputSearchRoots {
		untrustedInputSearchRoots.AddRoot(e)
	}
}
