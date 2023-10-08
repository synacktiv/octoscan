package core

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"octoscan/common"
	"octoscan/core/rules"

	"github.com/rhysd/actionlint"
)

type OctoLinter struct {
	actionlint.Linter
}

func OnRulesCreated(rules []actionlint.Rule) []actionlint.Rule {
	res := filterUnWantedRules(rules)
	res = append(res, addCustomRules()...)
	return res
}

func filterUnWantedRules(rules []actionlint.Rule) []actionlint.Rule {
	res := []actionlint.Rule{}

	for _, r := range rules {
		// only keep credential and shellcheck rule
		if r.Name() == "credentials" || r.Name() == "shellcheck" {
			res = append(res, r)
		}
	}

	return res
}

func addCustomRules() []actionlint.Rule {
	return []actionlint.Rule{
		rules.NewRuleDangerousAction(),
		rules.NewRuleDangerousCheckout(),
		rules.NewRuleExpressionInjection(),
		rules.NewRuleDangerousWrite(),
		rules.NewRuleLocalAction(),
		rules.NewRuleOIDCAction(),
		rules.NewRuleRepoJacking(),
	}
}

// LintRepositoryRecurse search for all GitHub project recursively and run the linter
func (l *OctoLinter) LintRepositoryRecurse(dir string) {
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		w := filepath.Join(path, ".github", "workflows")
		if s, err := os.Stat(w); err == nil && s.IsDir() {
			l.LintRepository(w)

			return fs.SkipDir
		}

		return nil
	}); err != nil {
		common.Log.Error(fmt.Errorf("could not read files in %q: %w", "./", err))
	}
}
