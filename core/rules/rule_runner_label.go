/*
the MIT License

Copyright (c) 2021 rhysd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

/*
this is a copy of https://github.com/rhysd/actionlint/blob/main/rule_runner_label.go
I need to change the error message return in this rule. If you have a better solution
please contact me :)
*/

package rules

import (
	"strings"

	"github.com/rhysd/actionlint"
)

type runnerOSCompat uint

const (
	compatInvalid                   = 0
	compatUbuntu2004 runnerOSCompat = 1 << iota
	compatUbuntu2204
	compatMacOS1015
	compatMacOS110
	compatMacOS120
	compatMacOS120L
	compatMacOS120XL
	compatMacOS130
	compatMacOS130L
	compatMacOS130XL
	compatMacOS140
	compatMacOS140L
	compatMacOS140XL
	compatWindows2016
	compatWindows2019
	compatWindows2022
)

// https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners
// var allGitHubHostedRunnerLabels = []string{
// 	"windows-latest",
// 	"windows-2022",
// 	"windows-2019",
// 	"windows-2016",
// 	"ubuntu-latest",
// 	"ubuntu-22.04",
// 	"ubuntu-20.04",
// 	"ubuntu-18.04",
// 	"macos-latest",
// 	"macos-latest-xl",
// 	"macos-13-xl",
// 	"macos-13",
// 	"macos-13.0",
// 	"macos-12-xl",
// 	"macos-12",
// 	"macos-12.0",
// 	"macos-11",
// 	"macos-11.0",
// 	"macos-10.15",
// }

// https://docs.github.com/en/actions/hosting-your-own-runners/using-self-hosted-runners-in-a-workflow#using-default-labels-to-route-jobs
// var selfHostedRunnerPresetOSLabels = []string{
// 	"linux",
// 	"macos",
// 	"windows",
// }

var defaultRunnerOSCompats = map[string]runnerOSCompat{
	"ubuntu-latest":          compatUbuntu2204,
	"ubuntu-latest-4-cores":  compatUbuntu2204,
	"ubuntu-latest-8-cores":  compatUbuntu2204,
	"ubuntu-latest-16-cores": compatUbuntu2204,
	"ubuntu-22.04":           compatUbuntu2204,
	"ubuntu-20.04":           compatUbuntu2004,
	"macos-14-xl":            compatMacOS140XL,
	"macos-14-xlarge":        compatMacOS140XL,
	"macos-14-large":         compatMacOS140L,
	"macos-14":               compatMacOS140,
	"macos-14.0":             compatMacOS140,
	"macos-13-xl":            compatMacOS130XL,
	"macos-13-xlarge":        compatMacOS130XL,
	"macos-13-large":         compatMacOS130L,
	"macos-13":               compatMacOS130,
	"macos-13.0":             compatMacOS130,
	"macos-latest-xl":        compatMacOS120XL,
	"macos-latest-xlarge":    compatMacOS120XL,
	"macos-latest-large":     compatMacOS120L,
	"macos-latest":           compatMacOS120,
	"macos-12-xl":            compatMacOS120XL,
	"macos-12-xlarge":        compatMacOS120XL,
	"macos-12-large":         compatMacOS120L,
	"macos-12":               compatMacOS120,
	"macos-12.0":             compatMacOS120,
	"macos-11":               compatMacOS110,
	"macos-11.0":             compatMacOS110,
	"macos-10.15":            compatMacOS1015,
	"windows-latest":         compatWindows2022,
	"windows-latest-8-cores": compatWindows2022,
	"windows-2022":           compatWindows2022,
	"windows-2019":           compatWindows2019,
	"windows-2016":           compatWindows2016,
	"linux":                  compatUbuntu2204 | compatUbuntu2004, // Note: "linux" does not always indicate Ubuntu. It might be Fedora or Arch or ...
	"macos":                  compatMacOS130 | compatMacOS130L | compatMacOS130XL | compatMacOS120 | compatMacOS120L | compatMacOS120XL | compatMacOS110 | compatMacOS1015,
	"windows":                compatWindows2022 | compatWindows2019 | compatWindows2016,
}

var knownLabels = []string{
	"ubuntu-18.04",
	"ubuntu-16.04",
}

// RuleRunnerLabel is a rule to check runner label like "ubuntu-latest". There are two types of
// runners, GitHub-hosted runner and Self-hosted runner. GitHub-hosted runner is described at
// https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners .
// And Self-hosted runner is described at
// https://docs.github.com/en/actions/hosting-your-own-runners/using-self-hosted-runners-in-a-workflow .
type RuleRunnerLabel struct {
	actionlint.RuleBase
	// Note: Using only one compatibility integer is enough to check compatibility. But we remember
	// all past compatibility values here for better error message. If accumulating all compatibility
	// values into one integer, we can no longer know what labels are conflicting.
	compats map[runnerOSCompat]*actionlint.String
}

// NewRuleRunnerLabel creates new RuleRunnerLabel instance.
func NewRuleRunnerLabel() *RuleRunnerLabel {
	return &RuleRunnerLabel{
		RuleBase: actionlint.NewRuleBase(
			"runner-label",
			"Checks for GitHub-hosted and preset self-hosted runner labels in \"runs-on:\"",
		),
		compats: nil,
	}
}

// VisitJobPre is callback when visiting Job node before visiting its children.
func (rule *RuleRunnerLabel) VisitJobPre(n *actionlint.Job) error {
	if n.RunsOn == nil {
		return nil
	}

	var m *actionlint.Matrix
	if n.Strategy != nil {
		m = n.Strategy.Matrix
	}

	if len(n.RunsOn.Labels) == 1 {
		rule.checkLabel(n.RunsOn.Labels[0], m)

		return nil
	}

	rule.compats = map[runnerOSCompat]*actionlint.String{}
	if n.RunsOn.LabelsExpr != nil {
		rule.checkLabelAndConflict(n.RunsOn.LabelsExpr, m)
	} else {
		for _, label := range n.RunsOn.Labels {
			rule.checkLabelAndConflict(label, m)
		}
	}

	rule.compats = nil // reset

	return nil
}

// https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners
func (rule *RuleRunnerLabel) checkLabelAndConflict(l *actionlint.String, m *actionlint.Matrix) {
	if l.ContainsExpression() {
		ss := rule.tryToGetLabelsInMatrix(l, m)

		// add this check to detect non matrix expression in a label.
		if len(ss) == 0 {
			rule.Errorf(
				l.Pos,
				"Expression in a label: %q. It might be a self-hosted runner.",
				l.Value,
			)
		} else {
			cs := make([]runnerOSCompat, 0, len(ss))
			for _, s := range ss {
				comp := rule.verifyRunnerLabel(s)
				cs = append(cs, comp)
			}
			rule.checkCombiCompat(cs, ss)
		}

		return
	}

	comp := rule.verifyRunnerLabel(l)
	rule.checkCompat(comp, l)
}

func (rule *RuleRunnerLabel) checkLabel(l *actionlint.String, m *actionlint.Matrix) {
	if l.ContainsExpression() {
		ss := rule.tryToGetLabelsInMatrix(l, m)
		for _, s := range ss {
			rule.verifyRunnerLabel(s)
		}

		return
	}

	rule.verifyRunnerLabel(l)
}

func (rule *RuleRunnerLabel) verifyRunnerLabel(label *actionlint.String) runnerOSCompat {
	l := label.Value
	if c, ok := defaultRunnerOSCompats[strings.ToLower(l)]; ok {
		return c
	}

	// TODO
	known := knownLabels // rule.getKnownLabels()
	for _, k := range known {
		if strings.EqualFold(l, k) {
			return compatInvalid
		}
	}

	rule.Errorf(
		label.Pos,
		"label %q is non default and might be a self-hosted runner.",
		label.Value,
	)

	return compatInvalid
}

func (rule *RuleRunnerLabel) tryToGetLabelsInMatrix(label *actionlint.String, m *actionlint.Matrix) []*actionlint.String {
	if m == nil {
		return nil
	}

	// Only when the form of "${{...}}", evaluate the expression
	if !label.IsExpressionAssigned() {
		return nil
	}

	l := strings.TrimSpace(label.Value)
	p := actionlint.NewExprParser()
	expr, err := p.Parse(actionlint.NewExprLexer(l[3:])) // 3 means omit first "${{"

	if err != nil {
		return nil
	}

	deref, ok := expr.(*actionlint.ObjectDerefNode)
	if !ok {
		return nil
	}

	recv, ok := deref.Receiver.(*actionlint.VariableNode)
	if !ok {
		return nil
	}

	if recv.Name != "matrix" {
		return nil
	}

	prop := deref.Property
	labels := []*actionlint.String{}

	if m.Rows != nil {
		if row, ok := m.Rows[prop]; ok {
			for _, v := range row.Values {
				if s, ok := v.(*actionlint.RawYAMLString); ok && !containsExpression(s.Value) {
					labels = append(labels, &actionlint.String{Value: s.Value, Quoted: false, Pos: s.Pos()})
				}
			}
		}
	}

	if m.Include != nil {
		for _, combi := range m.Include.Combinations {
			if combi.Assigns != nil {
				if assign, ok := combi.Assigns[prop]; ok {
					if s, ok := assign.Value.(*actionlint.RawYAMLString); ok && !containsExpression(s.Value) {
						labels = append(labels, &actionlint.String{Value: s.Value, Quoted: false, Pos: s.Pos()})
					}
				}
			}
		}
	}

	return labels
}

func (rule *RuleRunnerLabel) checkConflict(comp runnerOSCompat, label *actionlint.String) bool {
	for c, l := range rule.compats {
		if c&comp == 0 {
			rule.Errorf(label.Pos, "label %q conflicts with label %q defined at %s. note: to run your job on each workers, use matrix", label.Value, l.Value, l.Pos)

			return false
		}
	}

	return true
}

func (rule *RuleRunnerLabel) checkCompat(comp runnerOSCompat, label *actionlint.String) {
	if comp == compatInvalid || !rule.checkConflict(comp, label) {
		return
	}

	if _, ok := rule.compats[comp]; !ok {
		rule.compats[comp] = label
	}
}

func (rule *RuleRunnerLabel) checkCombiCompat(comps []runnerOSCompat, labels []*actionlint.String) {
	for i, c := range comps {
		if c != compatInvalid && !rule.checkConflict(c, labels[i]) {
			// Overwrite the compatibility value with compatInvalid at conflicted label not to
			// register the label to `rule.compats`.
			comps[i] = compatInvalid
		}
	}

	for i, c := range comps {
		if c != compatInvalid {
			if _, ok := rule.compats[c]; !ok {
				rule.compats[c] = labels[i]
			}
		}
	}
}

// func (rule *RuleRunnerLabel) getKnownLabels() []string {
// 	if rule.RuleBase.config == nil {
// 		return knownLabels
// 	}
// 	return append(knownLabels, rule.RuleBase.config.SelfHostedRunner.Labels)
// }
