// Copyright 2023 OpenSSF Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ruleimpl

import (
	"embed"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
)

//go:embed *.yml
var rules embed.FS

type ruleImpl func(embed.FS, *checker.RawResults) ([]finding.Finding, error)

var rulesToRun []ruleImpl

func registerRule(impl ruleImpl) error {
	rulesToRun = append(rulesToRun, impl)
	return nil
}

// This is a place holder that would run all rules
// registered. For now, it simply hard codes the rules frm the permission checks.
func Run(raw *checker.RawResults) ([]finding.Finding, error) {
	var findings []finding.Finding
	for _, item := range rulesToRun {
		f := item
		// TODO: handle error
		// TODO: this should be run concurrently.
		ff, _ := f(rules, raw)
		if len(ff) > 0 {
			findings = append(findings, ff...)
		}
	}
	return findings, nil
}
