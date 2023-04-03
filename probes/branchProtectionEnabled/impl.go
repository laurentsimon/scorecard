// Copyright 2020 OpenSSF Scorecard Authors
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

package branchProtectionEnabled

import (
	"embed"
	"fmt"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/probes/utils"
)

//go:embed *.yml
var fs embed.FS

var probe = "branchProtectionEnabled"

func Run(raw *checker.RawResults) ([]finding.Finding, string, error) {
	var findings []finding.Finding
	for i := range raw.BranchProtectionResults.Branches {
		branch := raw.BranchProtectionResults.Branches[i]
		f, _, err := utils.IsProtected(branch, fs, probe)
		if err != nil {
			return nil, probe, fmt.Errorf("create finding: %w", err)
		}

		findings = append(findings, *f)
	}

	if len(findings) == 0 {
		// This should never happen.
		f, err := finding.NewPositive(fs, probe, "no branch on this repository", nil)
		if err != nil {
			return nil, probe, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
	}
	return findings, probe, nil
}
