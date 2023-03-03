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

package branchProtectionCodeownersFile

import (
	"embed"
	"fmt"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
)

//go:embed *.yml
var fs embed.FS

var id = "branchProtectionCodeownersFile"

func Run(raw *checker.RawResults) ([]finding.Finding, error) {
	var findings []finding.Finding
	for i := range raw.BranchProtectionResults.CodeownersFiles {
		file := raw.BranchProtectionResults.CodeownersFiles[i]

		// See https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners#codeowners-file-location.
		// CODEOWNERS in the root, docs/, or .github/
		if file.Path != "CODEOWNERS" && file.Path != "docs/CODEOWNERS" &&
			file.Path != ".github/CODEOWNERS" {
			continue
		}
		f, err := finding.NewPositive(fs, id, "CODEOWNERS file present", file.Location())
		if err != nil {
			return nil, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
	}

	if len(findings) == 0 {
		f, err := finding.NewNegative(fs, id, "no CODEOWNERS file present", nil)
		if err != nil {
			return nil, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
	}
	return findings, nil
}
