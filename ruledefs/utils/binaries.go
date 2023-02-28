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

package utils

import (
	"embed"
	"fmt"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
)

type PathMatch func(path string) bool

func BinaryRun(raw *checker.RawResults, fs embed.FS, ruleID string, match PathMatch) ([]finding.Finding, error) {
	var findings []finding.Finding
	binaries := raw.BinaryArtifactResults.Files
	for i := range binaries {
		file := binaries[i]
		if !match(file.Path) {
			continue
		}
		f, err := finding.NewWith(fs, ruleID, "binary found",
			file.Location(), finding.OutcomeNegative)
		if err != nil {
			return nil, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)

	}

	// No file found, positive result.
	if len(findings) == 0 {
		f, err := finding.NewPositive(fs, ruleID, "no binaries found", nil)
		if err != nil {
			return nil, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
	}

	return findings, nil
}
