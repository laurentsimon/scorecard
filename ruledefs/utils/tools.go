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

func ToolsRun(tools []checker.Tool, fs embed.FS, ruleID string,
	foundOutcome, notFoundOutcome finding.Outcome, match func(tool checker.Tool) bool,
) ([]finding.Finding, error) {
	var findings []finding.Finding
	for i := range tools {
		tool := tools[i]
		if !match(tool) {
			continue
		}

		if len(tool.Files) == 0 {
			f, err := finding.NewWith(fs, ruleID, fmt.Sprintf("tool '%s' is used", tool.Name),
				nil, foundOutcome)
			if err != nil {
				return nil, fmt.Errorf("create finding: %w", err)
			}
			findings = append(findings, *f)
		} else {
			// Use only the first file.
			f, err := finding.NewWith(fs, ruleID, fmt.Sprintf("tool '%s' is used", tool.Name),
				tool.Files[0].Location(), foundOutcome)
			if err != nil {
				return nil, fmt.Errorf("create finding: %w", err)
			}
			findings = append(findings, *f)
		}

	}

	// No tools found.
	if len(findings) == 0 {
		f, err := finding.NewWith(fs, ruleID, "tool not used",
			nil, notFoundOutcome)
		if err != nil {
			return nil, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
	}

	return findings, nil
}
