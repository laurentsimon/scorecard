// Copyright 2021 OpenSSF Scorecard Authors
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

package evaluation

import (
	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/evaluation"
	"github.com/ossf/scorecard/v4/finding"
)

// BinaryArtifacts evaluates the raw results for the Binary-Artifacts check.
func BinaryArtifacts(name string, dl checker.DetailLogger,
	statements evaluation.Evaluation,
) checker.CheckResult {
	// Compute the score for backward compatibility.
	score := checker.MaxResultScore
	for i := range statements {
		stmt := statements[i]
		if stmt.Outcome != finding.OutcomeNegative {
			continue
		}
		// We remove one point for each binary.
		score--
	}

	if score < checker.MinResultScore {
		score = checker.MinResultScore
	}

	if score == checker.MaxResultScore {
		return checker.CreateMaxScoreResult(name, "no binaries found in the repo")
	}

	return checker.CreateResultWithScore(name, "binaries present in source code", score)
}
