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
	"fmt"
	"strings"

	"github.com/ossf/scorecard/v4/checker"
	sce "github.com/ossf/scorecard/v4/errors"
	"github.com/ossf/scorecard/v4/evaluation"
	"github.com/ossf/scorecard/v4/finding"
)

// Fuzzing applies the score policy for the Fuzzing check.
func Fuzzing(name string, dl checker.DetailLogger,
	statements evaluation.Evaluation,
) checker.CheckResult {
	fuzzers := []string{}

	if len(statements) != 1 {
		e := sce.WithMessage(sce.ErrScorecardInternal, "1 single statement expected")
		return checker.CreateRuntimeErrorResult(name, e)
	}
	fuzzingStmt := statements[0]
	if fuzzingStmt.Outcome == finding.OutcomeNegative {
		return checker.CreateMinScoreResult(name, "project is not fuzzed")
	}
	// Get the probe IDs, which contains the name of the fuzzers.
	for i := range fuzzingStmt.Findings {
		f := fuzzingStmt.Findings[i]
		if f.Outcome == finding.OutcomePositive {
			fuzzers = append(fuzzers, f.Probe)
		}
	}

	return checker.CreateMaxScoreResult(name,
		fmt.Sprintf("project is fuzzed: %s", strings.Join(fuzzers, ",")))
}
