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

package checks

import (
	"fmt"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/evaluation"
	"github.com/ossf/scorecard/v4/probes"
	prunner "github.com/ossf/scorecard/v4/probes/zrunner"
)

func evaluateCheck(c *checker.CheckRequest, checkName string) (*evaluation.Evaluation, error) {
	// Evaluate the check
	findings, err := prunner.Run(c.RawResults, probes.BinaryArtifacts)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	// TODO: make this file dynamic.
	eval, err := evaluation.Run(findings, "evaluation/policy.yml", &checkName)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	// Log the findings.
	if err := checker.LogFindings(findings, c.Dlogger); err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return eval, nil
}
