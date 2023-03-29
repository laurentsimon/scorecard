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

package checks

import (
	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/checks/evaluation"
	"github.com/ossf/scorecard/v4/checks/raw"
	sce "github.com/ossf/scorecard/v4/errors"
	pevaluation "github.com/ossf/scorecard/v4/evaluation"
	"github.com/ossf/scorecard/v4/probes"
	prunner "github.com/ossf/scorecard/v4/probes/zrunner"
)

// CheckBinaryArtifacts is the exported name for Binary-Artifacts check.
const CheckBinaryArtifacts string = "Binary-Artifacts"

// nolint
func init() {
	supportedRequestTypes := []checker.RequestType{
		checker.CommitBased,
	}
	if err := registerCheck(CheckBinaryArtifacts, BinaryArtifacts, supportedRequestTypes); err != nil {
		// this should never happen
		panic(err)
	}
}

// BinaryArtifacts  will check the repository contains binary artifacts.
func BinaryArtifacts(c *checker.CheckRequest) checker.CheckResult {
	rawData, err := raw.BinaryArtifacts(c.RepoClient)
	if err != nil {
		e := sce.WithMessage(sce.ErrScorecardInternal, err.Error())
		return checker.CreateRuntimeErrorResult(CheckBinaryArtifacts, e)
	}

	// Return raw results.
	if c.RawResults != nil {
		c.RawResults.BinaryArtifactResults = rawData
	}

	// Evaluate the check
	findings, err := prunner.Run(c.RawResults, probes.BinaryArtifacts)
	if err != nil {
		e := sce.WithMessage(sce.ErrScorecardInternal, err.Error())
		return checker.CreateRuntimeErrorResult(CheckBinaryArtifacts, e)
	}
	// var eval *evaluation.Evaluation
	eval, err := pevaluation.Run(findings, "probes/policy.yml")
	if err != nil {
		e := sce.WithMessage(sce.ErrScorecardInternal, err.Error())
		return checker.CreateRuntimeErrorResult(CheckBinaryArtifacts, e)
	}

	// Log the findings.
	if err := checker.LogFindings(findings, c.Dlogger); err != nil {
		e := sce.WithMessage(sce.ErrScorecardInternal, err.Error())
		return checker.CreateRuntimeErrorResult(CheckBinaryArtifacts, e)
	}

	// Return the score evaluation.
	return evaluation.BinaryArtifacts(CheckBinaryArtifacts, c.Dlogger, findings)
}
