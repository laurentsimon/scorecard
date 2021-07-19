// Copyright 2020 Security Scorecard Authors
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

package checker

import (
	"errors"
	"fmt"
	"math"

	scorecarderrors "github.com/ossf/scorecard/errors"
)

// UPGRADEv2: to remove.
const (
	MaxResultConfidence  = 10
	HalfResultConfidence = 5
	MinResultConfidence  = 0
)

// ErrorDemoninatorZero indicates the denominator for a proportional result is 0.
// UPGRADEv2: to remove.
var ErrorDemoninatorZero = errors.New("internal error: denominator is 0")

//nolint
const (
	MaxResultScore          = 10
	HalfResultScore         = 5
	MinResultScore          = 0
	InconclusiveResultScore = -1
)

//nolint
type CheckResult struct {
	// Old structure
	Error       error `json:"-"`
	Name        string
	Details     []string
	Confidence  int
	Pass        bool
	ShouldRetry bool `json:"-"`

	// UPGRADEv2: New structure. Omitting unchanged Name field
	// for simplicity.
	Version  int           // 2. Default value of 0 indicates old structure
	Error2   error         `json:"-"` // Runtime error indicate a filure to run the check.
	Details2 []CheckDetail `json:"-"` // Details of tests and sub-checks
	Score2   int           `json:"-"` // {[0...1], -1 = Inconclusive}
	Reason2  string        `json:"-"` // A sentence describing the check result (score, etc)
}

// CreateResultWithScore is used when
// the check runs without runtime errors and want to assign a
// specific score.
func CreateResultWithScore(name, reason string, score int) CheckResult {
	pass := true
	//nolint
	if score < 8 {
		pass = false
	}
	return CheckResult{
		Name: name,
		// Old structure.
		Error:       nil,
		Confidence:  MaxResultScore,
		Pass:        pass,
		ShouldRetry: false,
		// New structure.
		//nolint
		Version: 2,
		Error2:  nil,
		Score2:  score,
		Reason2: reason,
	}
}

// CreateProportionalScoreResult is used when
// the check runs without runtime errors and we assign a
// proportional score. This may be used if a check contains
// multiple tests and we want to assign a score proportional
// the the number of tests that succeeded.
func CreateProportionalScoreResult(name, reason string, b, t int) CheckResult {
	pass := true
	//nolint
	score := int(math.Min(float64(10*b/t), float64(10)))
	//nolint
	if score < 8 {
		pass = false
	}
	return CheckResult{
		Name: name,
		// Old structure.
		Error: nil,
		//nolint
		Confidence:  10,
		Pass:        pass,
		ShouldRetry: false,
		// New structure.
		//nolint
		Version: 2,
		Error2:  nil,
		Score2:  score,
		Reason2: fmt.Sprintf("%v -- score normalized to %d", reason, score),
	}
}

// CreateMaxScoreResult is used when
// the check runs without runtime errors and we can assign a
// maximum score to the result.
func CreateMaxScoreResult(name, reason string) CheckResult {
	return CreateResultWithScore(name, reason, MaxResultScore)
}

// CreateMinScoreResult is used when
// the check runs without runtime errors and we can assign a
// minimum score to the result.
func CreateMinScoreResult(name, reason string) CheckResult {
	return CreateResultWithScore(name, reason, MinResultScore)
}

// CreateInconclusiveResult is used when
// the check runs without runtime errors, but we don't
// have enough evidence to set a score.
func CreateInconclusiveResult(name, reason string) CheckResult {
	return CheckResult{
		Name: name,
		// Old structure.
		Confidence:  0,
		Pass:        false,
		ShouldRetry: false,
		// New structure.
		//nolint
		Version: 2,
		Score2:  InconclusiveResultScore,
		Reason2: reason,
	}
}

// CreateRuntimeErrorResult is used when the check fails to run because of a runtime error.
func CreateRuntimeErrorResult(name string, e error) CheckResult {
	return CheckResult{
		Name: name,
		// Old structure.
		Error:       e,
		Confidence:  0,
		Pass:        false,
		ShouldRetry: false,
		// New structure.
		//nolint
		Version: 2,
		Error2:  e,
		Score2:  InconclusiveResultScore,
		Reason2: e.Error(), // Note: message already accessible by caller thru `Error`.
	}
}

// UPGRADEv2: will be renamed.
func MakeAndResult2(checks ...CheckResult) CheckResult {
	if len(checks) == 0 {
		// That should never happen.
		panic("MakeResult called with no checks")
	}

	worseResult := checks[0]
	// UPGRADEv2: will go away after old struct is removed.
	//nolint
	for _, result := range checks[1:] {
		if result.Score2 < worseResult.Score2 {
			worseResult = result
		}
	}
	return worseResult
}

// UPGRADEv2: will be removed.
func MakeInconclusiveResult(name string, err error) CheckResult {
	return CheckResult{
		Name:       name,
		Pass:       false,
		Confidence: 0,
		Error:      scorecarderrors.MakeLowConfidenceError(err),
	}
}

func MakePassResult(name string) CheckResult {
	return CheckResult{
		Name:       name,
		Pass:       true,
		Confidence: MaxResultConfidence,
		Error:      nil,
	}
}

func MakeFailResult(name string, err error) CheckResult {
	return CheckResult{
		Name:       name,
		Pass:       false,
		Confidence: MaxResultConfidence,
		Error:      err,
	}
}

func MakeRetryResult(name string, err error) CheckResult {
	return CheckResult{
		Name:        name,
		Pass:        false,
		ShouldRetry: true,
		Error:       scorecarderrors.MakeRetryError(err),
	}
}

// TODO: update this function to return a ResultDontKnow
// if the confidence is low?
func MakeProportionalResult(name string, numerator int, denominator int,
	threshold float32) CheckResult {
	if denominator == 0 {
		return MakeInconclusiveResult(name, ErrorDemoninatorZero)
	}
	if numerator == 0 {
		return CheckResult{
			Name:       name,
			Pass:       false,
			Confidence: MaxResultConfidence,
		}
	}
	actual := float32(numerator) / float32(denominator)
	if actual >= threshold {
		return CheckResult{
			Name:       name,
			Pass:       true,
			Confidence: int(actual * MaxResultConfidence),
		}
	}

	return CheckResult{
		Name:       name,
		Pass:       false,
		Confidence: MaxResultConfidence - int(actual*MaxResultConfidence),
	}
}

// Given a min result, check if another result is worse.
//nolint
func isMinResult(result, min CheckResult) bool {
	if Bool2int(result.Pass) < Bool2int(min.Pass) {
		return true
	}
	if result.Pass && result.Confidence < min.Confidence {
		return true
	} else if !result.Pass && result.Confidence > min.Confidence {
		return true
	}
	return false
}

// MakeAndResult means all checks must succeed. This returns a conservative result
// where the worst result is returned.
func MakeAndResult(checks ...CheckResult) CheckResult {
	minResult := CheckResult{
		Pass:       true,
		Confidence: MaxResultConfidence,
	}
	// UPGRADEv2: will go away after old struct is removed.
	//nolint
	for _, result := range checks {
		if minResult.Name == "" {
			minResult.Name = result.Name
		}
		if isMinResult(result, minResult) {
			minResult = result
		}
	}
	return minResult
}
