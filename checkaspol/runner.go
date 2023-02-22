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

package checkaspol

import "github.com/ossf/scorecard/v4/finding"

func Run(findings []finding.Finding) error {
	// TODO: run the policy given a file.
	// compute a risk/effort (?).
	// have a description ?
	// provide a text for positive results, according to the
	// policy file.
	// PoC: the policy is called FuzzingPol and every results must be positives
	// we re-use the findings as-is but add a layer for each check.
	// the final risk calculation: propagate the highest risk
	// we can compute a score based on risk, but we also need to
	// account for number of occurences: or we only use one, and we use them all
	// or we remove scores entirely.
	return nil
}
