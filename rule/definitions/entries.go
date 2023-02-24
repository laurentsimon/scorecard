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

package definitions

import (
	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/rule/definitions/fuzzedWithClusterFuzzLite"
	"github.com/ossf/scorecard/v4/rule/definitions/fuzzedWithGoNative"
	"github.com/ossf/scorecard/v4/rule/definitions/fuzzedWithOSSFuzz"
	"github.com/ossf/scorecard/v4/rule/definitions/fuzzedWithOneFuzz"
	"github.com/ossf/scorecard/v4/rule/definitions/gitHubWorkflowPermissionsTopNoWrite"
)

type entryImpl func(*checker.RawResults) ([]finding.Finding, error)

var EntriesToRun = []entryImpl{
	// Workflow permissions.
	gitHubWorkflowPermissionsTopNoWrite.Run,
	// Fuzzing.
	fuzzedWithOSSFuzz.Run,
	fuzzedWithOneFuzz.Run,
	fuzzedWithGoNative.Run,
	fuzzedWithClusterFuzzLite.Run,
}
