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

package branchProtectionLastPushApprovalEnabled

import (
	"embed"
	"fmt"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/clients"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/probes/utils"
)

//go:embed *.yml
var fs embed.FS

var id = "branchProtectionLastPushApprovalEnabled"

func handleSetting(branch clients.BranchRef) (*finding.Finding, error) {
	if branch.BranchProtectionRule.RequireLastPushApproval == nil {
		f, err := finding.NewNotAvailable(fs, id,
			fmt.Sprintf("cannot retrieve setting for branch '%s'", *branch.Name), nil)
		if err != nil {
			return nil, fmt.Errorf("create finding: %w", err)
		}
		return f, nil
	}
	if *branch.BranchProtectionRule.RequireLastPushApproval {
		f, err := finding.NewPositive(fs, id,
			fmt.Sprintf("setting enabled for branch '%s'", *branch.Name), nil)
		if err != nil {
			return nil, fmt.Errorf("create finding: %w", err)
		}
		return f, nil
	}

	f, err := finding.NewNegative(fs, id,
		fmt.Sprintf("setting disabled for branch '%s'", *branch.Name), nil)
	if err != nil {
		return nil, fmt.Errorf("create finding: %w", err)
	}
	return f, nil
}

func Run(raw *checker.RawResults) ([]finding.Finding, error) {
	return utils.BranchProtectionRun(raw.BranchProtectionResults.Branches,
		fs, id, handleSetting)
}
