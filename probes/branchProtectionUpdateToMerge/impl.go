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

package branchProtectionUpdateToMerge

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

var probe = "branchProtectionUpdateToMerge"

func handleSetting(branch clients.BranchRef) (*finding.Finding, error) {
	if branch.BranchProtectionRule.CheckRules.UpToDateBeforeMerge == nil {
		f, err := finding.NewNotAvailable(fs, probe,
			fmt.Sprintf("cannot retrieve setting for branch '%s'", *branch.Name), nil)
		if err != nil {
			return nil, fmt.Errorf("create finding: %w", err)
		}
		return f, nil
	}
	if *branch.BranchProtectionRule.CheckRules.UpToDateBeforeMerge {
		f, err := finding.NewPositive(fs, probe,
			fmt.Sprintf("status checks require up-to-date branches for '%s'", *branch.Name), nil)
		if err != nil {
			return nil, fmt.Errorf("create finding: %w", err)
		}
		return f, nil
	}

	f, err := finding.NewNegative(fs, probe,
		fmt.Sprintf("status checks require up-to-date branches for branch '%s'", *branch.Name), nil)
	if err != nil {
		return nil, fmt.Errorf("create finding: %w", err)
	}
	return f, nil
}

func Run(raw *checker.RawResults) ([]finding.Finding, string, error) {
	return utils.BranchProtectionRun(raw.BranchProtectionResults.Branches,
		fs, probe, handleSetting)
}
