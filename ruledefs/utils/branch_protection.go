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

	"github.com/ossf/scorecard/v4/clients"
	"github.com/ossf/scorecard/v4/finding"
)

// Protected field only indates that the branch matches
// one `Branch protection rules`. All settings may be disabled,
// so it does not provide any guarantees.
func IsProtected(branch clients.BranchRef, fs embed.FS, ruleID string) (*finding.Finding, bool, error) {
	if branch.Protected == nil {
		f, err := finding.NewNotAvailable(fs, ruleID,
			fmt.Sprintf("cannot retrieve settings for branch '%s' not ", *branch.Name), nil)
		if err != nil {
			return nil, false, fmt.Errorf("create finding: %w", err)
		}
		return f, false, nil
	}

	if !*branch.Protected {
		f, err := finding.NewNegative(fs, ruleID,
			fmt.Sprintf("branch '%s' has no protection", *branch.Name), nil)
		if err != nil {
			return nil, false, fmt.Errorf("create finding: %w", err)
		}
		return f, false, nil
	}
	f, err := finding.NewPositive(fs, ruleID,
		fmt.Sprintf("branch '%s' has protection enabled", *branch.Name), nil)
	if err != nil {
		return nil, false, fmt.Errorf("create finding: %w", err)
	}
	return f, true, nil
}

func BranchProtectionRun(branches []clients.BranchRef,
	fs embed.FS, ruleID string,
	getSetting func(clients.BranchRef) (*finding.Finding, error),
) ([]finding.Finding, error) {
	var findings []finding.Finding
	for i := range branches {
		branch := branches[i]
		f, ok, err := IsProtected(branch, fs, ruleID)
		if err != nil {
			return nil, fmt.Errorf("create finding: %w", err)
		}
		if !ok {
			// Only report non-positive results.
			findings = append(findings, *f)
			continue
		}

		// branch protection is enabled. Let's retrieve the setting
		// we're looking for.
		ff, err := getSetting(branch)
		if err != nil {
			return nil, fmt.Errorf("getSetting: %w", err)
		}
		if ff == nil {
			return nil, fmt.Errorf("nil findings: %v, %v", i, branch.Name)
		}

		findings = append(findings, *ff)
	}

	if len(findings) == 0 {
		// This should never happen.
		f, err := finding.NewPositive(fs, ruleID, "no branch on this repository", nil)
		if err != nil {
			return nil, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
	}
	return findings, nil
}
