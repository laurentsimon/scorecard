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

package checks

import (
	"github.com/google/go-github/v32/github"
	"github.com/ossf/scorecard/checker"
)

const branchProtectionStr = "Branch-Protection"
const YES = "YES"
const NO = "NO"

func init() {
	registerCheck(branchProtectionStr, BranchProtection)
}

func BranchProtection(c *checker.CheckRequest) checker.CheckResult {
	repo, _, err := c.Client.Repositories.Get(c.Ctx, c.Owner, c.Repo)

	if err != nil {
		return checker.MakeRetryResult(branchProtectionStr, err)
	}

	protection, resp, err := c.Client.Repositories.
		GetBranchProtection(c.Ctx, c.Owner, c.Repo, *repo.DefaultBranch)
	const fileNotFound = 404
	if resp.StatusCode == fileNotFound {
		return checker.MakeRetryResult(branchProtectionStr, err)
	}

	if err != nil {
		c.Logf("Branch protection enabled: %s", NO)
		const confidence = 10
		return checker.CheckResult{
			Name:       branchProtectionStr,
			Pass:       false,
			Confidence: confidence,
		}
	}
	return IsBranchProtected(protection, c)
}

func IsBranchProtected(protection *github.Protection, c *checker.CheckRequest) checker.CheckResult {
	totalChecks := 8
	totalSuccess := 0

	if protection.GetAllowForcePushes() != nil {
		if protection.AllowForcePushes.Enabled {
			c.Logf("AllowForcePushes disabled: %s", NO)
		} else {
			c.Logf("AllowForcePushes disabled: %s", YES)
			totalSuccess++
		}
	} else {
		c.Logf("AllowForcePushes disabled: %s", YES)
	}

	if protection.GetAllowDeletions() != nil {
		if protection.AllowDeletions.Enabled {
			c.Logf("AllowDeletions disabled: %s", NO)
		} else {
			c.Logf("AllowDeletions disabled: %s", YES)
			totalSuccess++
		}
	} else {
		c.Logf("AllowDeletions disabled: %s", NO)
	}

	if protection.GetEnforceAdmins() != nil {
		if !protection.EnforceAdmins.Enabled {
			c.Logf("EnforceAdmins enabled: %s", NO)
		} else {
			c.Logf("EnforceAdmins enabled: %s", YES)
			totalSuccess++
		}
	} else {
		c.Logf("EnforceAdmins enabled: %s", NO)
	}

	if protection.GetRequireLinearHistory() != nil {
		if !protection.RequireLinearHistory.Enabled {
			c.Logf("RequireLinearHistory enabled: %s", NO)
		} else {
			c.Logf("RequireLinearHistory enabled: %s", YES)
			totalSuccess++
		}
	} else {
		c.Logf("RequireLinearHistory enabled: %s", NO)
	}

	// https://docs.github.com/en/rest/reference/repos#statuses
	if protection.GetRequiredStatusChecks() != nil {
		if !protection.RequiredStatusChecks.Strict {
			c.Logf("RequiredStatusChecks enabled: %s", NO)
		} else {
			if len(protection.RequiredStatusChecks.Contexts) == 0 {
				c.Logf("RequiredStatusChecks enabled: %s but has no contexts", YES)
			} else {
				c.Logf("RequiredStatusChecks enabled: %s", YES)
				totalSuccess++
			}
		}
	} else {
		c.Logf("RequiredStatusChecks enabled: %s", NO)
	}

	// https://registry.terraform.io/providers/integrations/github/latest/docs/resources/branch_protection
	if protection.GetRequiredPullRequestReviews() == nil {
		c.Logf("RequiredPullRequestReviews enabled: %s", NO)
	} else {
		if protection.RequiredPullRequestReviews.RequiredApprovingReviewCount < 2 {
			c.Logf("RequiredPullRequestReviews enabled: %s but with only %d reviews", YES, protection.RequiredPullRequestReviews.RequiredApprovingReviewCount)
		} else {
			c.Logf("RequiredPullRequestReviews enabled: %s", YES)
			totalSuccess++
		}

		if protection.RequiredPullRequestReviews.DismissStaleReviews {
			c.Logf("\tDismissStaleReviews enabled: %s", NO)
		} else {
			c.Logf("DismissStaleReviews enabled: %s", YES)
			totalSuccess++
		}

		// Not everyone sould be able to dismiss pull requests
		if protection.RequiredPullRequestReviews.DismissalRestrictions == nil {
			c.Logf("\tDismissalRestrictions enabled: %s", NO)
		} else {
			// TODO: check which users can do it.
			c.Logf("DismissalRestrictions enabled: %s", YES)
			totalSuccess++
		}

		// This is purely informative
		if !protection.RequiredPullRequestReviews.RequireCodeOwnerReviews {
			c.Logf("\tRequireCodeOwnerReviews enabled: %s", NO)
		} else {
			c.Logf("RequireCodeOwnerReviews enabled: %s", YES)
		}

	}

	return checker.MakeProportionalResult(branchProtectionStr, totalSuccess, totalChecks, 1.0)
}
