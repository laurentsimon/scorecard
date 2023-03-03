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

package ruledefs

import (
	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/ruledefs/binaryGradleActionInstalled"
	"github.com/ossf/scorecard/v4/ruledefs/binaryGradleNotPresent"
	"github.com/ossf/scorecard/v4/ruledefs/binaryOtherNotPresent"
	"github.com/ossf/scorecard/v4/ruledefs/branchProtectionCheckRulesContext"
	"github.com/ossf/scorecard/v4/ruledefs/branchProtectionCodeownersEnabled"
	"github.com/ossf/scorecard/v4/ruledefs/branchProtectionCodeownersFile"
	"github.com/ossf/scorecard/v4/ruledefs/branchProtectionDeletionDisabled"
	"github.com/ossf/scorecard/v4/ruledefs/branchProtectionDismissStaleReviewDisabled"
	"github.com/ossf/scorecard/v4/ruledefs/branchProtectionEnabled"
	"github.com/ossf/scorecard/v4/ruledefs/branchProtectionLastPushApprovalEnabled"
	"github.com/ossf/scorecard/v4/ruledefs/branchProtectionReviewers"
	"github.com/ossf/scorecard/v4/ruledefs/branchProtectionUpdateToMerge"

	"github.com/ossf/scorecard/v4/ruledefs/branchProtectionEnforceAdmins"
	"github.com/ossf/scorecard/v4/ruledefs/branchProtectionForcePushDisabled"
	"github.com/ossf/scorecard/v4/ruledefs/fuzzedWithClusterFuzzLite"
	"github.com/ossf/scorecard/v4/ruledefs/fuzzedWithGoNative"
	"github.com/ossf/scorecard/v4/ruledefs/fuzzedWithOSSFuzz"
	"github.com/ossf/scorecard/v4/ruledefs/fuzzedWithOneFuzz"
	"github.com/ossf/scorecard/v4/ruledefs/gitHubWorkflowPermissionsTopNoWrite"
	"github.com/ossf/scorecard/v4/ruledefs/securityPolicyContainsDisclosure"
	"github.com/ossf/scorecard/v4/ruledefs/securityPolicyContainsLinks"
	"github.com/ossf/scorecard/v4/ruledefs/securityPolicyContainsText"
	"github.com/ossf/scorecard/v4/ruledefs/securityPolicyPresentInOrg"
	"github.com/ossf/scorecard/v4/ruledefs/securityPolicyPresentInRepo"
	"github.com/ossf/scorecard/v4/ruledefs/toolDependabotInstalled"
	"github.com/ossf/scorecard/v4/ruledefs/toolPyUpInstalled"
	"github.com/ossf/scorecard/v4/ruledefs/toolRenovateInstalled"
	"github.com/ossf/scorecard/v4/ruledefs/toolSonarTypeLiftInstalled"
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
	// Binaries.
	binaryOtherNotPresent.Run,
	binaryGradleNotPresent.Run,
	binaryGradleActionInstalled.Run,
	// Security Policy.
	securityPolicyPresentInRepo.Run,
	securityPolicyPresentInOrg.Run,
	securityPolicyContainsLinks.Run,
	securityPolicyContainsDisclosure.Run,
	securityPolicyContainsText.Run,
	// Dependency update tools.
	toolRenovateInstalled.Run,
	toolDependabotInstalled.Run,
	toolPyUpInstalled.Run,
	toolSonarTypeLiftInstalled.Run,
	// branch protection.
	branchProtectionEnabled.Run,
	branchProtectionForcePushDisabled.Run,
	branchProtectionDeletionDisabled.Run,
	branchProtectionEnforceAdmins.Run,
	branchProtectionCheckRulesContext.Run,
	branchProtectionUpdateToMerge.Run,
	branchProtectionDismissStaleReviewDisabled.Run,
	branchProtectionReviewers.Run,
	branchProtectionLastPushApprovalEnabled.Run,
	branchProtectionCodeownersEnabled.Run,
	branchProtectionCodeownersFile.Run,
}
