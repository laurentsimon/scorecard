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

package probes

import (
	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/probes/binaryGradleActionInstalled"
	"github.com/ossf/scorecard/v4/probes/binaryGradleNotPresent"
	"github.com/ossf/scorecard/v4/probes/binaryOtherNotPresent"
	"github.com/ossf/scorecard/v4/probes/branchProtectionCheckRulesContext"
	"github.com/ossf/scorecard/v4/probes/branchProtectionCodeownersEnabled"
	"github.com/ossf/scorecard/v4/probes/branchProtectionCodeownersFile"
	"github.com/ossf/scorecard/v4/probes/branchProtectionDeletionDisabled"
	"github.com/ossf/scorecard/v4/probes/branchProtectionDismissStaleReviewDisabled"
	"github.com/ossf/scorecard/v4/probes/branchProtectionEnabled"
	"github.com/ossf/scorecard/v4/probes/branchProtectionLastPushApprovalEnabled"
	"github.com/ossf/scorecard/v4/probes/branchProtectionReviewers"
	"github.com/ossf/scorecard/v4/probes/branchProtectionUpdateToMerge"

	"github.com/ossf/scorecard/v4/probes/branchProtectionEnforceAdmins"
	"github.com/ossf/scorecard/v4/probes/branchProtectionForcePushDisabled"
	"github.com/ossf/scorecard/v4/probes/fuzzedWithClusterFuzzLite"
	"github.com/ossf/scorecard/v4/probes/fuzzedWithGoNative"
	"github.com/ossf/scorecard/v4/probes/fuzzedWithOSSFuzz"
	"github.com/ossf/scorecard/v4/probes/fuzzedWithOneFuzz"
	"github.com/ossf/scorecard/v4/probes/fuzzedWithPropertyBasedHaskell"

	"github.com/ossf/scorecard/v4/probes/gitHubWorkflowPermissionsTopNoWrite"
	"github.com/ossf/scorecard/v4/probes/securityPolicyContainsDisclosure"
	"github.com/ossf/scorecard/v4/probes/securityPolicyContainsLinks"
	"github.com/ossf/scorecard/v4/probes/securityPolicyContainsText"
	"github.com/ossf/scorecard/v4/probes/securityPolicyPresentInOrg"
	"github.com/ossf/scorecard/v4/probes/securityPolicyPresentInRepo"
	"github.com/ossf/scorecard/v4/probes/toolDependabotInstalled"
	"github.com/ossf/scorecard/v4/probes/toolPyUpInstalled"
	"github.com/ossf/scorecard/v4/probes/toolRenovateInstalled"
	"github.com/ossf/scorecard/v4/probes/toolSonarTypeLiftInstalled"
)

type ProbeImpl func(*checker.RawResults) ([]finding.Finding, string, error)

var (
	AllProbes []ProbeImpl
	Fuzzing   = []ProbeImpl{
		fuzzedWithOSSFuzz.Run,
		fuzzedWithOneFuzz.Run,
		fuzzedWithGoNative.Run,
		fuzzedWithClusterFuzzLite.Run,
		fuzzedWithPropertyBasedHaskell.Run,
	}
	BinaryArtifacts = []ProbeImpl{
		binaryGradleNotPresent.Run,
		binaryGradleActionInstalled.Run,
		binaryOtherNotPresent.Run,
	}
	SecurityPolicy = []ProbeImpl{
		securityPolicyPresentInRepo.Run,
		securityPolicyPresentInOrg.Run,
		securityPolicyContainsLinks.Run,
		securityPolicyContainsDisclosure.Run,
		securityPolicyContainsText.Run,
	}
	DependencyToolUpdates = []ProbeImpl{
		toolRenovateInstalled.Run,
		toolDependabotInstalled.Run,
		toolPyUpInstalled.Run,
		toolSonarTypeLiftInstalled.Run,
	}
	BranchProtection = []ProbeImpl{
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
	TokenPermissions = []ProbeImpl{
		gitHubWorkflowPermissionsTopNoWrite.Run,
		// TODO:gitHubWorkflowPermissionsStepsNoWrite.Run,
	}
)

func concatMultipleSlices[T any](slices [][]T) []T {
	var totalLen int

	for _, s := range slices {
		totalLen += len(s)
	}

	result := make([]T, totalLen)

	var i int

	for _, s := range slices {
		i += copy(result[i:], s)
	}

	return result
}

func init() {
	AllProbes = concatMultipleSlices([][]ProbeImpl{
		TokenPermissions, Fuzzing,
		BinaryArtifacts, SecurityPolicy,
		DependencyToolUpdates, BranchProtection,
	})
}
