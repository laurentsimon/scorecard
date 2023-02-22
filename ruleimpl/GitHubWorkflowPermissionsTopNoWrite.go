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

package ruleimpl

import (
	"embed"
	"fmt"
	"strings"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/remediation"
)

func init() {
	if err := registerRule(gitHubWorkflowPermissionsStepsNoWrite); err != nil {
		panic(err)
	}
}

// TODO: take a config file as input.
func gitHubWorkflowPermissionsStepsNoWrite(fs embed.FS, raw *checker.RawResults) ([]finding.Finding, error) {
	var findings []finding.Finding
	remediationMetadata, _ := remediation.New(nil)
	permsData := raw.TokenPermissionsResults.TokenPermissions
	for _, r := range permsData {
		// We only care about top-level permission declarations.
		if r.LocationType != nil && *r.LocationType != checker.PermissionLocationTop {
			continue
		}

		var loc *finding.Location
		if r.File != nil {
			loc = &finding.Location{
				Type:      r.File.Type,
				Value:     r.File.Path,
				LineStart: &r.File.Offset,
			}
			if r.File.Snippet != "" {
				loc.Snippet = &r.File.Snippet
			}

			loc.Value = r.File.Path
		}

		text, err := createText(r)
		if err != nil {
			return nil, err
		}

		f, err := createFinding(fs, r.LocationType)
		if err != nil {
			return nil, err
		}

		f = f.WithMessage(text).WithLocation(loc)
		switch r.Type {
		case checker.PermissionLevelNone, checker.PermissionLevelRead:
			f = f.WithOutcome(finding.OutcomePositive)
			findings = append(findings, *f)
		case checker.PermissionLevelUndeclared:
			if r.LocationType == nil {
				return nil, fmt.Errorf("locationType is nil")
			}

			f = withRemediation(f, remediationMetadata, loc)
			findings = append(findings, *f)

		case checker.PermissionLevelWrite:
			f = withRemediation(f, remediationMetadata, loc)
			findings = append(findings, *f)
		}
	}

	if len(findings) == 0 {
		// TODO: share this function
		text := "no workflows found in the repository"
		if err := reportFinding(&findings, fs, "GitHubWorkflowPermissionsTopNoWrite",
			text, finding.OutcomeNotApplicable); err != nil {
			return nil, err
		}
	}

	return findings, nil
}

func reportFinding(findings *[]finding.Finding, fs embed.FS, ruleID, text string, o finding.Outcome) error {
	f, err := finding.New(fs, ruleID)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	f = f.WithMessage(text).WithOutcome(o)
	*findings = append(*findings, *f)
	return nil
}

func withRemediation(f *finding.Finding,
	rem *remediation.RemediationMetadata, loc *finding.Location,
) *finding.Finding {
	if loc != nil && loc.Value != "" {
		f = f.WithRemediationMetadata(map[string]string{
			"repo":     rem.Repo,
			"branch":   rem.Branch,
			"workflow": strings.TrimPrefix(loc.Value, ".github/workflows/"),
		})
	}
	return f
}

func createFinding(fs embed.FS, loct *checker.PermissionLocation) (*finding.Finding, error) {
	// TODO: only one or share with others
	if loct == nil || *loct == checker.PermissionLocationTop {
		f, err := finding.New(fs, "GitHubWorkflowPermissionsTopNoWrite")
		if err != nil {
			return nil, fmt.Errorf("%w", err.Error())
		}
		return f, nil
	}

	return nil, nil
}

func createText(t checker.TokenPermission) (string, error) {
	// By default, use the message already present.
	if t.Msg != nil {
		return *t.Msg, nil
	}

	// Ensure there's no implementation bug.
	if t.LocationType == nil {
		return "", fmt.Errorf("locationType is nil")
	}

	// Use a different text depending on the type.
	if t.Type == checker.PermissionLevelUndeclared {
		return fmt.Sprintf("no %s permission defined", *t.LocationType), nil
	}

	if t.Value == nil {
		return "", fmt.Errorf("Value fields is nil")
	}

	if t.Name == nil {
		return fmt.Sprintf("%s permissions set to '%v'", *t.LocationType,
			*t.Value), nil
	}

	return fmt.Sprintf("%s '%v' permission set to '%v'", *t.LocationType,
		*t.Name, *t.Value), nil
}
