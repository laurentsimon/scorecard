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

package binaryGradleActionInstalled

import (
	"embed"
	"fmt"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
)

//go:embed *.yml
var fs embed.FS

var probe = "binaryGradleActionInstalled"

func Run(raw *checker.RawResults) ([]finding.Finding, string, error) {
	// TODO: needs implementation.
	// For the demo, let's assume it fails.
	f, err := finding.NewNegative(fs, probe,
		"gradle Action is not installed", nil)
	if err != nil {
		return nil, probe, fmt.Errorf("create finding: %w", err)
	}
	return []finding.Finding{*f}, probe, nil
}
