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

package evaluation

import (
	"embed"
	"fmt"
	"os"

	"github.com/ossf/scorecard/v4/finding"
)

//go:embed policy.yml
var policyFs embed.FS

func Run(findings []finding.Finding, policyFile string) (*Evaluation, error) {
	var content []byte
	var err error
	if policyFile != "" {
		content, err = os.ReadFile(policyFile)
	} else {
		content, err = policyFs.ReadFile("policy.yml")
	}
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	p, err := PolicyFromBytes(content)
	if err != nil {
		return nil, fmt.Errorf("create policy: %w", err)
	}

	return p.Evaluate(findings)
}
