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

package rule

import (
	"embed"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// RemediationEffort indicates the estimated effort necessary to remediate a finding.
type RemediationEffort int

const (
	// RemediationEffortNone indicates a no remediation effort.
	RemediationEffortNone RemediationEffort = iota
	// RemediationEffortLow indicates a low remediation effort.
	RemediationEffortLow
	// RemediationEffortMedium indicates a medium remediation effort.
	RemediationEffortMedium
	// RemediationEffortHigh indicates a high remediation effort.
	RemediationEffortHigh
)

// Remediation represents the remediation for a finding.
type Remediation struct {
	// Patch for machines.
	Patch *string `json:"patch,omitempty"`
	// Text for humans.
	Text string `json:"text"`
	// Text in markdown format for humans.
	Markdown string `json:"markdown"`
	// Effort to remediate.
	Effort RemediationEffort `json:"effort"`
}

// nolint: govet
type jsonRemediation struct {
	Text     []string          `yaml:"text"`
	Markdown []string          `yaml:"markdown"`
	Effort   RemediationEffort `yaml:"effort"`
}

// nolint: govet
type jsonRule struct {
	ID             string `yaml:"id"`
	Short          string `yaml:"short"`
	Desc           string `yaml:"desc"`
	Motivation     string `yaml:"motivation"`
	Implementation string `yaml:"implementation"`
	// Risk           Risk            `yaml:"risk"`
	Remediation jsonRemediation `yaml:"remediation"`
}

// nolint: govet
type Rule struct {
	Name       string
	Short      string
	Desc       string
	Motivation string
	// Risk        Risk
	Remediation *Remediation
}

var errInvalid = errors.New("invalid")

// New create a new rule.
func New(loc embed.FS, ruleID string) (*Rule, error) {
	content, err := loc.ReadFile("def.yml")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalid, err)
	}

	r, err := parseFromJSON(content)
	if err != nil {
		return nil, err
	}

	if err := validate(r, ruleID); err != nil {
		return nil, err
	}

	return &Rule{
		Name:       r.ID,
		Short:      r.Short,
		Desc:       r.Desc,
		Motivation: r.Motivation,
		// Risk:       r.Risk,
		Remediation: &Remediation{
			Text:     strings.Join(r.Remediation.Text, "\n"),
			Markdown: strings.Join(r.Remediation.Markdown, "\n"),
			Effort:   r.Remediation.Effort,
		},
	}, nil
}

func validate(r *jsonRule, ruleID string) error {
	if err := validateID(r.ID, ruleID); err != nil {
		return fmt.Errorf("%w: %v", errInvalid, err)
	}
	// if err := validateRisk(r.Risk); err != nil {
	// 	return fmt.Errorf("%w: %v", errInvalid, err)
	// }
	if err := validateRemediation(r.Remediation); err != nil {
		return fmt.Errorf("%w: %v", errInvalid, err)
	}
	return nil
}

func validateID(actual, expected string) error {
	if actual != expected {
		return fmt.Errorf("%w: read '%v', expected '%v'", errInvalid,
			actual, expected)
	}
	return nil
}

func validateRemediation(r jsonRemediation) error {
	switch r.Effort {
	case RemediationEffortHigh, RemediationEffortMedium, RemediationEffortLow:
		return nil
	default:
		return fmt.Errorf("%w: %v", errInvalid, fmt.Sprintf("remediation '%v'", r))
	}
}

func parseFromJSON(content []byte) (*jsonRule, error) {
	r := jsonRule{}

	err := yaml.Unmarshal(content, &r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalid, err)
	}
	return &r, nil
}

// UnmarshalYAML is a custom unmarshalling function
// to transform the string into an enum.
func (r *RemediationEffort) UnmarshalYAML(n *yaml.Node) error {
	var str string
	if err := n.Decode(&str); err != nil {
		return fmt.Errorf("%w: %v", errInvalid, err)
	}

	// nolint:goconst
	switch n.Value {
	case "Low":
		*r = RemediationEffortLow
	case "Medium":
		*r = RemediationEffortMedium
	case "High":
		*r = RemediationEffortHigh
	default:
		return fmt.Errorf("%w: %q", errInvalid, str)
	}
	return nil
}

// String stringifies the enum.
func (r *RemediationEffort) String() string {
	switch *r {
	case RemediationEffortLow:
		return "Low"
	case RemediationEffortMedium:
		return "Medium"
	case RemediationEffortHigh:
		return "High"
	default:
		return ""
	}
}
