// Copyright 2021 OpenSSF Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package evaluation

import (
	"fmt"
	"strings"

	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"

	"github.com/ossf/scorecard/v4/finding"
)

// Policy specifies a set of tests.
type Policy struct {
	Version    int         `yaml:"version"`
	Statements []Statement `yaml:"statements"`
}

// Risk indicates a risk.
type Risk int

const (
	// RiskNone is a no risk.
	RiskNone Risk = iota
	// RiskLow is a low risk.
	RiskLow
	// RiskMedium is a medium risk.
	RiskMedium
	// RiskHigh is a high risk.
	RiskHigh
	// RiskCritical is a critical risk.
	RiskCritical
)

// Logic indicates the logic type
type Logic int

const (
	// LogicAnd indicates an "And".
	LogicAnd Logic = iota
	// LogicOr indicates an "Or".
	LogicOr
)

type Confidence int

const (
	// ConfidenceNone is no confidence.
	ConfidenceNone Confidence = iota
	// ConfidenceLow is a low confidence.
	ConfidenceLow
	// ConfidenceMedium is a medium confidence.
	ConfidenceMedium
	// ConfidenceHigh is a high confidence.
	ConfidenceHigh
)

type Evaluation []EvaluatedStatement

// Result is the result of a statement.
type EvaluatedStatement struct {
	Name       string            `json:"name"`
	Outcome    finding.Outcome   `json:"outcome"`
	Risk       Risk              `json:"risk"`
	Text       string            `json:"text"`
	Labels     []string          `json:"labels"`
	Logic      Logic             `json:"logic"`
	Confidence Confidence        `json:"confidence"`
	Findings   []finding.Finding `json:"findings"`
}

// Test specifies a policy for evaluating a set of results and the remediation
// advice should the results fail the requirements.
type Statement struct {
	Name         string            `yaml:"name"`
	Require      *Clause           `yaml:"require"`
	NegativeText string            `yaml:"negativeText"`
	PositiveText string            `yaml:"positiveText"`
	Risk         Risk              `yaml:"risk"`
	Confidence   []finding.Outcome `yaml:"confidence"`
	Labels       []string          `yaml:"labels"`
}
type Clause struct {
	// Exactly one of these fields must be populated.
	// Statement evaluates to true if the specified Statement passed.
	// TODO: make is a pointer?
	Probe string `yaml:"probe,omitempty"`
	// And evalutes to true if its set of clauses all evalute true.
	And []*Clause `yaml:"and,omitempty"`
	// Or evalutes to true if any of its set of clauses evalute true.
	Or []*Clause `yaml:"or,omitempty"`
	// Not evalutes to true if its clause does not evalute true.
	Not *Clause `yaml:"not,omitempty"`
}

func PolicyFromBytes(content []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(content, &p); err != nil {
		return nil, fmt.Errorf("unmarshal policy file: %w", err)
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("unsupported version: %v", p.Version)
	}
	// TODO: validate no repeatitive entries.
	if err := p.validateRisks(); err != nil {
		return nil, fmt.Errorf("validate risks: %w", err)
	}

	if err := p.validateConfidence(); err != nil {
		return nil, fmt.Errorf("validate confidence: %w", err)
	}

	return &p, nil
}

func (es *EvaluatedStatement) LegacyCheck(checkName string) bool {
	return slices.Contains(es.Labels, "check:"+checkName)
}

func (s *Statement) legacyCheck(checkName string) bool {
	return slices.Contains(s.Labels, "check:"+checkName)
}

func (s *Statement) neededCheck() string {
	return strings.TrimPrefix(s.Labels[0], "check:")
}

// Evaluate evaluates the given results with respect to the given policy.
// checkName is an optional parameter used to generate results for only a particular check,
// and it's only used by the legacy code to evaluate a subset of statements.
// We can remove support for it when we drop support for legacy score computation.
func (p *Policy) Evaluate(findings []finding.Finding, checkName *string) (*Evaluation, error) {
	var results Evaluation
	for i := range p.Statements {
		statement := p.Statements[i]
		if checkName != nil && !statement.legacyCheck(*checkName) {
			continue
		}
		if statement.Require == nil {
			// TODO: validate in constructor.
			continue
		}
		o, logic, fds := evaluate(statement.Require, findings)
		e := EvaluatedStatement{
			Name:     statement.Name,
			Outcome:  o,
			Risk:     statement.Risk,
			Findings: fds,
			Labels:   statement.Labels,
			Logic:    logic,
		}
		if o < finding.OutcomePositive {
			e.Text = statement.NegativeText
		} else {
			e.Text = statement.PositiveText
		}
		if err := e.updateConfidence(statement.Confidence); err != nil {
			return nil, err
		}
		results = append(results, e)
	}
	return &results, nil
}

func (es *EvaluatedStatement) updateConfidence(os []finding.Outcome) error {
	switch es.Outcome {
	case finding.OutcomeError, finding.OutcomeNotAvailable,
		finding.OutcomeNotSupported:
		es.Confidence = ConfidenceHigh
	case finding.OutcomePositive, finding.OutcomeNegative:
		es.Confidence = ConfidenceLow
		if slices.Contains(os, es.Outcome) {
			es.Confidence = ConfidenceHigh
		}

	default:
		return fmt.Errorf("invalid confidence: %s")
	}
	return nil
}

func evaluate(clause *Clause, findings []finding.Finding) (finding.Outcome, Logic, []finding.Finding) {
	var pfds []finding.Finding
	var ofds []finding.Finding
	var outcome finding.Outcome
	var logic Logic
	switch {
	case clause.Probe != "":
		logic = LogicAnd
		o, fs := evaluateProbe(clause.Probe, findings)
		return o, logic, fs
	case clause.Or != nil:
		logic = LogicOr
		outcome = finding.OutcomeNegative
		for i := range clause.Or {
			c := clause.Or[i]
			co, _, cfs := evaluate(c, findings)
			// NOTE: any better outcome than negative, including not applicable, unknown, etc.
			// Only the negative and error should return an failure?
			// Set the text appropriately. Have a default text for not supported, na and error.
			if outcome < co {
				outcome = co
			}
			if co < finding.OutcomePositive {
				ofds = append(ofds, cfs...)
			} else {
				pfds = append(pfds, cfs...)
			}
		}
	case clause.And != nil:
		logic = LogicAnd
		outcome = finding.OutcomePositive
		for i := range clause.And {
			c := clause.And[i]
			co, _, cfs := evaluate(c, findings)
			// TODO: support other outcome, e.g. NotApplicable.
			// Only the negative and error should return an failure?
			// NOTE: any better outcome than negative, including not applicable, unknown, etc.
			if co < outcome {
				outcome = co
			}
			if co < finding.OutcomePositive {
				ofds = append(ofds, cfs...)
			} else {
				pfds = append(pfds, cfs...)
			}
		}
	case clause.Not != nil:
		panic("not")
	}
	if outcome < finding.OutcomePositive {
		return outcome, logic, append(pfds, ofds...)
	}
	return outcome, logic, pfds
}

func evaluateProbe(probeID string, findings []finding.Finding) (finding.Outcome, []finding.Finding) {
	var pfds []finding.Finding
	var ofds []finding.Finding
	o := finding.OutcomePositive
	for i := range findings {
		f := findings[i]
		if f.Probe != probeID {
			continue
		}
		if f.Outcome < o {
			o = f.Outcome
		}
		// We assume there are not duplicate entries, i.e., that
		// the same probe is not used multiple times in a Statement definition.
		if f.Outcome < finding.OutcomePositive {
			ofds = append(ofds, f)
		} else {
			pfds = append(pfds, f)
		}
	}
	if o < finding.OutcomePositive {
		return o, append(pfds, ofds...)
	}
	return o, pfds
}

func (p *Policy) validateRisks() error {
	for _, c := range p.Statements {
		if err := validateRisk(c.Risk); err != nil {
			return err
		}
	}
	return nil
}

func (p *Policy) validateConfidence() error {
	for _, c := range p.Statements {
		if len(c.Confidence) == 0 {
			return fmt.Errorf("confidence field not set")
		}
	}
	return nil
}

// UnmarshalYAML unmarshals the given Node into the Clause, ensuring that only
// one of its fields are set.
func (c *Clause) UnmarshalYAML(n *yaml.Node) error {
	type y Clause // Redefine type to lose the UnmarshalYAML method.
	var d y
	if err := n.Decode(&d); err != nil {
		return err
	}
	i := 0
	if d.Probe != "" {
		i++
	}
	if d.And != nil {
		i++
	}
	if d.Or != nil {
		i++
	}
	if d.Not != nil {
		i++
	}
	const clauses = "'probe', 'and', 'or', or 'not'"
	switch i {
	default:
		return fmt.Errorf("line %d: only one of %s may be specified", n.Line, clauses)
	case 0:
		return fmt.Errorf("line %d: one of %s clauses must be specified", n.Line, clauses)
	case 1:
		*c = Clause(d)
		return nil
	}
}

// UnmarshalYAML is a custom unmarshalling function
// to transform the string into an enum.
func (r *Risk) UnmarshalYAML(n *yaml.Node) error {
	var str string
	if err := n.Decode(&str); err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	switch n.Value {
	case "None":
		*r = RiskNone
	case "Low":
		*r = RiskLow
	case "High":
		*r = RiskHigh
	case "Medium":
		*r = RiskMedium
	case "Critical":
		*r = RiskCritical
	default:
		return fmt.Errorf("invalid risk: %q", str)
	}
	return nil
}

func validateRisk(r Risk) error {
	switch r {
	case RiskNone, RiskLow, RiskHigh, RiskMedium, RiskCritical:
		return nil
	default:
		return fmt.Errorf("invalid risk: %v", r)
	}
}

// String stringifies the enum.
func (r *Risk) String() string {
	switch *r {
	case RiskNone:
		return "None"
	case RiskLow:
		return "Low"
	case RiskHigh:
		return "High"
	case RiskMedium:
		return "Medium"
	case RiskCritical:
		return "Critical"
	default:
		return ""
	}
}
