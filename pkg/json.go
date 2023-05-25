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

package pkg

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	docs "github.com/ossf/scorecard/v4/docs/checks"
	sce "github.com/ossf/scorecard/v4/errors"
	"github.com/ossf/scorecard/v4/evaluation"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/log"
)

// nolint: govet
type jsonCheckResult struct {
	Name       string
	Details    []string
	Confidence int
	Pass       bool
}

type jsonScorecardResult struct {
	Repo     string
	Date     string
	Checks   []jsonCheckResult
	Metadata []string
}

type jsonCheckDocumentationV2 struct {
	URL   string `json:"url"`
	Short string `json:"short"`
	// Can be extended if needed.
}

// nolint: govet
type jsonCheckResultV2 struct {
	Details []string                 `json:"details"`
	Score   int                      `json:"score"`
	Reason  string                   `json:"reason"`
	Name    string                   `json:"name"`
	Doc     jsonCheckDocumentationV2 `json:"documentation"`
}

type jsonRepoV2 struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
}

type jsonScorecardV2 struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type jsonFloatScore float64

func (s jsonFloatScore) MarshalJSON() ([]byte, error) {
	// Note: for integers, this will show as X.0.
	return []byte(fmt.Sprintf("%.1f", s)), nil
}

// JSONScorecardResultV2 exports results as JSON for new detail format.
//
//nolint:govet
type JSONScorecardResultV2 struct {
	Date           string              `json:"date"`
	Repo           jsonRepoV2          `json:"repo"`
	Scorecard      jsonScorecardV2     `json:"scorecard"`
	AggregateScore jsonFloatScore      `json:"score"`
	Checks         []jsonCheckResultV2 `json:"checks"`
	Metadata       []string            `json:"metadata"`
}

// nolint: govet
type jsonCheckResultV3 struct {
	// Findings   []finding.AnonymousFinding `json:"details"`
	Findings   []finding.Finding        `json:"details"`
	Confidence evaluation.Confidence    `json:"confidence"`
	Score      int                      `json:"score"`
	Reason     string                   `json:"reason"`
	Name       string                   `json:"name"`
	Doc        jsonCheckDocumentationV3 `json:"documentation"`
}

// jsonCheckDocumentationV3 exports results as JSON for new detail format.
//
//nolint:govet
type jsonCheckDocumentationV3 struct {
	URL   string          `json:"url"`
	Short string          `json:"short"`
	Risk  evaluation.Risk `json:"risk"`
	// Can be extended if needed.
}

// JSONScorecardResultV3 exports results as JSON for structured detail format.
//
//nolint:govet
type JSONScorecardResultV3 struct {
	Date           string              `json:"date"`
	Repo           jsonRepoV2          `json:"repo"`
	Scorecard      jsonScorecardV2     `json:"scorecard"`
	AggregateScore jsonFloatScore      `json:"score"`
	Checks         []jsonCheckResultV3 `json:"checks"`
	Metadata       []string            `json:"metadata"`
}

// AsJSON exports results as JSON for new detail format.
func (r *ScorecardResult) AsJSON(showDetails bool, logLevel log.Level, writer io.Writer) error {
	encoder := json.NewEncoder(writer)

	out := jsonScorecardResult{
		Repo:     r.Repo.Name,
		Date:     r.Date.Format("2006-01-02"),
		Metadata: r.Metadata,
	}

	for _, checkResult := range r.Checks {
		tmpResult := jsonCheckResult{
			Name: checkResult.Name,
		}
		if showDetails {
			for i := range checkResult.Details {
				d := checkResult.Details[i]
				m := DetailToString(&d, logLevel)
				if m == "" {
					continue
				}
				tmpResult.Details = append(tmpResult.Details, m)
			}
		}
		out.Checks = append(out.Checks, tmpResult)
	}
	if err := encoder.Encode(out); err != nil {
		return sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("encoder.Encode: %v", err))
	}
	return nil
}

// AsJSON2 exports results as JSON for new detail format.
func (r *ScorecardResult) AsJSON2(showDetails bool,
	logLevel log.Level, checkDocs docs.Doc, writer io.Writer,
) error {
	score, err := r.GetAggregateScore(checkDocs)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(writer)
	out := JSONScorecardResultV2{
		Repo: jsonRepoV2{
			Name:   r.Repo.Name,
			Commit: r.Repo.CommitSHA,
		},
		Scorecard: jsonScorecardV2{
			Version: r.Scorecard.Version,
			Commit:  r.Scorecard.CommitSHA,
		},
		Date:           r.Date.Format(time.RFC3339),
		Metadata:       r.Metadata,
		AggregateScore: jsonFloatScore(score),
	}

	for _, checkResult := range r.Checks {
		doc, e := checkDocs.GetCheck(checkResult.Name)
		if e != nil {
			return sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("GetCheck: %s: %v", checkResult.Name, e))
		}

		tmpResult := jsonCheckResultV2{
			Name: checkResult.Name,
			Doc: jsonCheckDocumentationV2{
				URL:   doc.GetDocumentationURL(r.Scorecard.CommitSHA),
				Short: doc.GetShort(),
			},
			Reason: checkResult.Reason,
			Score:  checkResult.Score,
		}
		if showDetails {
			for i := range checkResult.Details {
				d := checkResult.Details[i]
				m := DetailToString(&d, logLevel)
				if m == "" {
					continue
				}
				tmpResult.Details = append(tmpResult.Details, m)
			}
		}
		out.Checks = append(out.Checks, tmpResult)
	}

	if err := encoder.Encode(out); err != nil {
		return sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("encoder.Encode: %v", err))
	}

	return nil
}

func (r *ScorecardResult) AsFJSON(showDetails bool,
	logLevel log.Level, checkDocs docs.Doc, writer io.Writer,
) error {
	score, err := r.GetAggregateScore(checkDocs)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(writer)
	out := JSONScorecardResultV3{
		// TODO: for users to be able to retrieve probe results via
		// REST API and apply a check definition file, metadata will need to
		// be recorded.
		Repo: jsonRepoV2{
			Name:   r.Repo.Name,
			Commit: r.Repo.CommitSHA,
		},
		Scorecard: jsonScorecardV2{
			Version: r.Scorecard.Version,
			Commit:  r.Scorecard.CommitSHA,
		},
		Date:           r.Date.Format("2006-01-02"),
		Metadata:       r.Metadata,
		AggregateScore: jsonFloatScore(score),
	}

	// TODO: filter the check that are enabled.
	for _, checkResult := range r.Checks {
		doc, e := checkDocs.GetCheck(checkResult.Name)
		if e != nil {
			return sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("GetCheck: %s: %v", checkResult.Name, e))
		}

		tmpResult := jsonCheckResultV3{
			Name: checkResult.Name,
			Doc: jsonCheckDocumentationV3{
				URL:   doc.GetDocumentationURL(r.Scorecard.CommitSHA),
				Short: doc.GetShort(),
				Risk:  evaluation.RiskNone,
			},
			Reason:     checkResult.Reason,
			Score:      checkResult.Score,
			Confidence: evaluation.ConfidenceHigh,
		}

		if showDetails {
			// Use the structuredResults field
			// to access the risk and the confidence.

			foundCheck := false
			for i := range r.StructuredResults {
				statement := r.StructuredResults[i]
				// Is the statement for for this check.
				if !statement.LegacyCheck(checkResult.Name) {
					continue
				}
				foundCheck = true

				// Update the outcome, risk and confidence
				// based on each statement related to the check.
				if tmpResult.Doc.Risk < statement.Risk {
					tmpResult.Doc.Risk = statement.Risk
				}
				if tmpResult.Confidence > statement.Confidence {
					tmpResult.Confidence = statement.Confidence
				}
				for j := range statement.Findings {
					f := statement.Findings[j]
					// tmpResult.Findings = append(tmpResult.Findings, *f.Anonimize())
					tmpResult.Findings = append(tmpResult.Findings, f)
				}
			}
			if !foundCheck {
				return sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("cannot find results for check: %s", checkResult.Name))
			}

			// Sanity check that the risk in the main check documentation is the same
			// as the one on the check configuration file.
			if doc.GetRisk() != tmpResult.Doc.Risk.String() {
				return sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("risk mismatch: '%v' != '%v'",
					doc.GetRisk(), tmpResult.Doc.Risk.String()))
			}
		}

		out.Checks = append(out.Checks, tmpResult)
	}
	if err := encoder.Encode(out); err != nil {
		return sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("encoder.Encode: %v", err))
	}

	return nil
}
