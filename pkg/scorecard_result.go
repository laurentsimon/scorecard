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

package pkg

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/olekukonko/tablewriter"
	"go.uber.org/zap/zapcore"

	"github.com/ossf/scorecard/v2/checker"
	sce "github.com/ossf/scorecard/v2/errors"
)

// TODO: this file should go unnder a format/ folder.
// ScorecardResult struct is returned on a successful Scorecard run.
type ScorecardResult struct {
	Repo     string
	Date     string
	Checks   []checker.CheckResult
	Metadata []string
}

// AsJSON outputs the result in JSON format with a newline at the end.
// If called on []ScorecardResult will create NDJson formatted output.
func (r *ScorecardResult) AsJSON(showDetails bool, logLevel zapcore.Level, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	if showDetails {
		if err := encoder.Encode(r); err != nil {
			//nolint:wrapcheck
			return sce.Create(sce.ErrScorecardInternal, fmt.Sprintf("encoder.Encode: %v", err))
		}
		return nil
	}
	out := ScorecardResult{
		Repo:     r.Repo,
		Date:     r.Date,
		Metadata: r.Metadata,
	}
	// UPGRADEv2: remove nolint after uggrade.
	//nolint
	for _, checkResult := range r.Checks {
		tmpResult := checker.CheckResult{
			Name:       checkResult.Name,
			Pass:       checkResult.Pass,
			Confidence: checkResult.Confidence,
		}
		out.Checks = append(out.Checks, tmpResult)
	}
	if err := encoder.Encode(out); err != nil {
		//nolint:wrapcheck
		return sce.Create(sce.ErrScorecardInternal, fmt.Sprintf("encoder.Encode: %v", err))
	}
	return nil
}

// AsCSV outputs ScorecardResult in CSV format.
func (r *ScorecardResult) AsCSV(showDetails bool, logLevel zapcore.Level, writer io.Writer) error {
	w := csv.NewWriter(writer)
	record := []string{r.Repo}
	columns := []string{"Repository"}
	// UPGRADEv2: remove nolint after uggrade.
	//nolint
	for _, checkResult := range r.Checks {
		columns = append(columns, checkResult.Name+"_Pass", checkResult.Name+"_Confidence")
		record = append(record, strconv.FormatBool(checkResult.Pass),
			strconv.Itoa(checkResult.Confidence))
		if showDetails {
			columns = append(columns, checkResult.Name+"_Details")
			record = append(record, checkResult.Details...)
		}
	}
	fmt.Fprintf(writer, "%s\n", strings.Join(columns, ","))
	if err := w.Write(record); err != nil {
		//nolint:wrapcheck
		return sce.Create(sce.ErrScorecardInternal, fmt.Sprintf("csv.Write: %v", err))
	}
	w.Flush()
	if err := w.Error(); err != nil {
		//nolint:wrapcheck
		return sce.Create(sce.ErrScorecardInternal, fmt.Sprintf("csv.Flush: %v", err))
	}
	return nil
}

// AsSARIF outputs ScorecardResult in SARIF 2.1.0 format.
func (r *ScorecardResult) AsSARIF(showDetails bool, logLevel zapcore.Level, writer io.Writer) error {
	//nolint
	// https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html.
	// We only support GitHub-supported properties:
	// see https://docs.github.com/en/code-security/secure-coding/integrating-with-code-scanning/sarif-support-for-code-scanning#supported-sarif-output-file-properties,
	// https://github.com/microsoft/sarif-tutorials.
	type text struct {
		Text string `json:"text"`
	}

	type region struct {
		StartLine   int `json:"startLine"`
		EndLine     int `json:"endLine,omitempty"`
		StartColumn int `json:"startColumn,omitempty"`
		EndColumn   int `json:"endColumn,omitempty"`
	}

	type location struct {
		PhysicalLocation struct {
			ArtifactLoction struct {
				URI        string `json:"uri"`
				URIBasedID string `json:"uriBaseId"`
				Region     region `json:"region"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
		// Logical location: https://github.com/microsoft/sarif-tutorials/blob/main/docs/2-Basics.md#the-locations-array
		// https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html#_Toc16012457.
		// Not supported by GitHub, but possibly useful.
	}

	type partialFingerprints map[string]string

	type defaultConfig struct {
		Level string `json:"level"`
	}

	type properties struct {
		Tags      []string `json:"tags"`
		Precision string   `json:"precision"`
	}
	type rule struct {
		ID            string        `json:"id"`
		Name          string        `json:"name"`
		HelpUri       string        `yaml:"helpUri"`
		ShortDesc     text          `json:"shortDescription"`
		FullDesc      text          `json:"fullDescription"`
		DefaultConfig defaultConfig `json:"defaultConfiguration"`
		Properties    properties    `json:"properties"`
	}

	type driver struct {
		Name           string `json:"name"`
		InformationUri string `yaml:"informationUri"`
		SemVersion     string `json:"semanticVersion"`
		Rules          []rule `json:"rules"`
	}

	type tool struct {
		Driver driver `json:"driver"`
	}

	type result struct {
		RuleID              string              `json:"ruleId"`
		Level               string              `json:"level"` // Optional.
		RuleIndex           int                 `json:"ruleIndex"`
		Message             text                `json:"message"`
		Locations           []location          `json:"locations"`
		RelatedLocations    []location          `json:"relatedLocations"`
		PartialFingerprints partialFingerprints `json:"partialFingerprints"`
	}
	type run struct {
		Tool              tool `json:"tool"`
		AutomationDetails struct {
			ID string `json:"id"`
		} `json:"automationDetails"`
		Artifacts string `yaml:"artifacts"` // TODO: https://github.com/microsoft/sarif-tutorials/blob/main/docs/1-Introduction.md#simple-example
		Results   []result
	}

	type sarif210 struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []run  `json:"runs"`
	}

	sarif := sarif210{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{
			run{
				Tool: tool{
					Driver: driver{
						Name:           "Scorecard",
						InformationUri: "our url on github",
						SemVersion:     "1.2.3",
						Rules:          make([]rule, 0),
					},
				},
			},
		},
	}

	for i, check := range r.Checks {
		rule := rule{
			ID:        "abcdefghi", // TODO: md5(check.Name),
			Name:      check.Name,
			ShortDesc: text{Text: "short decs"},
			FullDesc:  text{Text: "long decs"},
			HelpUri:   "our url to the check",
			DefaultConfig: defaultConfig{
				Level: "high-risk", // TODO: auto-generate frm yaml file
			},
			Properties: properties{
				Tags:      []string{"security", "scorecard", "slsa1"},
				Precision: "very-high", // TODO: generate automatically, from yaml file?
			},
		}
		r := result{
			RuleID: "abcdefghi",
			// https://github.com/microsoft/sarif-tutorials/blob/main/docs/2-Basics.md#level
			Level:     "warning",
			RuleIndex: i,
			Message:   text{Text: check.Reason},
		}
		// TODO: ierate over details
		locs := []location{
			PhysicalLocation: {},
		}

		// PhysicalLocation struct {
		// 	ArtifactLocation struct {
		// 		URI        string `json:"uri"`
		// 		URIBasedID string `json:"uriBaseId"`
		// 		Region     region `json:"region"`
		// 	} `json:"artifactLocation"`
		// } `json:"physicalLocation"`
		/*
			RuleID              string              `json:"ruleId"`
			Level               string              `json:"level"` // Optional.
			RuleIndex           int                 `json:"ruleIndex"`
			Message             text                `json:"message"`
			Locations           []location          `json:"locations"`
			RelatedLocations    []location          `json:"relatedLocations"`
			PartialFingerprints partialFingerprints `json:"partialFingerprints"`
		*/
	}

	return nil
}

// AsHTML outputs ScorecardResult in HTML format.
func (r *ScorecardResult) AsHTML(showDetails bool, logLevel zapcore.Level, writer io.Writer) error {
	return nil
}

// AsString returns ScorecardResult in string format.
func (r *ScorecardResult) AsString(showDetails bool, logLevel zapcore.Level, writer io.Writer) error {
	data := make([][]string, len(r.Checks))
	//nolint
	for i, row := range r.Checks {
		const withdetails = 5
		const withoutdetails = 4
		var x []string

		if showDetails {
			x = make([]string, withdetails)
		} else {
			x = make([]string, withoutdetails)
		}

		// UPGRADEv2: rename variable.
		if row.Score == checker.InconclusiveResultScore {
			x[0] = "?"
		} else {
			x[0] = fmt.Sprintf("%d", row.Score)
		}

		doc := fmt.Sprintf("github.com/ossf/scorecard/blob/main/docs/checks.md#%s", strings.ToLower(row.Name))
		x[1] = row.Reason
		x[2] = row.Name
		if showDetails {
			// UPGRADEv3: remove.
			var details string
			var show bool
			if len(row.Details3) > 0 {
				details, show = detailsToString3(row.Details3, logLevel)
			} else {
				details, show = detailsToString(row.Details2, logLevel)
			}

			if show {
				x[3] = details
			}
			x[4] = doc
		} else {
			x[3] = doc
		}

		data[i] = x
	}

	table := tablewriter.NewWriter(os.Stdout)
	header := []string{"Score", "Reason", "Name"}
	if showDetails {
		header = append(header, "Details")
	}
	header = append(header, "Documentation/Remediation")
	table.SetHeader(header)
	table.SetBorders(tablewriter.Border{Left: true, Top: true, Right: true, Bottom: true})
	table.SetRowSeparator("-")
	table.SetRowLine(true)
	table.SetCenterSeparator("|")
	table.AppendBulk(data)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetRowLine(true)
	table.Render()

	return nil
}

// UPGRADEv3: rename.
func detailsToString3(details []checker.CheckDetail3, logLevel zapcore.Level) (string, bool) {
	var sa []string
	for _, v := range details {
		if v.Type == checker.DetailDebug && logLevel != zapcore.DebugLevel {
			continue
		}
		switch {
		case v.Line != -1:
			sa = append(sa, fmt.Sprintf("%s: %s: %s:%d", typeToString(v.Type), v.Msg, v.Path, v.Line))
		default:
			if v.Path == "" {
				panic("fix it")
			}
			sa = append(sa, fmt.Sprintf("%s: %s: %s", typeToString(v.Type), v.Msg, v.Path))
		}
	}
	return strings.Join(sa, "\n"), len(sa) > 0
}

func detailsToString(details []checker.CheckDetail, logLevel zapcore.Level) (string, bool) {
	// UPGRADEv2: change to make([]string, len(details))
	// followed by sa[i] = instead of append.
	//nolint
	var sa []string
	for _, v := range details {
		if v.Type == checker.DetailDebug && logLevel != zapcore.DebugLevel {
			continue
		}
		sa = append(sa, fmt.Sprintf("%s: %s", typeToString(v.Type), v.Msg))
	}
	return strings.Join(sa, "\n"), len(sa) > 0
}

func typeToString(cd checker.DetailType) string {
	switch cd {
	default:
		panic("invalid detail")
	case checker.DetailInfo:
		return "Info"
	case checker.DetailWarn:
		return "Warn"
	case checker.DetailDebug:
		return "Debug"
	}
}
