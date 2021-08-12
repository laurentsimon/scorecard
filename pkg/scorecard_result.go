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
	"crypto/md5"
	"encoding/csv"
	"encoding/hex"
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

type text struct {
	Text string `json:"text,omitempty"`
}

//nolint
type region struct {
	StartLine   *int `json:"startLine,omitempty"`
	EndLine     *int `json:"endLine,omitempty"`
	StartColumn *int `json:"startColumn,omitempty"`
	EndColumn   *int `json:"endColumn,omitempty"`
	CharOffset  *int `json:"charOffset,omitempty"`
	ByteOffset  *int `json:"byteOffset,omitempty"`
	// Use pointer to omit the entire structure.
	Snippet *text `json:"snippet,omitempty"`
}

type artifactLocation struct {
	URI        string `json:"uri"`
	URIBasedID string `json:"uriBaseId,omitempty"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

//nolint
type relatedLocation struct {
	ID               int              `json:"id"`
	PhysicalLocation physicalLocation `json:"physicalLocation"`
	Message          text             `json:"message"`
}

type partialFingerprints map[string]string

type defaultConfig struct {
	// "none", "note", "warning", "error",
	// https://github.com/oasis-tcs/sarif-spec/blob/master/Schemata/sarif-schema-2.1.0.json#L1566.
	Level string `json:"level"`
}

type properties struct {
	Precision string   `json:"precision"`
	Tags      []string `json:"tags"`
}

type rule struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	HelpURI       string        `json:"helpUri"`
	ShortDesc     text          `json:"shortDescription"`
	FullDesc      text          `json:"fullDescription"`
	DefaultConfig defaultConfig `json:"defaultConfiguration"`
	Properties    properties    `json:"properties"`
}

type driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri"`
	SemVersion     string `json:"semanticVersion"`
	Rules          []rule `json:"rules"`
}

type tool struct {
	Driver driver `json:"driver"`
}

//nolint
type result struct {
	RuleID           string            `json:"ruleId"`
	Level            string            `json:"level"` // Optional.
	RuleIndex        int               `json:"ruleIndex"`
	Message          text              `json:"message"`
	Locations        []location        `json:"locations,omitempty"`
	RelatedLocations []relatedLocation `json:"relatedLocations,omitempty"`
	// Logical location: https://github.com/microsoft/sarif-tutorials/blob/main/docs/2-Basics.md#the-locations-array
	// https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html#_Toc16012457.
	// Not supported by GitHub, but possibly useful.
	PartialFingerprints partialFingerprints `json:"partialFingerprints,omitempty"`
}

type automationDetails struct {
	ID string `json:"id"`
}

type run struct {
	Tool              tool              `json:"tool"`
	AutomationDetails automationDetails `json:"automationDetails"`
	// For generated files during analysis. We leave this blank.
	Artifacts string   `json:"artifacts,omitempty"` // TODO: https://github.com/microsoft/sarif-tutorials/blob/main/docs/1-Introduction.md#simple-example
	Results   []result `json:"results"`
}

type sarif210 struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

func detailToRegion(details *checker.CheckDetail) region {
	var reg region
	switch details.Msg.Type {
	default:
		panic("invalid")
	case checker.FileTypeSource:
		reg = region{
			StartLine: &details.Msg.Offset,
		}
	case checker.FileTypeText:
		reg = region{
			CharOffset: &details.Msg.Offset,
		}
	case checker.FileTypeBinary:
		reg = region{
			ByteOffset: &details.Msg.Offset,
		}
	}
	return reg
}

func detailsToLocations(details []checker.CheckDetail) []location {
	locs := []location{}

	//nolint
	// Populate the locations.
	// Note https://docs.github.com/en/code-security/secure-coding/integrating-with-code-scanning/sarif-support-for-code-scanning#result-object
	// "Only the first value of this array is used. All other values are ignored."
	for _, d := range details {
		if d.Type != checker.DetailWarn {
			continue
		}

		if d.Msg.Path == "" {
			continue
		}
		loc := location{
			PhysicalLocation: physicalLocation{
				ArtifactLocation: artifactLocation{
					URI:        d.Msg.Path,
					URIBasedID: "SRCROOT",
				},
			},
		}

		// Set the region depending on file type.
		loc.PhysicalLocation.Region = detailToRegion(&d)
		locs = append(locs, loc)
	}

	// No details or not locations.
	// For GitHub to display results, we need to provide
	// a location anyway. TODO: experiment with value.
	detaultLine := 1
	if len(locs) == 0 {
		loc := location{
			PhysicalLocation: physicalLocation{
				ArtifactLocation: artifactLocation{
					URI:        "README.md",
					URIBasedID: "SRCROOT",
				},
				Region: region{
					StartLine: &detaultLine,
				},
			},
		}
		locs = append(locs, loc)
	}
	return locs
}

func detailsToRelatedLocations(details []checker.CheckDetail) []relatedLocation {
	rlocs := []relatedLocation{}

	//nolint
	// Populate the locations.
	// Note https://docs.github.com/en/code-security/secure-coding/integrating-with-code-scanning/sarif-support-for-code-scanning#result-object
	// "Only the first value of this array is used. All other values are ignored."
	for i, d := range details {
		if d.Msg.Type != checker.FileTypeURL ||
			d.Msg.Path == "" {
			continue
		}
		// TODO: related and logical
		rloc := relatedLocation{
			ID:      i,
			Message: text{Text: d.Msg.Text},
			PhysicalLocation: physicalLocation{
				ArtifactLocation: artifactLocation{
					URI: d.Msg.Path,
					// URIBasedID: "PROJECTROOT",
				},
			},
		}
		// Set the region depending on file type.
		rloc.PhysicalLocation.Region = detailToRegion(&d)
		rlocs = append(rlocs, rloc)
	}
	return rlocs
}

// This is too coarse.
func scoreToLevel(score int) string {
	switch score {
	default:
		return "warning"
	case checker.MaxResultScore:
		return "note"
	case checker.MinResultScore:
		return "error"
	}
}

// AsSARIF outputs ScorecardResult in SARIF 2.1.0 format.
func (r *ScorecardResult) AsSARIF(showDetails bool, logLevel zapcore.Level, writer io.Writer) error {
	//nolint
	// https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html.
	// We only support GitHub-supported properties:
	// see https://docs.github.com/en/code-security/secure-coding/integrating-with-code-scanning/sarif-support-for-code-scanning#supported-sarif-output-file-properties,
	// https://github.com/microsoft/sarif-tutorials.

	sarif := sarif210{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{
			run{
				Tool: tool{
					Driver: driver{
						Name:           "Scorecard",
						InformationURI: "https://github.com/ossf/scorecard",
						SemVersion:     "1.2.3",
						Rules:          make([]rule, 1),
					},
				},
				AutomationDetails: automationDetails{
					ID: fmt.Sprintf("%v/%v/%v", "security", "scorecard", "2021-02-01-13:54:12"),
				},
			},
		},
	}

	results := []result{}
	rules := []rule{}
	// nolint
	for i, check := range r.Checks {

		locs := detailsToLocations(check.Details2)
		rlocs := detailsToRelatedLocations(check.Details2)

		//nolint:gosec
		m := md5.Sum([]byte(check.Name))
		checkID := hex.EncodeToString(m[:])
		// logicalLocs:TODO
		// relatedLocs := []location{}

		// Unclear what to use for PartialFingerprints.
		// GitHub only uses `primaryLocationLineHash`, which is not properly defined
		// and Appendix B of https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html
		// warns about using line number for fingerprints:
		// "suppose the fingerprint were to include the line number where the result was located, and suppose
		// that after the baseline was constructed, a developer inserted additional lines of code above that
		// location. Then in the next run, the result would occur on a different line, the computed fingerprint
		// would change, and the result management system would erroneously report it as a new result."

		rule := rule{
			ID:   checkID,
			Name: check.Name,
			// TODO: read from yaml file.
			ShortDesc: text{Text: "short decs"},
			FullDesc:  text{Text: "long decs"},
			HelpURI:   fmt.Sprintf("https://github.com/ossf/scorecard/blob/main/docs/checks.md#%s", strings.ToLower(check.Name)),
			DefaultConfig: defaultConfig{
				Level: scoreToLevel(check.Score),
			},
			Properties: properties{
				Tags:      []string{"security", "scorecard", "slsa1", "gosspl:dependency:L1"},
				Precision: "very-high", // TODO: generate automatically, from yaml file?
			},
		}

		rules = append(rules, rule)

		if len(locs) == 0 {
		}

		r := result{
			RuleID: checkID,
			// https://github.com/microsoft/sarif-tutorials/blob/main/docs/2-Basics.md#level
			Level:            "error",
			RuleIndex:        i,
			Message:          text{Text: check.Reason},
			Locations:        locs,
			RelatedLocations: rlocs,
		}

		results = append(results, r)
	}

	// TODO: check for results
	sarif.Runs[0].Tool.Driver.Rules = rules
	sarif.Runs[0].Results = results

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "   ")
	if err := encoder.Encode(sarif); err != nil {
		panic(err.Error())
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
			details, show = detailsToString(row.Details2, logLevel)

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

func detailsToString(details []checker.CheckDetail, logLevel zapcore.Level) (string, bool) {
	// UPGRADEv2: change to make([]string, len(details))
	// followed by sa[i] = instead of append.
	//nolint
	var sa []string
	for _, v := range details {
		switch v.Msg.Version {
		case 3:
			if v.Type == checker.DetailDebug && logLevel != zapcore.DebugLevel {
				continue
			}
			if v.Msg.Path != "" {
				sa = append(sa, fmt.Sprintf("%s: %s: %s:%d", typeToString(v.Type), v.Msg.Text, v.Msg.Path, v.Msg.Offset))
			} else {
				sa = append(sa, fmt.Sprintf("%s: %s: %s", typeToString(v.Type), v.Msg.Text, v.Msg.Path))
			}
		default:
			if v.Type == checker.DetailDebug && logLevel != zapcore.DebugLevel {
				continue
			}
			sa = append(sa, fmt.Sprintf("%s: %s", typeToString(v.Type), v.Msg.Text))
		}
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
