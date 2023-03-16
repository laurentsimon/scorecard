package evaluation

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/ossf/scorecard/v4/finding"
)

func Test_PolicyFromFile(t *testing.T) {
	t.Parallel()
	// nolint:govet
	tests := []struct {
		name   string
		path   string
		policy Policy
		err    error
	}{
		{
			name: "nested",
			path: "testdata/nested.yml",
			policy: Policy{
				Version: 1,
				Statements: []Statement{
					{
						Name:         "NestedStatement",
						NegativeText: "fail",
						PositiveText: "pass",
						Risk:         RiskCritical,
						Labels:       []string{"label1", "label2"},
						Confidence: []finding.Outcome{
							finding.OutcomeNegative, finding.OutcomePositive,
						},
						Require: &Clause{
							And: []*Clause{
								{Probe: "Probe1"},
								{Probe: "Probe2"},
								{
									Or: []*Clause{
										{Probe: "Nested1"},
										{Probe: "Nested2"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "risk high",
			path: "testdata/policy.yml",
			policy: Policy{
				Version: 1,
				Statements: []Statement{
					{
						Name:         "Fuzzing",
						NegativeText: "Configure one of the recognized fuzzers.",
						PositiveText: "The project is fuzzed using one the fuzzers.",
						Risk:         RiskLow,
						Confidence: []finding.Outcome{
							finding.OutcomePositive,
						},
						Labels: []string{"label1", "label2"},
						Require: &Clause{
							Or: []*Clause{
								{Probe: "FuzzedWithCIFuzz"},
								{Probe: "FuzzedWithClusterFuzzLite"},
								{Probe: "FuzzedWithGoNative"},
								{Probe: "FuzzedWithOSSFuzz"},
							},
						},
					},
					{
						Name:         "BinaryOtherNotPresent",
						NegativeText: "Remove binary artifacts.",
						PositiveText: "No binaries present.",
						Risk:         RiskHigh,
						Confidence: []finding.Outcome{
							finding.OutcomeNegative,
						},
						Labels: []string{"BinaryArtifacts"},
						Require: &Clause{
							Probe: "BinaryOtherNotPresent",
						},
					},
					{
						Name:         "GradleBinaryArtifacts",
						NegativeText: "Remove the binary (BinaryGradleNotPresent) or install the Action (BinaryGradleWrapperAction).",
						PositiveText: "Gradle binaries not present or handled safely.",
						Risk:         RiskHigh,
						Confidence: []finding.Outcome{
							finding.OutcomeNegative, finding.OutcomePositive,
						},
						Labels: []string{"BinaryArtifacts"},
						Require: &Clause{
							And: []*Clause{
								{Probe: "BinaryGradleNotPresent"},
								{Probe: "BinaryGradleWrapperAction"},
							},
						},
					},
					{
						Name:         "MavenBinaryNoArtifacts",
						NegativeText: "Remove the binary (BinaryMavenNotPresent) or install the Action (BinaryMavenWrapperAction).",
						PositiveText: "Maven binaries not present or handled safely.",
						Risk:         RiskHigh,
						Confidence: []finding.Outcome{
							finding.OutcomePositive,
						},
						Labels: []string{"BinaryArtifacts"},
						Require: &Clause{
							And: []*Clause{
								{Probe: "BinaryMavenNotPresent"},
								{Probe: "BinaryMavenWrapperAction"},
							},
						},
					},
					{
						Name:         "BranchProtectionMinimal",
						NegativeText: "Enable all the settings according to the steps definned in BranchProtectionNoForcePushDisabled and BranchProtectionStatusEnabled.",
						PositiveText: "Branch protection settings all configured.",
						Risk:         RiskHigh,
						Confidence: []finding.Outcome{
							finding.OutcomeNegative,
						},
						Labels: []string{"BranchProtection"},
						Require: &Clause{
							And: []*Clause{
								{Probe: "BranchProtectionNoForcePushDisabled"},
								{Probe: "BranchProtectionStatusEnabled"},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("read policy file: %w", err))
			}
			p, err := PolicyFromBytes(content)
			if err != nil || tt.err != nil {
				if !cmp.Equal(err, tt.err, cmpopts.EquateErrors()) {
					t.Fatalf("unexpected error: %v", cmp.Diff(err, tt.err, cmpopts.EquateErrors()))
				}
				return
			}

			if diff := cmp.Diff(tt.policy, *p); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
