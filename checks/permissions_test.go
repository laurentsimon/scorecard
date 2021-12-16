// Copyright 2021 Security Scorecard Authors
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

package checks

import (
	"fmt"
	"os"
	"testing"

	"github.com/ossf/scorecard/v3/checker"
	scut "github.com/ossf/scorecard/v3/utests"
)

//nolint
func TestGithubTokenPermissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		filenames []string
		expected  scut.TestReturn
	}{
		{
			name:      "run workflow codeql write test",
			filenames: []string{"./testdata/github-workflow-permissions-run-codeql-write.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  1,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "run workflow no codeql write test",
			filenames: []string{"./testdata/github-workflow-permissions-run-no-codeql-write.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore - 1,
				NumberOfWarn:  1,
				NumberOfInfo:  1,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "run workflow write test",
			filenames: []string{"./testdata/github-workflow-permissions-run-writes-2.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  3,
				NumberOfInfo:  2,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "run package workflow write test",
			filenames: []string{"./testdata/github-workflow-permissions-run-package-workflow-write.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  3,
				NumberOfDebug: 3,
			},
		},
		{
			name:      "run package write test",
			filenames: []string{"./testdata/github-workflow-permissions-run-package-write.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  1,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "run writes test",
			filenames: []string{"./testdata/github-workflow-permissions-run-writes.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  1,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "write all test",
			filenames: []string{"./testdata/github-workflow-permissions-writeall.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  0,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "read all test",
			filenames: []string{"./testdata/github-workflow-permissions-readall.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  1,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "no permission test",
			filenames: []string{"./testdata/github-workflow-permissions-absent.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  0,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "writes test",
			filenames: []string{"./testdata/github-workflow-permissions-writes.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  1,
				NumberOfDebug: 6,
			},
		},
		{
			name:      "reads test",
			filenames: []string{"./testdata/github-workflow-permissions-reads.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  10,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "nones test",
			filenames: []string{"./testdata/github-workflow-permissions-nones.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  10,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "none test",
			filenames: []string{"./testdata/github-workflow-permissions-none.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  1,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "status/checks write",
			filenames: []string{"./testdata/github-workflow-permissions-status-checks.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore - 1,
				NumberOfWarn:  2,
				NumberOfInfo:  2,
				NumberOfDebug: 6,
			},
		},
		{
			name:      "sec-events/deployments write",
			filenames: []string{"./testdata/github-workflow-permissions-secevent-deployments.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore - 2,
				NumberOfWarn:  2,
				NumberOfInfo:  3,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "contents write",
			filenames: []string{"./testdata/github-workflow-permissions-contents.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  2,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "actions write",
			filenames: []string{"./testdata/github-workflow-permissions-actions.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  2,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "packages write",
			filenames: []string{"./testdata/github-workflow-permissions-packages.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MinResultScore,
				NumberOfWarn:  1,
				NumberOfInfo:  1,
				NumberOfDebug: 5,
			},
		},
		{
			name:      "Non-yaml file",
			filenames: []string{"./testdata/script.sh"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  0,
				NumberOfDebug: 0,
			},
		},
		{
			name:      "release workflow write",
			filenames: []string{"./testdata/github-workflow-permissions-release-writes.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  3,
				NumberOfDebug: 3,
			},
		},
		{
			name:      "package workflow write",
			filenames: []string{"./testdata/github-workflow-permissions-packages-writes.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore,
				NumberOfWarn:  0,
				NumberOfInfo:  3,
				NumberOfDebug: 3,
			},
		},
		{
			name:      "workflow jobs only",
			filenames: []string{"./testdata/github-workflow-permissions-jobs-only.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         9,
				NumberOfWarn:  1,
				NumberOfInfo:  3,
				NumberOfDebug: 4,
			},
		},
		{
			name:      "security-events write, codeql comment",
			filenames: []string{"./testdata/github-workflow-permissions-run-write-codeql-comment.yaml"},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore - 1,
				NumberOfWarn:  1,
				NumberOfInfo:  1,
				NumberOfDebug: 4,
			},
		},
		{
			name: "two files mix run-level and top-level",
			filenames: []string{
				"./testdata/github-workflow-permissions-top-level-only.yaml",
				"./testdata/github-workflow-permissions-run-level-only.yaml",
			},
			expected: scut.TestReturn{
				Error:         nil,
				Score:         checker.MaxResultScore - 1,
				NumberOfWarn:  1,
				NumberOfInfo:  2,
				NumberOfDebug: 9,
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var files []struct {
				pathfn  string
				content []byte
			}
			var content []byte
			var err error
			for _, fn := range tt.filenames {
				if fn == "" {
					content = make([]byte, 0)
				} else {
					content, err = os.ReadFile(fn)
					if err != nil {
						panic(fmt.Errorf("cannot read file: %w", err))
					}
				}
				files = append(files, struct {
					pathfn  string
					content []byte
				}{pathfn: fn, content: content})
			}

			dl := scut.TestDetailLogger{}
			r := testValidateGitHubActionTokenPermissions(files, &dl)
			if !scut.ValidateTestReturn(t, tt.name, &tt.expected, &r, &dl) {
				t.Fail()
			}
		})
	}
}

func TestGithubTokenPermissionsLineNumber(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		filename string
		expected []struct {
			lineNumber int
		}
	}{
		{
			name:     "Job level write permission",
			filename: "./testdata/github-workflow-permissions-run-no-codeql-write.yaml",
			expected: []struct {
				lineNumber int
			}{
				{
					lineNumber: 22,
				},
			},
		},
		{
			name:     "Workflow level write permission",
			filename: "./testdata/github-workflow-permissions-writeall.yaml",
			expected: []struct {
				lineNumber int
			}{
				{
					lineNumber: 16,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			content, err := os.ReadFile(tt.filename)
			if err != nil {
				t.Errorf("cannot read file: %v", err)
			}
			dl := scut.TestDetailLogger{}
			files := []struct {
				pathfn  string
				content []byte
			}{{pathfn: tt.filename, content: content}}
			testValidateGitHubActionTokenPermissions(files, &dl)
			for _, expectedLog := range tt.expected {
				isExpectedLog := func(logMessage checker.LogMessage, logType checker.DetailType) bool {
					return logMessage.Offset == expectedLog.lineNumber && logMessage.Path == tt.filename &&
						logType == checker.DetailWarn
				}
				if !scut.ValidateLogMessage(isExpectedLog, &dl) {
					t.Errorf("test failed: log message not present: %+v", tt.expected)
				}
			}
		})
	}
}
