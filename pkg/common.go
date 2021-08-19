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

package pkg

import (
	"fmt"
	"strings"

	"github.com/ossf/scorecard/v2/checker"
	"go.uber.org/zap/zapcore"
)

// TODO: Verify this works in GitHub's dashboard.
func textToHTML(s string) string {
	return strings.ReplaceAll(s, "\n", "<br>")
}

func textToMarkdown(s string) string {
	return textToHTML(s)
}

func detailsToString(details []checker.CheckDetail, logLevel zapcore.Level) (string, bool) {
	// UPGRADEv2: change to make([]string, len(details))
	// followed by sa[i] = instead of append.
	var sa []string
	for _, v := range details {
		switch v.Msg.Version {
		//nolint
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
