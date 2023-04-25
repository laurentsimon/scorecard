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

package toolRenovateInstalled

import (
	"embed"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/ruledefs/utils"
)

//go:embed *.yml
var fs embed.FS

func matches(tool checker.Tool) bool {
	return tool.Name == "RenovateBot"
}

func Run(raw *checker.RawResults) ([]finding.Finding, error) {
	tools := raw.DependencyUpdateToolResults.Tools
	return utils.ToolsRun(tools, fs, "toolRenovateInstalled",
		finding.OutcomePositive, finding.OutcomeNegative, matches)
}
