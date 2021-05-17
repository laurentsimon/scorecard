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

package checks

import (
	"bufio"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/checker"
	"gopkg.in/yaml.v2"
)

const frozenDepsStr = "Frozen-Deps"

func init() {
	registerCheck(frozenDepsStr, FrozenDeps)
}

// FrozenDeps will check the repository if it contains frozen dependecies.
func FrozenDeps(c *checker.CheckRequest) checker.CheckResult {
	return checker.MultiCheckAnd(
		isPackageManagerLockFilePresent,
		isGitHubActionsWorkflowPinned,
		isDockerfilePinned,
	)(c)
}

// TODO(laurent): need to support GCB

// ============================================================
// ======================== Dockerfiles =======================
// ============================================================
func isDockerfilePinned(c *checker.CheckRequest) checker.CheckResult {
	return CheckFilesContent(frozenDepsStr, "*Dockerfile*", false, c, validateDockerfile)
}

func validateDockerfile(path string, content []byte,
	logf func(s string, f ...interface{})) (bool, error) {
	// Users may use various names, e.g.,
	// Dockerfile.aarch64, Dockerfile.template, Dockerfile_template, dockerfile, Dockerfile-name.template
	// Templates may trigger false positives, e.g. FROM { NAME }.

	// We have what looks like a docker file.
	// Let's interpret the content as utf8-encoded strings.
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	hashRegex := regexp.MustCompile(`^FROM\s+.*@sha256:[a-f\d]{64}`)

	// Read the file line by line.
	scanner.Split(bufio.ScanLines)
	r := true
	nl := 0
	for scanner.Scan() {
		line := scanner.Text()
		// Only look at lines starting with FROM.
		if !strings.HasPrefix(line, "FROM ") {
			continue
		}

		nl += 1
		match, err := hashRegex.Match([]byte(line))
		if err != nil {
			return false, err
		}
		if !match {
			r = false
			logf("!! frozen-deps - %v has non-pinned dependency '%v'", path, line)
		}
	}

	// The file should have at least one FROM statement.
	if nl == 0 {
		return false, errors.New("file has no FROM keyword")
	}

	return r, nil
}

// ============================================================
// ===================== Github workflows =====================
// ============================================================

// Check pinning of github actions in workflows.
func isGitHubActionsWorkflowPinned(c *checker.CheckRequest) checker.CheckResult {
	return CheckFilesContent(frozenDepsStr, ".github/workflows/*", true, c, validateGitHubActionWorkflow)
}

// Check file content
func validateGitHubActionWorkflow(path string, content []byte,
	logf func(s string, f ...interface{})) (bool, error) {

	// Structure for workflow config.
	// We only retrieve what we need for logging.
	// Github workflows format: https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions
	type GitHubActionWorkflowConfig struct {
		Name string `yaml:name`
		Jobs map[string]struct {
			Name  string `yaml:name`
			Steps []struct {
				Name string `yaml:name`
				Id   string `yaml:id`
				Uses string `yaml:uses`
			}
		}
	}

	if len(content) == 0 {
		return false, errors.New("file has no content")
	}

	var workflow GitHubActionWorkflowConfig
	err := yaml.Unmarshal(content, &workflow)
	if err != nil {
		return false, fmt.Errorf("!! frozen-deps - cannot unmarshal file %v\n%v\n%v: %w", path, content, string(content), err)
	}

	hashRegex := regexp.MustCompile(`^.*@[a-f\d]{40,}`)
	r := true
	for jobName, job := range workflow.Jobs {
		if len(job.Name) > 0 {
			jobName = job.Name
		}
		for _, step := range job.Steps {
			if len(step.Uses) > 0 {
				// Ensure a hash at least as large as SHA1 is used (40 hex characters).
				// Example: action-name@hash
				match := hashRegex.Match([]byte(step.Uses))
				if err != nil {
					return false, err
				}
				if !match {
					r = false
					logf("!! frozen-deps - %v has non-pinned dependency '%v' (job \"%v\")", path, step.Uses, jobName)
				}
			}
		}

	}

	return r, nil
}

// ============================================================
// ================== Package manager lock files ==============
// ============================================================

// Check presence of lock files thru validatePackageManagerFile().
func isPackageManagerLockFilePresent(c *checker.CheckRequest) checker.CheckResult {
	return CheckIfFileExists(frozenDepsStr, c, validatePackageManagerFile)
}

// validatePackageManagerFile will validate the if frozen dependecies file name exists.
// TODO(laurent): need to differentiate between libraries and programs.
// TODO(laurent): handle multi-language repos
func validatePackageManagerFile(name string, logf func(s string, f ...interface{})) (bool, error) {
	switch strings.ToLower(name) {
	case "go.mod", "go.sum":
		logf("go modules found: %s", name)
		return true, nil
	case "vendor/", "third_party/", "third-party/":
		logf("vendor dir found: %s", name)
		return true, nil
	case "package-lock.json", "npm-shrinkwrap.json":
		logf("nodejs packages found: %s", name)
		return true, nil
	// TODO(laurent): add check for hashbased pinning in requirements.txt - https://davidwalsh.name/hashin
	case "requirements.txt", "pipfile.lock":
		logf("python requirements found: %s", name)
		return true, nil
	case "gemfile.lock":
		logf("ruby gems found: %s", name)
		return true, nil
	case "cargo.lock":
		logf("rust crates found: %s", name)
		return true, nil
	case "yarn.lock":
		logf("yarn packages found: %s", name)
		return true, nil
	case "composer.lock":
		logf("composer packages found: %s", name)
		return true, nil
	default:
		return false, nil
	}
}
