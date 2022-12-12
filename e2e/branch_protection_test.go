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

package e2e

import (
	"context"
	"os"

	"github.com/go-git/go-git/v5"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/checks"
	"github.com/ossf/scorecard/v4/clients"
	"github.com/ossf/scorecard/v4/clients/githubrepo"
	"github.com/ossf/scorecard/v4/clients/localdir"
	scut "github.com/ossf/scorecard/v4/utests"
)

var _ = Describe("E2E TEST PAT:"+checks.CheckBranchProtection, func() {
	Context("E2E TEST:Validating branch protection", func() {
		It("Should get non-admin branch protection on other repositories", func() {
			skipIfTokenIsNot(patTokenType, "PAT only")

			dl := scut.TestDetailLogger{}
			repo, err := githubrepo.MakeGithubRepo("ossf-tests/scorecard-check-branch-protection-e2e")
			Expect(err).Should(BeNil())
			repoClient := githubrepo.CreateGithubRepoClient(context.Background(), logger)
			err = repoClient.InitRepo(repo, clients.HeadSHA, 0)
			Expect(err).Should(BeNil())
			req := checker.CheckRequest{
				Ctx:        context.Background(),
				RepoClient: repoClient,
				Repo:       repo,
				Dlogger:    &dl,
			}
			expected := scut.TestReturn{
				Error:         nil,
				Score:         5,
				NumberOfWarn:  2,
				NumberOfInfo:  4,
				NumberOfDebug: 4,
			}
			result := checks.BranchProtection(&req)
			// UPGRADEv2: to remove.
			// Old version.

			// New version.
			Expect(scut.ValidateTestReturn(nil, "branch protection accessible none", &expected, &result, &dl)).Should(BeTrue())
			Expect(repoClient.Close()).Should(BeNil())
		})
		It("Should fail to return branch protection on other repositories", func() {
			skipIfTokenIsNot(patTokenType, "PAT only")

			dl := scut.TestDetailLogger{}
			repo, err := githubrepo.MakeGithubRepo("ossf-tests/scorecard-check-branch-protection-e2e-none")
			Expect(err).Should(BeNil())
			repoClient := githubrepo.CreateGithubRepoClient(context.Background(), logger)
			err = repoClient.InitRepo(repo, clients.HeadSHA, 0)
			Expect(err).Should(BeNil())
			req := checker.CheckRequest{
				Ctx:        context.Background(),
				RepoClient: repoClient,
				Repo:       repo,
				Dlogger:    &dl,
			}
			expected := scut.TestReturn{
				Error:         nil,
				Score:         0,
				NumberOfWarn:  2,
				NumberOfInfo:  0,
				NumberOfDebug: 0,
			}
			result := checks.BranchProtection(&req)

			// New version.
			Expect(scut.ValidateTestReturn(nil, "branch protection accessible patch", &expected, &result, &dl)).Should(BeTrue())
			Expect(repoClient.Close()).Should(BeNil())
		})
		It("Should fail to return branch protection on other repositories patch", func() {
			skipIfTokenIsNot(patTokenType, "PAT only")

			dl := scut.TestDetailLogger{}
			repo, err := githubrepo.MakeGithubRepo("ossf-tests/scorecard-check-branch-protection-e2e-patch-1")
			Expect(err).Should(BeNil())
			repoClient := githubrepo.CreateGithubRepoClient(context.Background(), logger)
			err = repoClient.InitRepo(repo, clients.HeadSHA, 0)
			Expect(err).Should(BeNil())
			req := checker.CheckRequest{
				Ctx:        context.Background(),
				RepoClient: repoClient,
				Repo:       repo,
				Dlogger:    &dl,
			}
			expected := scut.TestReturn{
				Error:         nil,
				Score:         1,
				NumberOfWarn:  3,
				NumberOfInfo:  3,
				NumberOfDebug: 4,
			}
			result := checks.BranchProtection(&req)

			// New version.
			Expect(scut.ValidateTestReturn(nil, "branch protection accessible local", &expected, &result, &dl)).Should(BeTrue())
			Expect(repoClient.Close()).Should(BeNil())
		})
		It("Should return error on a local repo client", func() {
			dl := scut.TestDetailLogger{}

			tmpDir, err := os.MkdirTemp("", "")
			Expect(err).Should(BeNil())
			defer os.RemoveAll(tmpDir)

			_, e := git.PlainClone(tmpDir, false, &git.CloneOptions{
				URL: "http://github.com/ossf-tests/scorecard-check-branch-protection-e2e-patch-1",
			})
			Expect(e).Should(BeNil())

			repo, err := localdir.MakeLocalDirRepo(tmpDir)
			Expect(err).Should(BeNil())

			x := localdir.CreateLocalDirClient(context.Background(), logger)
			err = x.InitRepo(repo, clients.HeadSHA, 0)
			Expect(err).Should(BeNil())

			req := checker.CheckRequest{
				Ctx:        context.Background(),
				RepoClient: x,
				Repo:       repo,
				Dlogger:    &dl,
			}

			result := checks.BranchProtection(&req)
			Expect(result.Error).ShouldNot(BeNil())
			Expect(x.Close()).Should(BeNil())
		})
	})
})

var _ = Describe("E2E TEST GITHUB_TOKEN:"+checks.CheckBranchProtection, func() {
	Context("E2E TEST:Validating branch protection", func() {
		It("Should get errors with GITHUB_TOKEN", func() {
			skipIfTokenIsNot(githubWorkflowDefaultTokenType, "GITHUB_TOKEN only")
			dl := scut.TestDetailLogger{}
			repo, err := githubrepo.MakeGithubRepo("ossf-tests/scorecard-check-branch-protection-e2e")
			Expect(err).Should(BeNil())
			repoClient := githubrepo.CreateGithubRepoClient(context.Background(), logger)
			err = repoClient.InitRepo(repo, clients.HeadSHA, 0)
			Expect(err).Should(BeNil())
			req := checker.CheckRequest{
				Ctx:        context.Background(),
				RepoClient: repoClient,
				Repo:       repo,
				Dlogger:    &dl,
			}

			result := checks.BranchProtection(&req)
			Expect(result.Error).ShouldNot(BeNil())
			// There should be an error with the GITHUB_TOKEN, until it's supported
			// byt GitHub.
			Expect(repoClient.Close()).Should(BeNil())
		})
	})
})
