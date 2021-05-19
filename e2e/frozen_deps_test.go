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

package e2e

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/ossf/scorecard/checker"
	"github.com/ossf/scorecard/checks"
)

var _ = Describe("E2E TEST:FrozenDeps", func() {
	Context("E2E TEST:Validating deps are frozen", func() {
		It("Should return deps are not frozen", func() {
			l := log{}
			checkRequest := checker.CheckRequest{
				Ctx:         context.Background(),
				Client:      ghClient,
				HTTPClient:  client,
				Owner:       "tensorflow",
				Repo:        "tensorflow",
				GraphClient: graphClient,
				Logf:        l.Logf,
			}
			result := checks.FrozenDeps(&checkRequest)
			Expect(result.Error).ShouldNot(BeNil())
			Expect(result.Pass).Should(BeFalse())
		})
		It("Should return deps are not frozen", func() {
			l := log{}
			checkRequest := checker.CheckRequest{
				Ctx:         context.Background(),
				Client:      ghClient,
				HTTPClient:  client,
				Owner:       "ossf",
				Repo:        "scorecard",
				GraphClient: graphClient,
				Logf:        l.Logf,
			}
			result := checks.FrozenDeps(&checkRequest)
			Expect(result.Error).Should(BeNil())
			Expect(result.Pass).Should(BeFalse())
		})
		It("Should return deps are not frozen", func() {
			l := log{}
			checkRequest := checker.CheckRequest{
				Ctx:         context.Background(),
				Client:      ghClient,
				HTTPClient:  client,
				Owner:       "ossf",
				Repo:        "scorecard",
				GraphClient: graphClient,
				Logf:        l.Logf,
			}
			result := checks.FrozenDeps(&checkRequest)
			Expect(result.Error).Should(BeNil())
			Expect(result.Pass).Should(BeTrue())
		})
	})
})
