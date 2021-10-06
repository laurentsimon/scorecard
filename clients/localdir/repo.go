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
//

// Package localdir is local repo containing source code.
package localdir

import (
<<<<<<< HEAD
	"errors"
	"fmt"

	clients "github.com/ossf/scorecard/v3/clients"
=======
	"fmt"

	clients "github.com/ossf/scorecard/v2/clients"
>>>>>>> 376995a (docker file)
)

type localRepoClient struct {
	path string
}

<<<<<<< HEAD
// URI implements Repo.URI().
=======
>>>>>>> 376995a (docker file)
func (r *localRepoClient) URI() string {
	return fmt.Sprintf("file://%s", r.path)
}

<<<<<<< HEAD
// String implements Repo.String.
func (r *localRepoClient) String() string {
	// TODO
	return "unsupported String()"
}

// Org implements Repo.Org.
func (r *localRepoClient) Org() clients.Repo {
	// TODO
	return &localRepoClient{}
}

// IsValid implements Repo.IsValid.
func (r *localRepoClient) IsValid() error {
	// TODO
	//nolint:goerr113
	return errors.New("unsupported IsValid()")
}

// Metadata implements Repo.Metadata.
func (r *localRepoClient) Metadata() []string {
	// TODO
	return []string{}
}

// AppendMetadata implements Repo.AppendMetadata.
func (r *localRepoClient) AppendMetadata(m ...string) {
	// TODO
}

// IsScorecardRepo implements Repo.IsScorecardRepo.
func (r *localRepoClient) IsScorecardRepo() bool {
	// TODO
=======
func (r *localRepoClient) String() string {
	panic("invalid String()")
	//nolint
	return ""
}

func (r *localRepoClient) Org() clients.Repo {
	panic("invalid Org()")
	//nolint
	return &localRepoClient{}
}

func (r *localRepoClient) IsValid() error {
	panic("invalid IsValid()")
	//nolint
	return nil
}

func (r *localRepoClient) Metadata() []string {
	panic("invalid Metadata()")
	//nolint
	return nil
}

func (r *localRepoClient) AppendMetadata(m ...string) {
	panic("invalid AppendMetadata()")
}

func (r *localRepoClient) IsScorecardRepo() bool {
	panic("invalid IsScorecardRepo()")
	//nolint
>>>>>>> 376995a (docker file)
	return false
}

// MakeLocalDirRepo returns an implementation of clients.Repo interface.
func MakeLocalDirRepo(path string) (clients.Repo, error) {
	// TODO: validate the path exists
	return &localRepoClient{
		path: path,
	}, nil
}
