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

// Package localdir implements RepoClient on local source code.
package localdir

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"go.uber.org/zap"

	clients "github.com/ossf/scorecard/v3/clients"
)

var (
	errUnsupportedFeature = errors.New("unsupported feature")
	errInputRepoType      = errors.New("input repo should be of type repoLocal")
)

var once sync.Once

type localDirClient struct {
	logger *zap.Logger
	ctx    context.Context
	path   string
}

// InitRepo sets up the local repo.
func (client *localDirClient) InitRepo(inputRepo clients.Repo) error {
	localRepo, ok := inputRepo.(*repoLocal)
	if !ok {
		return fmt.Errorf("%w: %v", errInputRepoType, inputRepo)
	}

	client.path = strings.TrimPrefix(localRepo.URI(), "file://")

	return nil
}

// URI implements RepoClient.URI.
func (client *localDirClient) URI() string {
	return fmt.Sprintf("file://%s", client.path)
}

// IsArchived implements RepoClient.IsArchived.
func (client *localDirClient) IsArchived() (bool, error) {
	return false, fmt.Errorf("IsArchived: %w", errUnsupportedFeature)
}

// IsLocal implements RepoClient.IsLocal.
func (client *localDirClient) IsLocal() bool {
	return true
}

func isDir(p string) (bool, error) {
	fileInfo, err := os.Stat(p)
	if err != nil {
		return false, fmt.Errorf("%w", err)
	}

	return fileInfo.IsDir(), nil
}

func (client *localDirClient) listFiles(predicate func(string) (bool, error)) ([]string, error) {
	files := []string{}
	err := filepath.Walk(client.path, func(pathfn string, info fs.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("failure accessing path %q: %w", pathfn, err)
		}

		// Skip directories.
		d, err := isDir(pathfn)
		if err != nil {
			return err
		}
		if d {
			return nil
		}

		// Remove prefix of the folder.
		cleanPath := path.Clean(pathfn)
		prefix := fmt.Sprintf("%s%s", client.path, string(os.PathSeparator))
		p := strings.TrimPrefix(cleanPath, prefix)
		matches, err := predicate(p)
		if err != nil {
			return err
		}

		if matches {
			files = append(files, p)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error walking the path %q: %w", client.path, err)
	}

	return files, nil
}

// ListFiles implements RepoClient.ListFiles.
func (client *localDirClient) ListFiles(predicate func(string) (bool, error)) ([]string, error) {
	files := []string{}
	var err error

	once.Do(func() {
		files, err = client.listFiles(predicate)
	})

	return files, err
}

// GetFileContent implements RepoClient.GetFileContent.
func (client *localDirClient) GetFileContent(filename string) ([]byte, error) {
	// Note: the filenames do not contain the original path - see ListFiles().
	fn := path.Join(client.path, filename)
	content, err := os.ReadFile(fn)
	if err != nil {
		return content, fmt.Errorf("%w", err)
	}
	return content, nil
}

// ListMergedPRs implements RepoClient.ListMergedPRs.
func (client *localDirClient) ListMergedPRs() ([]clients.PullRequest, error) {
	return nil, fmt.Errorf("ListMergedPRs: %w", errUnsupportedFeature)
}

// ListBranches implements RepoClient.ListBranches.
func (client *localDirClient) ListBranches() ([]*clients.BranchRef, error) {
	return nil, fmt.Errorf("ListBranches: %w", errUnsupportedFeature)
}

// GetDefaultBranch implements RepoClient.GetDefaultBranch.
func (client *localDirClient) GetDefaultBranch() (*clients.BranchRef, error) {
	return nil, fmt.Errorf("GetDefaultBranch: %w", errUnsupportedFeature)
}

func (client *localDirClient) ListCommits() ([]clients.Commit, error) {
	return nil, fmt.Errorf("ListCommits: %w", errUnsupportedFeature)
}

// ListReleases implements RepoClient.ListReleases.
func (client *localDirClient) ListReleases() ([]clients.Release, error) {
	return nil, fmt.Errorf("ListReleases: %w", errUnsupportedFeature)
}

// ListContributors implements RepoClient.ListContributors.
func (client *localDirClient) ListContributors() ([]clients.Contributor, error) {
	return nil, fmt.Errorf("ListContributors: %w", errUnsupportedFeature)
}

// ListSuccessfulWorkflowRuns implements RepoClient.WorkflowRunsByFilename.
func (client *localDirClient) ListSuccessfulWorkflowRuns(filename string) ([]clients.WorkflowRun, error) {
	return nil, fmt.Errorf("ListSuccessfulWorkflowRuns: %w", errUnsupportedFeature)
}

// ListCheckRunsForRef implements RepoClient.ListCheckRunsForRef.
func (client *localDirClient) ListCheckRunsForRef(ref string) ([]clients.CheckRun, error) {
	return nil, fmt.Errorf("ListCheckRunsForRef: %w", errUnsupportedFeature)
}

// ListStatuses implements RepoClient.ListStatuses.
func (client *localDirClient) ListStatuses(ref string) ([]clients.Status, error) {
	return nil, fmt.Errorf("ListStatuses: %w", errUnsupportedFeature)
}

// Search implements RepoClient.Search.
func (client *localDirClient) Search(request clients.SearchRequest) (clients.SearchResponse, error) {
	return clients.SearchResponse{}, fmt.Errorf("Search: %w", errUnsupportedFeature)
}

func (client *localDirClient) Close() error {
	return nil
}

// CreateLocalDirClient returns a client which implements RepoClient interface.
func CreateLocalDirClient(ctx context.Context, logger *zap.Logger) clients.RepoClient {
	return &localDirClient{
		ctx:    ctx,
		logger: logger,
	}
}
