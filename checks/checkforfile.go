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
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ossf/scorecard/checker"
)

// TODO: readme, security.md, check for email and send email
// CheckIfFileExists downloads the tar of the repository and calls the predicate to check
// for the occurrence.
func CheckIfFileExists(checkName string, c *checker.CheckRequest, predicate func(name string,
	Logf func(s string, f ...interface{})) bool) checker.CheckResult {
	r, _, err := c.Client.Repositories.Get(c.Ctx, c.Owner, c.Repo)
	if err != nil {
		return checker.MakeRetryResult(checkName, err)
	}
	url := r.GetArchiveURL()
	fmt.Printf("url:%s\n", url)
	url = strings.Replace(url, "{archive_format}", "tarball/", 1)
	url = strings.Replace(url, "{/ref}", r.GetDefaultBranch(), 1)
	fmt.Printf("url:%s\n", url)

	// Using the http.get instead of the lib httpClient because
	// the default checker.HTTPClient caches everything in the memory and it causes oom.

	//https://securego.io/docs/rules/g107.html
	//nolint
	resp, err := http.Get(url)
	if err != nil {
		return checker.MakeRetryResult(checkName, err)
	}
	defer resp.Body.Close()

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return checker.MakeRetryResult(checkName, err)
	}
	tr := tar.NewReader(gz)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return checker.MakeRetryResult(checkName, err)
		}

		// Strip the repo name
		const splitLength = 2

		if hdr.Name == "ossf-scorecard-a2d51ea/gitcache/README.md" {

			// switch hdr.Typeflag {

			// case tar.TypeReg:
			// 	fmt.Println("Name: ", hdr.Name)

			// 	fmt.Println(" --- ")
			// 	io.Copy(os.Stdout, tr)
			// 	fmt.Println(" --- ")

			// default:
			// 	fmt.Printf("%s : %c %s %s\n",
			// 		"Yikes! Unable to figure out type",
			// 		hdr.Typeflag,
			// 		"in file",
			// 		hdr.Name,
			// 	)
			// }
			content := make([]byte, hdr.Size)
			size, err := tr.Read(content)
			fmt.Printf("%s %d %d %d %d\n", hdr.Name, size, hdr.Size, err, hdr.Typeflag)
			if err != io.EOF || int64(size) != hdr.Size {
				break
			}

			fmt.Printf("%s", content)
			contentType := http.DetectContentType(content)
			fmt.Printf("%s", contentType)
		}
		names := strings.SplitN(hdr.Name, "/", splitLength)
		if len(names) < splitLength {
			continue
		}

		name := names[1]
		if predicate(name, c.Logf) {
			return checker.MakePassResult(checkName)
		}
	}
	const confidence = 5
	return checker.CheckResult{
		Name:       checkName,
		Pass:       false,
		Confidence: confidence,
	}
}
