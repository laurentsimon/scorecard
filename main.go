// Copyright 2020 OpenSSF Scorecard Authors
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

// Package main of OSSF Scoreard.
package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"

	"golang.org/x/exp/constraints"
	"golang.org/x/exp/slices"

	"github.com/laurentsimon/godep2"
	permissions "github.com/laurentsimon/permissions-go"
	"github.com/ossf/scorecard/v4/cmd"
	"github.com/ossf/scorecard/v4/options"
)

//go:embed go.perm.yml
var b []byte

var permissionManager *permissions.PermissionsManager

// TODO: proper argument: dd, cd, access, resource type, resource name
// TODO: use interface
func onViolation(s *permissions.Stack,
) error {
	fmt.Fprintln(os.Stderr, "VIOLATION")
	fmt.Fprintln(os.Stderr, "directDep", s.DirectPkg)
	fmt.Fprintln(os.Stderr, "callerDep", s.CallerPkg)
	fmt.Fprintln(os.Stderr, "resName", s.ResName)
	fmt.Fprintln(os.Stderr, "req", s.Access)
	fmt.Fprintln(os.Stderr, "resType", s.ResType)
	// can walk the stack for printing.
	j, _ := s.ToJSON()
	fmt.Printf("%s", j)
	return fmt.Errorf("%w: xxx", permissions.ErrPermissionManagerViolation)
	// os.Exit(2)
	// return fmt.Errorf("%w: xxx", permissions.ErrPermissionManagerViolation)
}

func init() {
	var err error
	permissionManager, err = permissions.NewPermissionManagerFromData(b, onViolation)
	if err != nil {
		panic(err)
	}
	// panic("end")
}

/*
insights:
env: GODEBUG, HOME, PATH
files: /etc/nsswitch.conf isRuntime not detected properly coz runtime
.init functio need test
*/

func main() {
	// fmt.Println(fsMatches("/etc/ssl/certs/*", "/etc/ssl/certs"))
	// os.Exit(2)
	godep2.TestEnv("FROM_MAIN_DEP2")
	godep2.TestEnvThruDep3("MAIN_DEP2_DEP3")
	os.Getenv("FROM_MAIN_REALLY")
	opts := options.New()
	if err := cmd.New(opts).Execute(); err != nil {
		log.Fatalf("error during command execution: %v", err)
	}
	fmt.Fprintln(os.Stderr, "times", permissions.Times[:permissions.Times_c])
	fmt.Fprintln(os.Stderr, "median:", median(permissions.Times[:permissions.Times_c]))
}

// https://gosamples.dev/calculate-median/
type Number interface {
	constraints.Float | constraints.Integer
}

func median[T Number](data []T) float64 {
	dataCopy := make([]T, len(data))
	copy(dataCopy, data)

	slices.Sort(dataCopy)

	var median float64
	l := len(dataCopy)
	if l == 0 {
		return 0
	} else if l%2 == 0 {
		median = float64((dataCopy[l/2-1] + dataCopy[l/2]) / 2.0)
	} else {
		median = float64(dataCopy[l/2])
	}

	return median
}
