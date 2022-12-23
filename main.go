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
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/laurentsimon/godep2"
	"github.com/ossf/scorecard/v4/cmd"
	"github.com/ossf/scorecard/v4/options"
	"github.com/ossf/scorecard/v4/permissions"
)

//go:embed go.perm.yml
var b []byte

var permissionManager *permissions.PermissionsManager

// TODO: proper argument: dd, cd, access, resource type, resource name
// TODO: use interface
func handleViolation(directDep, callerDep string,
	resType permissions.ResourceType, resName string,
	req permissions.Access,
) {
	fmt.Println("VIOLATION")
	fmt.Println("directDep", directDep)
	fmt.Println("callerDep", callerDep)
	fmt.Println("resName", resName)
	fmt.Println("req", req)
	fmt.Println("resType", resType)
	os.Exit(2)
}

func init() {
	var err error
	permissionManager, err = permissions.NewPermissionManagerFromData(b, handleViolation)
	if err != nil {
		panic(err)
	}
	fmt.Println(prettyPrint(*permissionManager))
	// panic("end")
}

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
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
	log.Println("times", permissions.Times[:permissions.Times_c])
}
