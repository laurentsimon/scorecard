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
	"fmt"
	"hooks"
	"io/fs"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/laurentsimon/godep2"
	"github.com/ossf/scorecard/v4/cmd"
	"github.com/ossf/scorecard/v4/options"
)

type (
	testHook   struct{}
	policy     int
	permission int
)

const (
	policyDefaultAllow    policy = 1
	policyDefaultDisallow policy = 2

	permissionAllowed    permission = 1
	permissionDisallowed permission = 2
	permissionNotDefined permission = 3
)

var (
	times   [5000]int64
	times_c = 0
)

var localProgram = "<local>"

type access int

const (
	accessWrite access = 1
	accessRead  access = 2
	accessExec  access = 4
	accessNone  access = 0
)

type resourceType int

const (
	resourceTypeEnv resourceType = 1
	resourceTypeFs  resourceType = 2
	resourceTypeNet resourceType = 3
	// resourceTypeRpc resourceType = 4
	resourceTypeProcess resourceType = 4
)

type (
	resourceName string
	perm         map[resourceName]access
)

type (
	dependencyName string
	p              map[resourceType]struct {
		dangerousPermissions *perm
		contextPermissions   *perm
	}
)
type perms map[dependencyName]p

var (
	ambientPolicy = policyDefaultDisallow
	depsPolicy    = policyDefaultDisallow // Note: inherited. Useful only to validate when doing the direct deps definition. Maybe remove it (?)

	// Should use lists since this data is really sparse. This format is fine for the config file, though.
	definedPerms = perms{
		// TODO: remove dependencyName
		"<local>": p{
			resourceTypeEnv: {
				contextPermissions: &perm{
					"*": accessRead,
				},
			},
			resourceTypeFs: {
				contextPermissions: &perm{
					"*": accessRead,
				},
			},
		},
		"github.com/laurentsimon/godep2": p{
			// dangerousPermissions: perm{
			// 	"*": accessRead,
			// },
			resourceTypeEnv: {
				contextPermissions: &perm{
					"*": accessRead,
				},
			},
		},
		"github.com/laurentsimon/godep3": p{
			resourceTypeEnv: {
				contextPermissions: &perm{
					"FROM_OPTIONS": accessRead,
				},
			},
		},
		"github.com/spf13/cobra": p{ // Can use the needs.x in the future.
			resourceTypeEnv: {
				contextPermissions: &perm{
					"*": accessRead,
				},
			},
		},
		"github.com/google/go-containerregistry": p{
			resourceTypeEnv: {
				contextPermissions: &perm{
					"HOME":          accessRead,
					"DOCKER_CONFIG": accessRead,
					"GODEBUG":       accessRead,
					"PATH":          accessRead,
				},
			},
		},
		"github.com/docker/docker-credential-helpers": p{
			resourceTypeEnv: {
				contextPermissions: &perm{
					"HOME":          accessRead,
					"DOCKER_CONFIG": accessRead,
					"GODEBUG":       accessRead,
				},
			},
		},
	}
)

/*
var (

	// env variables.
	envAllowedDangerousDeps = map[string]permission{"github.com/laurentsimon/godep2": permissionAllowed}
	envContextPermissions   = map[string]permission{
		localProgram: permissionDisallowed,
		// "github.com/laurentsimon/godep2": permissionAllowed,
		// "github.com/laurentsimon/godep3": permissionAllowed,
		// "github.com/spf13/cobra":         permissionAllowed,
		// takes carer of github.com/google/go-github/x/y
		//"github.com/google/go-github": permissionDisallowed,
		//"go.opencensus.io/plugin/ochttp":                   permissionAllowed,
		//"github.com/google/go-containerregistry": permissionAllowed,
		//"github.com/google/go-containerregistry/pkg/crane": permissionAllowed,
		// go.opencensus.io/plugin/ochttp dependent of v38/github as permissionDiallowed
	}

	// Files.
	fileReadAllowedDangerousDeps = map[string]permission{}
	fileReadContextPermissions   = map[string]permission{
		localProgram: permissionAllowed,
	}
)
*/

func (l *testHook) Getenv(key string) {
	// return // disable for testing
	fmt.Printf("Getenv(%s)\n", key)
	// mylog("stack info:")
	start := time.Now()

	computePermissions(key, resourceTypeEnv, accessRead)

	elapsed := time.Since(start)
	times[times_c] = elapsed.Nanoseconds()
	times_c++
	log.Printf("perm check took %d", elapsed.Nanoseconds())
}

func (l *testHook) Environ() {
	// disabled for testing
	return
	fmt.Printf("Environ()\n")
	start := time.Now()

	// TODO: Do this properly.
	computePermissions("*", resourceTypeEnv, accessRead)

	elapsed := time.Since(start)
	times[times_c] = elapsed.Nanoseconds()
	times_c++
	log.Printf("perm check took %d", elapsed.Nanoseconds())
}

func (l *testHook) Open(file string, flag int, perms fs.FileMode) {
	// disabled
	return
	fmt.Printf("Open(%s)\n", file)
	start := time.Now()

	// TODO: Do this properly.
	computePermissions(file, resourceTypeFs, accessRead)

	elapsed := time.Since(start)
	times[times_c] = elapsed.Nanoseconds()
	times_c++
	log.Printf("perm check took %d", elapsed.Nanoseconds())
}

var (
	manager       testHook
	defaultPolicy = policyDefaultDisallow
)

// TODO: get dynamically at load time.
var compilerPath = "/usr/local/google/home/laurentsimon/sandboxing/golang/go/"

func mylog(args ...string) {
	fmt.Println(args)
}

func computePermissions(key string, resType resourceType, req access) {
	pc := make([]uintptr, 1000)
	// Skip this function and the runtime.caller itself.
	n := runtime.Callers(2, pc)
	if n == 0 {
		panic("!zero!")
	}

	pc = pc[:n] // pass only valid pcs to runtime.CallersFrames
	rpc := make([]uintptr, n)
	for i := 0; i < len(pc); i++ {
		rpc[i] = pc[len(pc)-i-1]
	}

	// TODO: query once and make it a double-linked list ?
	// if key == "GODEBUG" {
	// 	mylog("\n\n")
	// }
	// mylog(pc)
	// mylog(rpc)
	// Get the direct caller package.
	// Only needed if the main program or some packages have context-less permissions.
	frames := runtime.CallersFrames(pc)
	depName := localProgram
	i := 0
	for {
		curr, more := frames.Next()
		packageName := getPackageName(curr.Function)
		// if key == "ENABLE_SARIF" {
		// 	fmt.Printf("- %d - %s | %s | %s:%d \n", pc[i], packageName, curr.Function, curr.File, curr.Line)
		// }
		i++

		currIs3P := is3PDependency(curr.File)

		// Get the dependency.
		if depName == localProgram && currIs3P {
			depName = packageName
			break
		}

		if !more {
			break
		}
	}

	mylog(" . caller dep is", depName)
	// TODO: proper function for this.
	var dangerousAllowed bool
	dangerousPermissions := getDangerousPermissionsForDep(key, resType, depName)
	// TODO: simplify
	if ambientPolicy == policyDefaultAllow && depsPolicy == policyDefaultAllow {
		dangerousAllowed = isPermissionAllowed2(dangerousPermissions, req, true)
	} else {
		// dangerousAllowed = isPermissionAllowed(dangerousPermissions, depName)
		dangerousAllowed = isPermissionAllowed2(dangerousPermissions, req, false)
	}
	mylog(" . Allowed dangerous:", strconv.FormatBool(dangerousAllowed))

	/*
		ambientPolicy: allow
		depsPolicy: allow
		-> here we just need to walk the stack and find removed permissions.

		Here I assume:
		ambientPolicy: disallow
		despPolicy: allow - continue selective removing and direct deps.
		-> here we have a special case for the mmain program, but continue walking the
		stack for removed / intersection of permissions.

		ambientPolicy: disallow
		depsPolicy: disallow
		-> here we do the same as above, except we add a special case
		 for the direct dependency if its permissions are not defined

		Once direct deps are all declared, can move to disallow for deps.
	*/

	// Need to always walk the stack, since the calling dep could be part of a callback.
	// Assume a default policy or disallow.
	frames = runtime.CallersFrames(rpc)
	i = 0
	allowed := false
	prevIs3P := false
	found3P := false
	foundLocal := false
	for {
		curr, more := frames.Next()
		// Process this frame.
		//
		// To keep this example's output stable
		// even if there are changes in the testing package,
		// stop unwinding when we leave package runtime.
		// if !strings.Contains(frame.File, "runtime/") {
		// 	break
		// }

		// if key == "GODEBUG" {
		// 	fmt.Printf("- %d - %s | %s | %s:%d \n", rpc[i], packageName, curr.Function, curr.File, curr.Line)
		// }
		i++

		// Can cache these.
		currIs3P := is3PDependency(curr.File)
		isRuntime := isRuntime(curr.File)
		isLocal := !currIs3P && !isRuntime

		// Assuming default policy is disallow.
		// here we find the local package toop of the stack
		// we cannot just check if the package is local due to
		// callbacks.
		// Note: this code should be properly seperated.
		if isLocal {
			contextPermissions := getContextPermissionsForDep(key, resType, localProgram)
			if ambientPolicy == policyDefaultDisallow {
				if !foundLocal {
					foundLocal = true
					if !isPermissionAllowed2(contextPermissions, req, false) {
						mylog(" . Allowed context: false -", localProgram)
						break
					}
				}
			} else {
				if !isPermissionAllowed2(contextPermissions, req, true) {
					mylog(" . Allowed context: false -", localProgram)
					break
				}
			}
		}

		packageName := getPackageName(curr.Function)
		if currIs3P {
			contextPermissions := getContextPermissionsForDep(key, resType, packageName)
			if !found3P && !prevIs3P {
				mylog(" . Direct dep -", packageName)
			}
			if depsPolicy == policyDefaultDisallow {
				if !found3P && !prevIs3P {
					// Direct dependency.
					found3P = true
					if !isPermissionAllowed2(contextPermissions, req, false) {
						mylog(" . Allowed context: false (direct) -", packageName)
						break
					}
				} else {
					if !isPermissionAllowed2(contextPermissions, req, true) {
						mylog(" . Allowed context: false -", packageName)
						break
					}
				}
			} else {
				if !isPermissionAllowed2(contextPermissions, req, true) {
					mylog(" . Allowed context: false -", packageName)
					break
				}
			}
		}

		prevIs3P = currIs3P

		// 	// set to true so that dependent inherit it
		// 	allowed = true
		// 	continue
		// }

		// first direct dependency was found.
		// allow is always true here.
		// if !allowed {
		// 	panic("not allowed")
		// }

		// if currIs3P && isAllowed(contextPermissions, packageName) {
		// 	mylog(" . Allowed context: false -", packageName)
		// 	break
		// } else if !isRuntime && !isAllowed(contextPermissions, localProgram) {
		// 	// Local, ie main program
		// 	mylog(" . Allowed context: false -", localProgram)
		// 	break
		// }

		// Check whether there are more frames to process after this one.
		if !more {
			allowed = true
			break
		}

	}

	if allowed {
		mylog(" . Allowed context: true")
	}

	if !dangerousAllowed && !allowed {
		fmt.Println("VIOLATION")
		os.Exit(2)
	}
	// if depName == "go.opencensus.io/plugin/ochttp" {
	// 	os.Exit(2)
	// }

	// Get the frames - reverse
	// frames = runtime.CallersFrames(rpc)
	// prevIs3P := false
	// directDepName := "<local>"
	// for {
	// 	curr, more := frames.Next()
	// 	// Process this frame.
	// 	//
	// 	// To keep this example's output stable
	// 	// even if there are changes in the testing package,
	// 	// stop unwinding when we leave package runtime.
	// 	// if !strings.Contains(frame.File, "runtime/") {
	// 	// 	break
	// 	// }

	// 	packageName := getPackageName(curr.Function)
	// 	// fmt.Printf("- %s | %s | %s:%d \n", packageName, curr.Function, curr.File, curr.Line)

	// 	currIs3P := is3PDependency(curr.File)

	// 	// Check for package.
	// 	if currIs3P && !prevIs3P {
	// 		directDepName = packageName
	// 		break
	// 	}
	// 	prevIs3P = currIs3P

	// 	// Check whether there are more frames to process after this one.
	// 	if !more {
	// 		break
	// 	}

	// }
	// mylog(" . direct dep is", directDepName)
	// mylog(" . caller dep is", depName)
}

func getDangerousPermissionsForDep(resName string, resType resourceType, depName string) *access {
	e, ok := definedPerms[dependencyName(depName)]
	if !ok {
		if strings.HasPrefix(depName, "github.com/") {
			// Try a subset, github.com/google/go-github/v38/github
			parts := strings.Split(depName, "/")
			if len(parts) < 3 {
				return nil
			}
			e, ok = definedPerms[dependencyName(strings.Join(parts[:3], "/"))]
		}
		if !ok {
			return nil
		}
	}

	v, ok := e[resType]
	if !ok {
		return nil
	}

	if v.dangerousPermissions == nil {
		return nil
	}

	r, ok := (*v.dangerousPermissions)[resourceName(resName)]
	if !ok {
		// Need to handle globs. Probably need to change function completely
		// to iterate over the perm, instead of returning the access.
		if r, ok = (*v.dangerousPermissions)["*"]; ok {
			return &r
		}
		return nil
	}
	return &r
}

func getContextPermissionsForDep(resName string, resType resourceType, depName string) *access {
	e, ok := definedPerms[dependencyName(depName)]
	if !ok {
		if strings.HasPrefix(depName, "github.com/") {
			// Try a subset, github.com/google/go-github/v38/github
			parts := strings.Split(depName, "/")
			if len(parts) < 3 {
				return nil
			}
			e, ok = definedPerms[dependencyName(strings.Join(parts[:3], "/"))]
		}
		if !ok {
			return nil
		}
	}

	v, ok := e[resType]
	if !ok {
		return nil
	}

	if v.contextPermissions == nil {
		return nil
	}

	r, ok := (*v.contextPermissions)[resourceName(resName)]
	if !ok {
		// Need to handle globs. Probably need to change function completely
		// to iterate over the perm, instead of returning the access.
		if r, ok = (*v.contextPermissions)["*"]; ok {
			return &r
		}
		return nil
	}
	return &r
}

func getContextPermssionsForDep(resType resourceType, depName string) *perm {
	e, ok := definedPerms[dependencyName(depName)]
	if !ok {
		if strings.HasPrefix(depName, "github.com/") {
			// Try a subset, github.com/google/go-github/v38/github
			parts := strings.Split(depName, "/")
			if len(parts) < 3 {
				return nil
			}
			e, ok = definedPerms[dependencyName(strings.Join(parts[:3], "/"))]
		}
		if !ok {
			return nil
		}
	}

	v, ok := e[resType]
	if !ok {
		return nil
	}

	return v.contextPermissions
}

func isPermissionAllowed2(def *access, req access, defValue bool) bool {
	if def != nil {
		return (*def & req) != accessNone
	}
	return defValue
}

func isRuntime(filename string) bool {
	return strings.HasPrefix(filename, compilerPath) ||
		strings.Contains(filename, "/golang.org/")
}

// TODO: create a permission class.
func isPermissionAllowed(m map[string]permission, depName string) bool {
	if p, ok := m[depName]; ok {
		return p == permissionAllowed
	}

	if strings.HasPrefix(depName, "github.com/") {
		// Try a subset, github.com/google/go-github/v38/github
		parts := strings.Split(depName, "/")
		if len(parts) < 3 {
			return false
		}
		if p, ok := m[strings.Join(parts[:3], "/")]; ok {
			return p == permissionAllowed
		}
	}

	// No permission provided. Default is false if inheritance is not taken into account.
	return false
}

func isContextPermissionAllowed(m map[string]permission, depName string) bool {
	if p, ok := m[depName]; ok {
		return p == permissionAllowed
	}
	if strings.HasPrefix(depName, "github.com/") {
		// Try a subset, github.com/google/go-github/v38/github
		parts := strings.Split(depName, "/")
		if len(parts) < 3 {
			return true
		}
		if p, ok := m[strings.Join(parts[:3], "/")]; ok {
			return p == permissionAllowed
		}
	}
	// No permission provided. Default is true.
	return true
}

// TODO: fix with StartsWith and query once to learn the path.
func is3PDependency(filename string) bool {
	return !isRuntime(filename) && strings.Contains(filename, "/pkg/mod/")
}

func getPackageName(funcName string) string {
	parts := strings.Split(funcName, ".")
	pl := len(parts)

	if len(parts[pl-2]) == 0 {
		return "invalid"
	}
	if parts[pl-2][0] == '(' {
		return strings.Join(parts[0:pl-2], ".")
	}
	return strings.Join(parts[0:pl-1], ".")
}

func main() {
	hooks.SetManager(&manager)
	godep2.TestEnv("FROM_MAIN_DEP2")
	godep2.TestEnvThruDep3("MAIN_DEP2_DEP3")
	os.Getenv("FROM_MAIN_REALLY")
	opts := options.New()
	if err := cmd.New(opts).Execute(); err != nil {
		log.Fatalf("error during command execution: %v", err)
	}
	log.Printf("times", times[:times_c])
}
