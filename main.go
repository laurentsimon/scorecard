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
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/laurentsimon/godep2"
	"github.com/ossf/scorecard/v4/cmd"
	"github.com/ossf/scorecard/v4/options"
)

type testHook struct{}

func (l *testHook) Getenv(key string) {
	fmt.Printf("hook called with '%s'\n", key)
	// fmt.Println("stack info:")

	retrieveCallInfo2()
}

var manager testHook

func retrieveCallInfo2() {
	pc := make([]uintptr, 1000)
	// Skip this function and the runtime.caller itself.
	n := runtime.Callers(2, pc)
	if n == 0 {
		panic("!zero!")
	}

	pc = pc[:n] // pass only valid pcs to runtime.CallersFrames
	rpc := make([]uintptr, n)
	for i := 0; i <= len(pc)-1; i++ {
		rpc[i] = pc[len(pc)-(i+1)]
	}

	// TODO: query once and make it a double-linked list ?

	// Get the direct caller package.
	// Only needed if the main program or some packages have context-less permissions.
	frames := runtime.CallersFrames(pc)
	depName := "<local>"
	for {
		curr, more := frames.Next()
		packageName := getPackageName(curr.Function)
		// fmt.Printf("- %s | %s | %s:%d \n", packageName, curr.Function, curr.File, curr.Line)

		currIs3P := is3PDependency(curr.File)

		// Get the dependency.
		if depName == "<local>" && currIs3P {
			depName = packageName
			break
		}

		if !more {
			break
		}
	}

	// Get the frames
	frames = runtime.CallersFrames(rpc)
	prevIs3P := false
	directDepName := "<local>"
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

		packageName := getPackageName(curr.Function)
		// fmt.Printf("- %s | %s | %s:%d \n", packageName, curr.Function, curr.File, curr.Line)

		currIs3P := is3PDependency(curr.File)

		// Check for package.
		if currIs3P && !prevIs3P {
			directDepName = packageName
			break
		}
		prevIs3P = currIs3P

		// Check whether there are more frames to process after this one.
		if !more {
			break
		}

	}
	fmt.Println(" . direct dep is", directDepName)
	fmt.Println(" . caller dep is", depName)

	allowedDirectDeps := map[string]bool{
		"<local>":                        true,
		"github.com/spf13/cobra":         true,
		"github.com/laurentsimon/godep2": true,
	}
	allowedDangerousDeps := map[string]bool{"github.com/laurentsimon/godep2": true}
	fmt.Println(" . Allowed:", isAllowed(allowedDirectDeps, directDepName) ||
		isAllowed(allowedDangerousDeps, depName))
}

func isAllowed(m map[string]bool, depName string) bool {
	_, ok := m[depName]
	return ok
}

// TODO: fix with StartsWith and query once to learn the path.
func is3PDependency(filename string) bool {
	return strings.Contains(filename, "/pkg/mod/")
}

func getPackageName(packageName string) string {
	parts := strings.Split(packageName, ".")
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
	godep2.TestEnv("FROM_MAIN")
	godep2.TestEnvThruDep3("MAIN_DEP2_DEP3")
	os.Getenv("FROM_MAIN_REALLY")
	opts := options.New()
	if err := cmd.New(opts).Execute(); err != nil {
		log.Fatalf("error during command execution: %v", err)
	}
}
