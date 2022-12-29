package permissions

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

type PermissionsManager struct {
	config      *config
	hookManager *hookManager
	violationCb OnViolation
}

// TODO: remove?
var depsPolicy = policyDefaultAllow

type (
	permMatches func(val, req string) bool
	OnViolation func(s *Stack) error
)

var ErrPermissionManagerViolation = errors.New("permission manager violation")

func NewPermissionManagerFromFile(file string, cb OnViolation) (*PermissionsManager, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return NewPermissionManagerFromData(data, cb)
}

func NewPermissionManagerFromData(data []byte, cb OnViolation) (*PermissionsManager, error) {
	var pm PermissionsManager
	config, err := NewConfigFromData(data)
	if err != nil {
		return nil, err
	}

	manager, err := NewHookManager(&pm)
	if err != nil {
		return nil, err
	}

	pm.hookManager = manager
	pm.config = config
	pm.violationCb = cb

	return &pm, nil
}

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

func mylog(args ...string) {
	// msg := fmt.Sprintln(args)
	// fmt.Fprintf(os.Stderr, msg)
}

// TODO: callback
func (pm *PermissionsManager) OnAccess(key string, matches permMatches, resType ResourceType, req Access) error {
	pc := make([]uintptr, 1000)
	// Skip runtime.caller, this function, the hook manager and the runtime's hook.
	n := runtime.Callers(4, pc)
	if n == 0 {
		panic("!zero!")
	}

	pc = pc[:n] // Pass only valid pcs to runtime.CallersFrames
	rpc := make([]uintptr, n)
	for i := 0; i < len(pc); i++ {
		rpc[i] = pc[len(pc)-i-1]
	}

	// Get the direct caller package.
	// Only needed if the main program or some packages have context-less permissions.
	frames := runtime.CallersFrames(pc)
	depName := string(ambientAuthority)
	i := 0
	for {
		curr, more := frames.Next()
		packageName := getPackageName(curr.Function)
		// if key == "ENABLE_SARIF" {
		// 	fmt.Printf("- %d - %s | %s | %s:%d \n", pc[i], packageName, curr.Function, curr.File, curr.Line)
		// }
		i++

		currIs3P := isExternalDependency(curr.File)

		// Get the dependency.
		if depName == string(ambientAuthority) && currIs3P {
			depName = packageName
			break
		}

		if !more {
			break
		}
	}

	mylog(" . Caller dep is", depName)
	// TODO: proper function for this.
	var dangerousAllowed bool

	// TODO: verify that i's orrect for dangerous policy if error in fmatch()
	dangerousPermissions := pm.getDangerousPermissionsForDep(key, matches, resType, depName)
	// TODO: simplify
	if *pm.config.Default == policyDefaultAllow && depsPolicy == policyDefaultAllow {
		dangerousAllowed = isPermissionAllowed(dangerousPermissions, req, true)
	} else {
		// dangerousAllowed = isPermissionAllowed(DangerousPermissions, depName)
		dangerousAllowed = isPermissionAllowed(dangerousPermissions, req, false)
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

	// NOTE: we can stop here if dangerous is not allowed.. unless we are in learning mode.
	frames = runtime.CallersFrames(rpc)
	i = 0
	var directDep string
	allowed := false
	prevIs3P := false
	found3P := false
	foundLocal := false
	for {
		curr, more := frames.Next()
		// Process this frame.

		// Can cache these.
		currIs3P := isExternalDependency(curr.File)
		// isRuntime := isRuntime(curr.File)
		// TODO: isPermissionManager
		// We consider the runtime to be part of the local program.
		// This ensures we account for calls that are made at load time,
		// before the main program runs.
		isLocal := !currIs3P //|| isRuntime

		// isRuntime shoudl be tru but is false when the call is made
		// from the runtime at load time, before the main program runs.
		// if key == "/etc/nsswitch.conf" {
		// 	fmt.Printf("- %d - %s | %s | %s | %v \n", rpc[i], getPackageName(curr.Function), curr.Function, curr.File, isLocal)
		// }
		i++

		// NOTE: we cannot just check if the package is local due to
		// callbacks.
		// TODO: this code should be properly seperated.

		if isLocal {
			contextPermissions := pm.getContextPermissionsForDep(key, matches, resType, string(ambientAuthority))
			if *pm.config.Default == policyDefaultDisallow {
				if !foundLocal {
					foundLocal = true
					// Not allowed by default.
					if !isPermissionAllowed(contextPermissions, req, false) {
						mylog(" . Allowed context: false -", string(ambientAuthority))
						break
					}
				}
			} else {
				if !isPermissionAllowed(contextPermissions, req, true) {
					mylog(" . Allowed context: false -", string(ambientAuthority))
					break
				}
			}
		}

		packageName := getPackageName(curr.Function)
		if currIs3P {
			contextPermissions := pm.getContextPermissionsForDep(key, matches, resType, packageName)
			if !found3P && !prevIs3P {
				directDep = packageName
				mylog(" . Direct dep -", packageName)
			}
			if depsPolicy == policyDefaultDisallow {
				if !found3P && !prevIs3P {
					// Direct dependency.
					found3P = true
					if !isPermissionAllowed(contextPermissions, req, false) {
						mylog(" . Allowed context: false (direct) -", packageName)
						break
					}
				} else {
					// If the req type is not nil, we must honour the user's configuation
					// and consider non-declared entries as not allowed.
					if !isPermissionAllowed(contextPermissions, req, true) {
						mylog(" . Allowed context: false -", packageName)
						break
					}
				}
			} else {
				if !isPermissionAllowed(contextPermissions, req, true) {
					mylog(" . Allowed context: false -", packageName)
					break
				}
			}
		}

		prevIs3P = currIs3P

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
		return pm.violationCb(&Stack{
			DirectPkg: directDep,
			CallerPkg: depName,
			ResType:   resType,
			ResName:   key,
			Access:    req,
			rpcs:      pc,
		})
	}

	return nil
}

func (pm *PermissionsManager) getContextPermissionsForDep(resName string, fmatch permMatches, resType ResourceType, depName string) *Access {
	if pm.config.Permissions == nil {
		return nil
	}
	e, ok := (*pm.config.Permissions)[dependencyName(depName)]
	if !ok {
		if strings.HasPrefix(depName, "github.com/") {
			// Try a subset, github.com/google/go-github/v38/github
			parts := strings.Split(depName, "/")
			if len(parts) < 3 {
				return nil
			}
			e, ok = (*pm.config.Permissions)[dependencyName(strings.Join(parts[:3], "/"))]
		}
		if !ok {
			return nil
		}
	}

	v, ok := e[resType]
	if !ok {
		return nil
	}

	// The user defined no permissions.
	if v.ContextPermissions == nil || len(*v.ContextPermissions) == 0 {
		return nil
	}

	// The user defined some permission for some resources.
	// Entries that do not match are assumed denied.
	r, ok := (*v.ContextPermissions)[resourceName(resName)]
	if !ok {
		// Need to handle globs. Probably need to change function completely
		// to iterate over the perm, instead of returning the Access.
		for kk, vv := range *v.ContextPermissions {
			if fmatch(string(kk), resName) {
				return &vv
			}
		}
		/*if r, ok = (*v.ContextPermissions)["*"]; ok {
			return &r
		}*/
		no := AccessNone
		return &no
	}

	return &r
}

func (pm *PermissionsManager) getDangerousPermissionsForDep(resName string, fmatch permMatches, resType ResourceType, depName string) *Access {
	if pm.config.Permissions == nil {
		return nil
	}
	e, ok := (*pm.config.Permissions)[dependencyName(depName)]
	if !ok {
		if strings.HasPrefix(depName, "github.com/") {
			// Try a subset, github.com/google/go-github/v38/github
			parts := strings.Split(depName, "/")
			if len(parts) < 3 {
				return nil
			}
			e, ok = (*pm.config.Permissions)[dependencyName(strings.Join(parts[:3], "/"))]
		}
		if !ok {
			return nil
		}
	}

	v, ok := e[resType]
	if !ok {
		return nil
	}

	if v.DangerousPermissions == nil || len(*v.DangerousPermissions) == 0 {
		return nil
	}

	r, ok := (*v.DangerousPermissions)[resourceName(resName)]
	if !ok {
		// Need to handle globs. Probably need to change function completely
		// to iterate over the perm, instead of returning the Access.
		// TODO: use arrays.
		for kk, vv := range *v.DangerousPermissions {
			if fmatch(string(kk), resName) {
				return &vv
			}
		}

		// if r, ok = (*v.DangerousPermissions)["*"]; ok {
		// 	return &r
		// }
		no := AccessNone
		return &no
	}
	return &r
}
