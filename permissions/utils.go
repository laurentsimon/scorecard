package permissions

import "strings"

// TODO: get dynamically at load time.
var compilerPath = "/usr/local/google/home/laurentsimon/sandboxing/golang/go/"

// TODO: unit tests.
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

/*func isContextPermissionAllowed(m map[string]permission, depName string) bool {
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
}*/

func isRuntime(filename string) bool {
	return strings.HasPrefix(filename, compilerPath) ||
		strings.Contains(filename, "/golang.org/")
}

// TODO: fix with StartsWith and query once to learn the path.
// TODO: account for the permission manager package.
func isExternalDependency(filename string) bool {
	return !isRuntime(filename) && strings.Contains(filename, "/pkg/mod/")
}

func isPermissionAllowed(def *Access, req Access, defValue bool) bool {
	if def != nil {
		return (*def & req) != AccessNone
	}
	return defValue
}
