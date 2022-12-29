package permissions

import (
	"hooks"
	"io/fs"
	"os"
	"strings"
	"time"
)

type hookManager struct {
	permissionsManager *PermissionsManager
}

var manager hookManager

// Temp for printing.
var (
	Times   [5000]int64
	Times_c = 0
)

func NewHookManager(pm *PermissionsManager) (*hookManager, error) {
	// TODO: check error.
	hooks.SetManager(&manager)
	manager.permissionsManager = pm
	return &manager, nil
}

func envMatches(val, req string) bool {
	return val == "*" || val == req
}

func fsMatches(val, req string) bool {
	// /etc/ssl/certs/* /etc/ssl/certs
	// TODO: this function needs proper testing.
	if val == "*" {
		return true
	}

	if strings.HasSuffix(val, "*") {
		val = val[:len(val)-1]
	}

	// WARNING: do not remove the `/`.
	if req == val {
		return true
	}

	if val[len(val)-1] != os.PathSeparator {
		val += string(os.PathSeparator)
	}
	if strings.HasPrefix(req, val) {
		return true
	}

	if req[len(req)-1] != os.PathSeparator {
		req += string(os.PathSeparator)
	}
	return strings.HasPrefix(req, val)
	// match, err := filepath.Match(val, req)
	// if err != nil {
	// 	// we are conservative
	// 	return true
	// }
}

func (hm *hookManager) Getenv(key string) error {
	mylog("Getenv(%s)\n", key)
	// mylog("stack info:")
	start := time.Now()

	if err := hm.permissionsManager.OnAccess(key, envMatches, ResourceTypeEnv, AccessRead); err != nil {
		return err
	}

	elapsed := time.Since(start)
	Times[Times_c] = elapsed.Nanoseconds()
	Times_c++
	mylog("perm check took ", string(elapsed.Nanoseconds()))

	return nil
}

func (hm *hookManager) Environ() error {
	// disabled for testing
	// return
	mylog("Environ()\n")
	start := time.Now()

	if err := hm.permissionsManager.OnAccess("*", envMatches, ResourceTypeEnv, AccessRead); err != nil {
		return err
	}

	elapsed := time.Since(start)
	Times[Times_c] = elapsed.Nanoseconds()
	Times_c++
	mylog("perm check took ", string(elapsed.Nanoseconds()))

	return nil
}

func (hm *hookManager) Open(file string, flag int, perms fs.FileMode) error {
	// disabled
	// return
	mylog("Open(%s)\n", file)
	start := time.Now()

	// TODO: Do this properly.
	if err := hm.permissionsManager.OnAccess(file, fsMatches, ResourceTypeFs, AccessRead); err != nil {
		return err
	}

	elapsed := time.Since(start)
	Times[Times_c] = elapsed.Nanoseconds()
	Times_c++
	mylog("perm check took ", string(elapsed.Nanoseconds()))

	return nil
}
