//go:build !unix

package browser

import "os"

// defaultStarter is nil outside unix: the pipe needs ExtraFiles, and the
// Windows port-0 transport (ADR 0008 "Windows (A4)") is wired by its own
// Starter. Launch then fails with ErrLaunchFailed.
var defaultStarter Starter

// pidAlive is the default stale-profile probe outside unix: a pid that
// cannot be opened is gone. Anything else counts as alive.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return true
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = p.Release() // probe only
	return true
}
