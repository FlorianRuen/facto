//go:build !unix && !windows

package browser

import "os"

// defaultStarter is nil outside unix and windows: the pipe needs
// ExtraFiles, and the port-0 transport (ADR 0008 "Windows (A4)") is wired on
// windows only. Launch then fails with ErrLaunchFailed.
var defaultStarter Starter

// pidAlive is the default stale-profile probe outside unix and windows: a pid that
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
