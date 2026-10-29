//go:build unix && !linux

package browser

import "syscall"

// sysProcAttr puts the browser in its own process group, so teardown kills
// Chrome and every helper it starts. There is no Pdeathsig here: a
// SIGKILLed facto leaves a browser that ignores pipe EOF running (the macOS
// parent-death gap recorded in ADR 0008).
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// awaitExit reports false: there is no portable wait-without-reap here, so
// the browser is reaped first and its leftovers killed just after (see
// PipeProcess.wait for the residual risk).
func awaitExit(int) bool { return false }
