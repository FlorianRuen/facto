//go:build linux

package browser

import (
	"errors"
	"syscall"
)

// sysProcAttr puts the browser in its own process group, so teardown kills
// Chrome and every helper it starts, and sets Pdeathsig as a backstop for
// a SIGKILLed facto, where no teardown code runs.
//
// Pdeathsig fires when the thread that forked the browser exits, not the
// process: startCmd forks from a locked thread kept parked until the
// browser is reaped, so the runtime cannot end that thread early. It is a
// backstop, not the teardown mechanism.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

// pPID is P_PID of waitid(2): wait for the one child named by id.
const pPID = 1

// awaitExit blocks until the child pid has exited, without reaping it
// (waitid WEXITED|WNOWAIT, Linux accepts a nil siginfo), and reports true.
// It reports false if waitid fails for another reason than EINTR; the
// caller then reaps first.
func awaitExit(pid int) bool {
	for {
		_, _, e := syscall.Syscall6(syscall.SYS_WAITID, pPID, uintptr(pid), 0,
			syscall.WEXITED|syscall.WNOWAIT, 0, 0)
		if e == 0 {
			return true
		}
		if !errors.Is(e, syscall.EINTR) {
			return false
		}
	}
}
