//go:build unix && !linux

package browser_test

import (
	"errors"
	"syscall"
)

// processGone reports whether pid no longer exists. A zombie counts as
// alive here; the pipe tests reap their own browser and grandchildren are
// reaped by init.
func processGone(pid int) bool {
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}
