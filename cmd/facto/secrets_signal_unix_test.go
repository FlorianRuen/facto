//go:build unix

package main

import (
	"os"
	"syscall"
	"testing"
)

// canRaiseTerm reports that this OS can deliver SIGTERM to the test process.
const canRaiseTerm = true

// raiseTerm sends SIGTERM to the test process. Callers must hold a
// signal.NotifyContext on shutdownSignals(), otherwise the default action
// would kill the test binary.
func raiseTerm(t *testing.T) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Errorf("raise SIGTERM: %v", err)
	}
}
