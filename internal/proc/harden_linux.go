//go:build linux

package proc

import (
	"fmt"
	"syscall"
)

// prSetDumpable is PR_SET_DUMPABLE from <linux/prctl.h>; syscall has no name
// for it.
const prSetDumpable = 4

// Harden sets RLIMIT_CORE soft and hard limits to 0, so the process cannot
// raise them again, and clears the dumpable flag. It is idempotent.
func Harden() error {
	return harden(syscall.Setrlimit, clearDumpable)
}

func clearDumpable() error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE): %w", errno)
	}
	return nil
}

// harden is Harden with the system calls injected, so tests can cover the
// error paths without changing the test process itself.
func harden(setrlimit func(int, *syscall.Rlimit) error, undump func() error) error {
	if err := setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	if err := undump(); err != nil {
		return fmt.Errorf("clear dumpable flag: %w", err)
	}
	return nil
}
