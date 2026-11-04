//go:build unix && !linux

package cputime

import (
	"fmt"
	"syscall"
	"time"
)

const threadLocal = false

// now returns the user plus system CPU time of the whole process: syscall
// exposes no per-thread usage outside Linux.
func now() (time.Duration, error) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, fmt.Errorf("getrusage(RUSAGE_SELF): %w", err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano()), nil
}
