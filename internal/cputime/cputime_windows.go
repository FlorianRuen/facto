package cputime

import (
	"fmt"
	"syscall"
	"time"
)

const threadLocal = false

// now returns the user plus kernel CPU time of the whole process: syscall
// exposes GetProcessTimes but not GetThreadTimes.
func now() (time.Duration, error) {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, fmt.Errorf("GetCurrentProcess: %w", err)
	}
	var creation, exit, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return 0, fmt.Errorf("GetProcessTimes: %w", err)
	}
	return time.Duration(ticks(kernel)+ticks(user)) * 100, nil // 100 ns ticks
}

func ticks(ft syscall.Filetime) int64 {
	return int64(ft.HighDateTime)<<32 | int64(ft.LowDateTime)
}
