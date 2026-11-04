package cputime

import (
	"fmt"
	"syscall"
	"time"
)

const threadLocal = true

// rusageThread is RUSAGE_THREAD (getrusage(2)), not exported by syscall.
const rusageThread = 1

// now returns the user plus system CPU time of the calling OS thread.
func now() (time.Duration, error) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(rusageThread, &ru); err != nil {
		return 0, fmt.Errorf("getrusage(RUSAGE_THREAD): %w", err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano()), nil
}
