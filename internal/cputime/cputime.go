// Package cputime measures the CPU time a function consumes. It is a test
// helper and must not be imported by production code. Tests use it to bound
// the work a parser does on hostile input ("refused quickly", "linear
// time") without a tight wall-clock deadline: CPU time does not grow while
// the test waits for a CPU, so a loaded machine (parallel go test binaries,
// other jobs) cannot fail the bound, while a super-linear regression still
// exceeds it by orders of magnitude. A generous wall-clock watchdog (Within,
// Cap) only catches a hang that burns no CPU.
//
// Supported platforms: Linux, other unix (macOS, BSD) and Windows.
//
// On Linux the time is the calling OS thread's: f runs on a goroutine
// locked to its thread, so neither other processes nor other goroutines of
// the test binary are counted. Elsewhere (macOS, BSD, Windows: syscall has
// no per-thread usage there) it is the whole process's, still blind to
// other processes: callers must not run in parallel with other tests (a
// top-level test without t.Parallel runs before every parallel test of its
// package, alone).
package cputime

import (
	"errors"
	"runtime"
	"time"
)

// ThreadLocal reports whether Of counts only the calling thread (Linux)
// rather than the whole process.
const ThreadLocal = threadLocal

// ErrWallTimeout is returned by Within when f is still running after the
// wall-clock watchdog: a hang, not CPU work.
var ErrWallTimeout = errors.New("cputime: still running at the wall-clock watchdog")

// MaxWatchdog is the longest wall-clock watchdog Cap returns.
const MaxWatchdog = 2 * time.Minute

// Of runs f on a goroutine locked to its OS thread and returns the CPU time
// (user plus system) consumed meanwhile. f must not start goroutines whose
// work should be counted.
func Of(f func()) (time.Duration, error) {
	return Within(0, f)
}

// Within is Of with a wall-clock watchdog: when wall > 0 and f has not
// returned after wall, it returns ErrWallTimeout at once and leaves f
// running in the background.
func Within(wall time.Duration, f func()) (time.Duration, error) {
	type result struct {
		d   time.Duration
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		start, err := now()
		if err != nil {
			ch <- result{err: err}
			return
		}
		f()
		end, err := now()
		ch <- result{end - start, err}
	}()
	if wall <= 0 {
		r := <-ch
		return r.d, r.err
	}
	timer := time.NewTimer(wall)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.d, r.err
	case <-timer.C:
		return 0, ErrWallTimeout
	}
}

// Cap returns a wall-clock watchdog for Within: MaxWatchdog, or less when
// the test deadline (t.Deadline) leaves less than that, keeping a tenth of
// the remaining time for the failure report.
func Cap(t interface{ Deadline() (time.Time, bool) }) time.Duration {
	deadline, ok := t.Deadline()
	if !ok {
		return MaxWatchdog
	}
	return capLeft(time.Until(deadline))
}

// capLeft is Cap for a deadline that is left away.
func capLeft(left time.Duration) time.Duration {
	d := MaxWatchdog
	if l := left * 9 / 10; l < d {
		d = l
	}
	if d <= 0 {
		d = time.Millisecond
	}
	return d
}
