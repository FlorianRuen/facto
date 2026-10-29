// Tests for package proc (J0 task T26, process hardening).
//
// Expected API (package github.com/FlorianRuen/facto/internal/proc):
//
//	// Harden makes the current process resistant to memory disclosure
//	// through crash artifacts. On Linux it sets RLIMIT_CORE to 0 (soft and
//	// hard, so it cannot be raised again) and PR_SET_DUMPABLE to 0, using
//	// only the standard library syscall package. On every other OS it is a
//	// no-op returning nil. It is idempotent and is called once from run.
//	func Harden() error
//
// PR_SET_DUMPABLE and the hard RLIMIT_CORE are process-wide and irreversible,
// so the Linux test re-executes the test binary and calls Harden only in
// the child process.
package proc_test
