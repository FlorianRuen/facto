//go:build !windows

package fsx

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// tryLockFile takes a non-blocking exclusive flock on f. flock locks belong
// to the open file description, so two opens of the same file exclude each
// other even inside one process. A held lock returns ErrLocked.
func tryLockFile(f *os.File) error {
	return flock(f, unix.LOCK_EX|unix.LOCK_NB)
}

// unlockFile releases the flock on f.
func unlockFile(f *os.File) error {
	return flock(f, unix.LOCK_UN)
}

func flock(f *os.File, how int) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return fmt.Errorf("flock: %w", err)
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) {
		for {
			ferr = unix.Flock(int(fd), how)
			if !errors.Is(ferr, unix.EINTR) {
				return
			}
		}
	}); err != nil {
		return fmt.Errorf("flock: %w", err)
	}
	if errors.Is(ferr, unix.EWOULDBLOCK) {
		return ErrLocked
	}
	if ferr != nil {
		return fmt.Errorf("flock: %w", ferr)
	}
	return nil
}
