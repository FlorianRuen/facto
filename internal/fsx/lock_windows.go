//go:build windows

package fsx

import (
	"errors"
	"fmt"
	"math"
	"os"

	"golang.org/x/sys/windows"
)

// tryLockFile takes a non-blocking exclusive LockFileEx on the whole of f.
// The lock belongs to the handle, so two opens of the same file exclude each
// other even inside one process. A held lock returns ErrLocked.
func tryLockFile(f *os.File) error {
	return lockControl(f, func(h windows.Handle) error {
		ol := new(windows.Overlapped)
		err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, math.MaxUint32, math.MaxUint32, ol)
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return ErrLocked
		}
		return err
	})
}

// unlockFile releases the lock taken by tryLockFile.
func unlockFile(f *os.File) error {
	return lockControl(f, func(h windows.Handle) error {
		return windows.UnlockFileEx(h, 0, math.MaxUint32, math.MaxUint32, new(windows.Overlapped))
	})
}

func lockControl(f *os.File, fn func(windows.Handle) error) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return fmt.Errorf("lock file: %w", err)
	}
	var lerr error
	if err := rc.Control(func(fd uintptr) { lerr = fn(windows.Handle(fd)) }); err != nil {
		return fmt.Errorf("lock file: %w", err)
	}
	if errors.Is(lerr, ErrLocked) {
		return ErrLocked
	}
	if lerr != nil {
		return fmt.Errorf("lock file: %w", lerr)
	}
	return nil
}
