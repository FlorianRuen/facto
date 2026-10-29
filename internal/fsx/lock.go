package fsx

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"
)

// ErrLocked reports that TryLock found the lock held by another holder
// (another goroutine or another process).
var ErrLocked = errors.New("fsx: locked")

// Polling bounds for a blocking Lock. The OS calls used (flock, LockFileEx)
// cannot be interrupted by a context, so Lock retries a non-blocking attempt
// with a capped exponential backoff until ctx is done.
const (
	lockPollFirst = time.Millisecond
	lockPollCap   = 50 * time.Millisecond
)

// openLockHook runs between the Lstat check and the open in openLockFile.
// No-op in production; internal tests replace it to plant an entry in that
// window.
var openLockHook = func() {}

// Lock is a held exclusive advisory lock on a file. Close releases it; the
// lock file is left in place. Safe for concurrent use.
type Lock struct {
	mu sync.Mutex
	f  *os.File
}

// Close releases the lock and closes the lock file. It is idempotent: a
// second Close returns nil.
func (l *Lock) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	uerr := unlockFile(f)
	if err := f.Close(); err != nil {
		return fmt.Errorf("fsx unlock: close: %w", err)
	}
	if uerr != nil {
		return fmt.Errorf("fsx unlock: %w", uerr)
	}
	return nil
}

// Lock takes an exclusive advisory lock on name (relative to the root, same
// name rules as WriteAtomic: ErrInvalidName for empty, absolute or escaping
// names). The lock file is created 0600 if missing and never written: it
// holds no data. An existing lock file with group/world bits is refused with
// ErrInsecurePerms; anything but a regular file (symlink, directory, FIFO) is
// refused with ErrNotRegular. The lock is per open file description (flock on
// unix, LockFileEx on Windows), so two Lock calls exclude each other even from
// the same process and the same Root. Lock blocks until the lock is acquired
// or ctx is done (the error then wraps ctx.Err()). The parent directory must
// exist.
func (r *Root) Lock(ctx context.Context, name string) (*Lock, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("fsx lock %q: %w", name, err)
	}
	f, err := r.openLockFile(name)
	if err != nil {
		return nil, err
	}
	delay := lockPollFirst
	for {
		err := tryLockFile(f)
		if err == nil {
			return &Lock{f: f}, nil
		}
		if !errors.Is(err, ErrLocked) {
			_ = f.Close() // the lock error is the one reported
			return nil, fmt.Errorf("fsx lock %q: %w", name, err)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = f.Close() // nothing was locked; the ctx error is the one reported
			return nil, fmt.Errorf("fsx lock %q: %w", name, ctx.Err())
		case <-timer.C:
		}
		delay = min(2*delay, lockPollCap)
	}
}

// TryLock is Lock without waiting: a held lock returns an error wrapping
// ErrLocked.
func (r *Root) TryLock(name string) (*Lock, error) {
	f, err := r.openLockFile(name)
	if err != nil {
		return nil, err
	}
	if err := tryLockFile(f); err != nil {
		_ = f.Close() // the lock error is the one reported
		return nil, fmt.Errorf("fsx try lock %q: %w", name, err)
	}
	return &Lock{f: f}, nil
}

// openLockFile opens name for locking, creating it 0600 if missing. Before
// the open, an existing entry must be a private regular file; after it, the
// opened file must be the very regular file now at name, so a symlink or a
// swap between the two steps is refused. A symlink planted after the check
// is never followed to create its target (O_CREATE|O_EXCL, see below).
func (r *Root) openLockFile(name string) (*os.File, error) {
	osName, err := cleanName(name)
	if err != nil {
		return nil, err
	}
	li, err := r.root.Lstat(osName)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("fsx lock %q: %w", name, err)
	default:
		if err := checkLockFile(name, li); err != nil {
			return nil, err
		}
	}
	openLockHook()
	// os.Root ignores a caller's O_NOFOLLOW: it opens every component with
	// O_NOFOLLOW itself and then resolves in-root symlinks on its own, so a
	// symlink planted at name after the Lstat would be followed and its
	// target created. O_CREATE|O_EXCL is the one mode os.Root never follows
	// (on every OS); only when name already exists is it opened without
	// O_CREATE, which creates nothing and changes nothing, and the identity
	// check below then refuses anything that is not that regular file.
	f, err := r.root.OpenFile(osName, os.O_RDWR|os.O_CREATE|os.O_EXCL|nonBlock, filePerm)
	if errors.Is(err, fs.ErrExist) {
		f, err = r.root.OpenFile(osName, os.O_RDWR|nonBlock, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("fsx lock %q: %w", name, err)
	}
	fi, err := f.Stat()
	if err == nil {
		err = checkLockFile(name, fi)
	}
	if err == nil {
		li, err = r.root.Lstat(osName)
		if err == nil && !os.SameFile(li, fi) {
			err = fmt.Errorf("fsx lock %q: replaced while opening: %w", name, ErrNotRegular)
		}
	}
	if err != nil {
		_ = f.Close() // nothing was locked; the check error is the one reported
		return nil, fmt.Errorf("fsx lock %q: %w", name, err)
	}
	return f, nil
}

// checkLockFile refuses anything but a private regular file.
func checkLockFile(name string, fi fs.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("fsx lock %q: mode %v: %w", name, fi.Mode().Type(), ErrNotRegular)
	}
	if insecure(fi.Mode()) {
		return fmt.Errorf("fsx lock %q: mode %#o: %w", name, fi.Mode().Perm(), ErrInsecurePerms)
	}
	return nil
}
