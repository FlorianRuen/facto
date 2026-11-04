// Tests for the fsx exclusive lock (J1 T16, ADR 0009 "Rotation" step 0: the
// session store holds sessions/<id>.lock around key Set and file write so a
// scheduled collect and a manual login never interleave).
//
// Expected API (package fsx):
//
//	// ErrLocked reports that TryLock found the lock held by another holder
//	// (another goroutine or another process).
//	var ErrLocked = errors.New("fsx: locked")
//
//	// Lock is a held exclusive lock. Close releases it; Close is idempotent
//	// (a second Close returns nil). The lock file is left in place.
//	type Lock struct{ /* unexported */ }
//	func (l *Lock) Close() error
//
//	// Lock takes an exclusive advisory lock on name (relative to the root,
//	// same name rules as WriteAtomic: ErrInvalidName for empty, absolute or
//	// escaping names). The lock file is created 0600 if missing and never
//	// written: it holds no data. An existing lock file with group/world bits
//	// is refused with ErrInsecurePerms; anything but a regular file
//	// (symlink, directory, FIFO) is refused with ErrNotRegular. The lock is
//	// per open file description (flock on unix, LockFileEx on Windows), so
//	// two Lock calls exclude each other even from the same process and the
//	// same Root. Lock blocks until the lock is acquired or ctx is done (the
//	// error then wraps ctx.Err()). The parent directory must exist.
//	func (r *Root) Lock(ctx context.Context, name string) (*Lock, error)
//
//	// TryLock is Lock without waiting: a held lock returns ErrLocked.
//	func (r *Root) TryLock(name string) (*Lock, error)
package fsx_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/fsx"
)

func mustLock(t *testing.T, r *fsx.Root, name string) *fsx.Lock {
	t.Helper()
	l, err := r.Lock(t.Context(), name)
	if err != nil {
		t.Fatalf("Lock(%q): %v", name, err)
	}
	return l
}

func TestLock_ExclusiveAcrossGoroutines(t *testing.T) {
	t.Parallel()

	t.Run("TryLock refused while held, from the same and another Root", func(t *testing.T) {
		t.Parallel()
		r, dir := openRoot(t)
		other, err := fsx.Open(dir)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { _ = other.Close() })

		held := mustLock(t, r, "edf.lock")
		defer func() { _ = held.Close() }()
		for name, root := range map[string]*fsx.Root{"same root": r, "other root": other} {
			l, err := root.TryLock("edf.lock")
			if !errors.Is(err, fsx.ErrLocked) {
				if l != nil {
					_ = l.Close()
				}
				t.Fatalf("%s: TryLock on a held lock: err = %v, want ErrLocked", name, err)
			}
		}
		// Another name is an independent lock.
		l, err := r.TryLock("ileo.lock")
		if err != nil {
			t.Fatalf("TryLock(ileo.lock) while edf.lock is held: %v", err)
		}
		_ = l.Close()
	})

	t.Run("blocking Lock waits for the holder and honours ctx", func(t *testing.T) {
		t.Parallel()
		r, _ := openRoot(t)
		held := mustLock(t, r, "ileo.lock")

		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		l, err := r.Lock(ctx, "ileo.lock")
		if !errors.Is(err, context.DeadlineExceeded) {
			if l != nil {
				_ = l.Close()
			}
			t.Fatalf("Lock while held: err = %v, want context.DeadlineExceeded", err)
		}

		acquired := make(chan *fsx.Lock)
		errc := make(chan error, 1)
		go func() {
			l, err := r.Lock(t.Context(), "ileo.lock")
			if err != nil {
				errc <- err
				return
			}
			acquired <- l
		}()
		if err := held.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		select {
		case l := <-acquired:
			_ = l.Close()
		case err := <-errc:
			t.Fatalf("Lock after release: %v", err)
		}
	})

	t.Run("critical sections never overlap", func(t *testing.T) {
		t.Parallel()
		r, _ := openRoot(t)
		const workers, rounds = 8, 20
		var inside, overlaps atomic.Int32
		var wg sync.WaitGroup
		errc := make(chan error, workers)
		for range workers {
			wg.Go(func() {
				for range rounds {
					l, err := r.Lock(t.Context(), "edf.lock")
					if err != nil {
						errc <- err
						return
					}
					if inside.Add(1) != 1 {
						overlaps.Add(1)
					}
					inside.Add(-1)
					if err := l.Close(); err != nil {
						errc <- err
						return
					}
				}
			})
		}
		wg.Wait()
		close(errc)
		for err := range errc {
			t.Fatalf("Lock/Close: %v", err)
		}
		if n := overlaps.Load(); n != 0 {
			t.Fatalf("%d overlapping critical sections under an exclusive lock", n)
		}
	})
}

func TestLock_ReleasedOnClose(t *testing.T) {
	t.Parallel()
	r, dir := openRoot(t)

	l := mustLock(t, r, "edf.lock")
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v, want nil (idempotent)", err)
	}
	again, err := r.TryLock("edf.lock")
	if err != nil {
		t.Fatalf("TryLock after Close: %v", err)
	}
	if err := again.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// The lock file stays (it holds no data); only the lock is released.
	if got := entries(t, dir); len(got) != 1 || got[0] != "edf.lock" {
		t.Fatalf("dir entries after release = %v, want [edf.lock]", got)
	}
}

func TestLock_RejectsInvalidNames(t *testing.T) {
	t.Parallel()
	r, dir := openRoot(t)
	for _, name := range []string{"", ".", "/abs.lock", "../escape.lock", "a/../../escape.lock", "nul\x00.lock"} {
		l, err := r.Lock(t.Context(), name)
		if !errors.Is(err, fsx.ErrInvalidName) {
			if l != nil {
				_ = l.Close()
			}
			t.Errorf("Lock(%q): err = %v, want ErrInvalidName", name, err)
		}
		l, err = r.TryLock(name)
		if !errors.Is(err, fsx.ErrInvalidName) {
			if l != nil {
				_ = l.Close()
			}
			t.Errorf("TryLock(%q): err = %v, want ErrInvalidName", name, err)
		}
	}
	if got := entries(t, dir); len(got) != 0 {
		t.Fatalf("invalid names created %v", got)
	}
}
