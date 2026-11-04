//go:build !windows

// A symlink planted at the lock name between the Lstat check and the open
// must not be followed to create its target (os.Root ignores O_NOFOLLOW, so
// the open uses O_CREATE|O_EXCL first). The test swaps the package-level
// openLockHook, so it is NOT parallel.
package fsx

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestLock_SymlinkPlantedAfterLstatNotFollowed(t *testing.T) {
	r, dir := privateRoot(t)
	calls := 0
	setHook(t, &openLockHook, func() {
		calls++
		if err := os.Symlink("target", filepath.Join(dir, "edf.lock")); err != nil {
			t.Errorf("plant symlink: %v", err)
		}
	})
	l, err := r.Lock(t.Context(), "edf.lock")
	if calls != 1 {
		t.Fatalf("openLockHook called %d times, want 1", calls)
	}
	if err == nil {
		_ = l.Close()
		t.Fatal("Lock succeeded through a symlink planted after Lstat")
	}
	if _, err := os.Lstat(filepath.Join(dir, "target")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("symlink target created through the lock open (lstat err = %v)", err)
	}
}
