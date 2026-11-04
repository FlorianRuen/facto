//go:build unix

// Permission and file-type tests for the fsx lock (J1 T16). See lock_test.go
// for the expected API.
package fsx_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

func TestLock_FilePrivate(t *testing.T) {
	t.Parallel()

	t.Run("created 0600 and empty", func(t *testing.T) {
		t.Parallel()
		r, dir := openRoot(t)
		l := mustLock(t, r, "edf.lock")
		defer func() { _ = l.Close() }()
		p := filepath.Join(dir, "edf.lock")
		if got := perm(t, p); got != 0o600 {
			t.Fatalf("lock file mode = %#o, want 0600", got)
		}
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatalf("Lstat: %v", err)
		}
		if !fi.Mode().IsRegular() || fi.Size() != 0 {
			t.Fatalf("lock file: mode %v size %d, want an empty regular file", fi.Mode(), fi.Size())
		}
	})

	t.Run("existing group-readable lock file refused", func(t *testing.T) {
		t.Parallel()
		r, dir := openRoot(t)
		p := filepath.Join(dir, "edf.lock")
		mustWriteRaw(t, p, nil, 0o644)
		l, err := r.Lock(t.Context(), "edf.lock")
		if !errors.Is(err, fsx.ErrInsecurePerms) {
			if l != nil {
				_ = l.Close()
			}
			t.Fatalf("Lock on a 0644 lock file: err = %v, want ErrInsecurePerms", err)
		}
		if got := perm(t, p); got != 0o644 {
			t.Fatalf("refused lock file mode changed to %#o", got)
		}
	})

	t.Run("symlink and directory refused", func(t *testing.T) {
		t.Parallel()
		r, dir := openRoot(t)
		outside := filepath.Join(t.TempDir(), "victim")
		mustWriteRaw(t, outside, []byte("synthetic victim"), 0o600)
		mustSymlink(t, outside, filepath.Join(dir, "link.lock"))
		mustSymlink(t, "inside", filepath.Join(dir, "inner.lock"))
		mustWriteRaw(t, filepath.Join(dir, "inside"), nil, 0o600)
		mustMkdirRaw(t, filepath.Join(dir, "dir.lock"), 0o700)

		for _, name := range []string{"link.lock", "inner.lock", "dir.lock"} {
			l, err := r.Lock(t.Context(), name)
			if err == nil {
				_ = l.Close()
				t.Errorf("Lock(%q) accepted a non-regular lock file", name)
				continue
			}
			if !errors.Is(err, fsx.ErrNotRegular) {
				t.Errorf("Lock(%q): err = %v, want ErrNotRegular", name, err)
			}
		}
		if got := readFile(t, outside); string(got) != "synthetic victim" {
			t.Fatalf("symlink target modified: %q", got)
		}
	})
}

// TestLock_FilePrivateUnderUmask0 is a separate, non-parallel test: umask is
// process-wide.
func TestLock_FilePrivateUnderUmask0(t *testing.T) {
	r, dir := openRoot(t)
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	l := mustLock(t, r, "edf.lock")
	defer func() { _ = l.Close() }()
	if got := perm(t, filepath.Join(dir, "edf.lock")); got != 0o600 {
		t.Fatalf("lock file mode with umask 0 = %#o, want 0600", got)
	}
}
