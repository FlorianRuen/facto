//go:build unix

// Permission tests for package store (J0 task T20). See store_test.go for the
// expected API.
package store_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/store"
)

// setUmask sets the process umask and returns the previous one. A 022 umask
// proves the store sets modes explicitly instead of relying on the user's.
func setUmask(m int) int { return syscall.Umask(m) }

// chmodRaw and mkdirRaw set up deliberately broad modes for negative tests.
func chmodRaw(t *testing.T, p string, m fs.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatalf("setup Chmod(%s): %v", p, err)
	}
}

func mkdirRaw(t *testing.T, p string, m fs.FileMode) {
	t.Helper()
	if err := os.Mkdir(p, m); err != nil {
		t.Fatalf("setup Mkdir(%s): %v", p, err)
	}
	chmodRaw(t, p, m) // Mkdir is subject to umask
}

func modeOf(t *testing.T, p string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", p, err)
	}
	return fi.Mode()
}

// assertPrivateTree checks dir is 0700 and every entry is a 0600 regular file
// or a 0700 directory: this covers index.db and whatever SQLite creates next
// to it (-wal, -shm, -journal).
func assertPrivateTree(t *testing.T, dir string) {
	t.Helper()
	if m := modeOf(t, dir); !m.IsDir() || m.Perm() != 0o700 {
		t.Errorf("%s mode = %v, want drwx------", dir, m)
	}
	err := filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		m := modeOf(t, p)
		switch {
		case m.IsDir():
			if m.Perm() != 0o700 {
				t.Errorf("%s mode = %v, want 0700", p, m.Perm())
			}
		case m.IsRegular():
			if m.Perm() != 0o600 {
				t.Errorf("%s mode = %v, want 0600", p, m.Perm())
			}
		default:
			t.Errorf("%s: unexpected file type %v", p, m.Type())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir(%q): %v", dir, err)
	}
}

func TestOpen_PrivatePerms(t *testing.T) {
	// Not parallel: it changes the process umask.
	old := setUmask(0o022)
	t.Cleanup(func() { setUmask(old) })

	tests := []struct {
		name  string
		setup func(t *testing.T) string // returns the state dir
	}{
		{"creates missing dir", stateDir},
		{"existing private dir", func(t *testing.T) string {
			parent := t.TempDir()
			r, err := fsx.Open(parent)
			if err != nil {
				t.Fatalf("fsx.Open: %v", err)
			}
			defer func() { _ = r.Close() }()
			if err := r.MkdirPrivate("state"); err != nil {
				t.Fatalf("setup: %v", err)
			}
			return filepath.Join(parent, "state")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			dir := tt.setup(t)
			s, err := store.Open(ctx, dir, newClock())
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			t.Cleanup(func() { _ = s.Close() })

			db := filepath.Join(dir, store.FileName)
			if m := modeOf(t, db); m.Perm() != 0o600 {
				t.Errorf("%s mode right after Open = %v, want 0600", store.FileName, m.Perm())
			}
			// Writes make SQLite create its side files (-wal/-shm or -journal).
			for i, d := range []string{"a", "b", "c"} {
				mustInsert(t, s, doc("edf", d, 1, d))
				if i == 1 {
					assertPrivateTree(t, dir) // while the store is open
				}
			}
			if err := fsx.CheckPrivate(dir); err != nil {
				t.Errorf("fsx.CheckPrivate(dir): %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			assertPrivateTree(t, dir)
		})
	}
}

func TestOpen_RefusesBroadPerms(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("state dir group readable", func(t *testing.T) {
		t.Parallel()
		parent := t.TempDir()
		dir := filepath.Join(parent, "state")
		mkdirRaw(t, dir, 0o750)
		s, err := store.Open(ctx, dir, newClock())
		if err == nil {
			_ = s.Close()
		}
		if !errors.Is(err, fsx.ErrInsecurePerms) {
			t.Fatalf("Open: err = %v, want fsx.ErrInsecurePerms", err)
		}
		if _, err := os.Lstat(filepath.Join(dir, store.FileName)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("database created in an insecure dir (Lstat err = %v)", err)
		}
		if m := modeOf(t, dir); m.Perm() != 0o750 {
			t.Errorf("Open silently changed dir mode to %v", m.Perm())
		}
	})

	t.Run("database world readable", func(t *testing.T) {
		t.Parallel()
		dir := stateDir(t)
		s, err := store.Open(ctx, dir, newClock())
		if err != nil {
			t.Fatalf("setup Open: %v", err)
		}
		if _, err := s.Insert(ctx, doc("edf", "x", 1, "x")); err != nil {
			t.Fatalf("setup Insert: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("setup Close: %v", err)
		}
		db := filepath.Join(dir, store.FileName)
		chmodRaw(t, db, 0o644)
		s, err = store.Open(ctx, dir, newClock())
		if err == nil {
			_ = s.Close()
		}
		if !errors.Is(err, fsx.ErrInsecurePerms) {
			t.Fatalf("Open: err = %v, want fsx.ErrInsecurePerms", err)
		}
		if m := modeOf(t, db); m.Perm() != 0o644 {
			t.Errorf("Open silently changed database mode to %v", m.Perm())
		}
	})

	t.Run("database symlink", func(t *testing.T) {
		t.Parallel()
		dir := stateDir(t)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("setup Mkdir: %v", err)
		}
		outside := filepath.Join(t.TempDir(), "elsewhere.db")
		if err := os.Symlink(outside, filepath.Join(dir, store.FileName)); err != nil {
			t.Fatalf("setup Symlink: %v", err)
		}
		s, err := store.Open(ctx, dir, newClock())
		if err == nil {
			_ = s.Close()
			t.Error("Open through a symlinked database: want error")
		}
		if _, err := os.Lstat(outside); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Open created the symlink target outside the state dir (Lstat err = %v)", err)
		}
	})
}
