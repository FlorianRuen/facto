package fsx_test

// Root.MkdirNew (J1 T23 review): an exclusive 0700 mkdir of one component,
// so a caller picking a name (browser pool areas) never reuses a directory
// that already exists.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

func TestMkdirNew(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := r.MkdirNew("a"); err != nil {
		t.Fatalf("MkdirNew: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(dir, "a"))
	if err != nil || !fi.IsDir() {
		t.Fatalf("a: %v, %v", fi, err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700 {
		t.Errorf("mode %#o, want 0700", fi.Mode().Perm())
	}
	if err := r.MkdirNew("a"); !errors.Is(err, fs.ErrExist) {
		t.Errorf("MkdirNew on an existing dir = %v, want fs.ErrExist", err)
	}
	if err := os.Symlink(dir, filepath.Join(dir, "l")); err == nil {
		if err := r.MkdirNew("l"); !errors.Is(err, fs.ErrExist) {
			t.Errorf("MkdirNew on a symlink = %v, want fs.ErrExist", err)
		}
	}
	for _, bad := range []string{"", ".", "..", "x/y", "/abs"} {
		if err := r.MkdirNew(bad); err == nil {
			t.Errorf("MkdirNew(%q) = nil, want an error", bad)
		}
	}
}
