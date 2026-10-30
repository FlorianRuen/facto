//go:build unix

package fsx_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

func TestRename_MovesFilesAndDirectories(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	mustMkdir(t, r, "stage/sub")
	if err := r.WriteAtomic(t.Context(), "stage/sub/f", []byte("content")); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	if err := r.Rename("stage", "final"); err != nil {
		t.Fatalf("Rename(dir): %v", err)
	}
	if got := string(readFile(t, filepath.Join(dir, "final", "sub", "f"))); got != "content" {
		t.Fatalf("moved content = %q", got)
	}
	if err := r.Rename("final/sub/f", "g"); err != nil {
		t.Fatalf("Rename(file): %v", err)
	}
	if got := entries(t, dir); !slices.Equal(got, []string{"final", "g"}) {
		t.Fatalf("entries = %v, want [final g]", got)
	}
}

func TestRename_NeverReplaces(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{name: "existing file", setup: func(t *testing.T, dir string) {
			mustWriteRaw(t, filepath.Join(dir, "dst"), []byte("keep"), 0o600)
		}},
		{name: "existing empty directory", setup: func(t *testing.T, dir string) {
			mustMkdirRaw(t, filepath.Join(dir, "dst"), 0o700)
		}},
		{name: "dangling symlink", setup: func(t *testing.T, dir string) {
			mustSymlink(t, filepath.Join(dir, "missing"), filepath.Join(dir, "dst"))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, dir := openRoot(t)
			mustWriteRaw(t, filepath.Join(dir, "src"), []byte("new"), 0o600)
			tt.setup(t, dir)
			before := entries(t, dir)
			if err := r.Rename("src", "dst"); !errors.Is(err, fs.ErrExist) {
				t.Fatalf("Rename = %v, want errors.Is fs.ErrExist", err)
			}
			if got := entries(t, dir); !slices.Equal(got, before) {
				t.Fatalf("entries = %v, want %v", got, before)
			}
			if got := string(readFile(t, filepath.Join(dir, "src"))); got != "new" {
				t.Fatalf("src = %q, want untouched", got)
			}
		})
	}
}

func TestRename_RefusesBadNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, from, to string
		want           error
	}{
		{name: "escaping source", from: "../x", to: "y", want: fsx.ErrInvalidName},
		{name: "escaping target", from: "src", to: "../y", want: fsx.ErrInvalidName},
		{name: "absolute target", from: "src", to: "/tmp/y", want: fsx.ErrInvalidName},
		{name: "empty target", from: "src", to: "", want: fsx.ErrInvalidName},
		{name: "missing source", from: "missing", to: "y", want: fs.ErrNotExist},
		{name: "missing target parent", from: "src", to: "nodir/y", want: fs.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, dir := openRoot(t)
			mustWriteRaw(t, filepath.Join(dir, "src"), []byte("x"), 0o600)
			if err := r.Rename(tt.from, tt.to); !errors.Is(err, tt.want) {
				t.Fatalf("Rename(%q, %q) = %v, want errors.Is %v", tt.from, tt.to, err, tt.want)
			}
			if _, err := os.Lstat(filepath.Join(dir, "src")); err != nil {
				t.Fatalf("src moved or removed: %v", err)
			}
		})
	}
}

func TestRename_TargetParentSymlinkOutsideRefused(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	mustMkdirRaw(t, root, 0o700)
	mustMkdirRaw(t, outside, 0o700)
	mustWriteRaw(t, filepath.Join(root, "src"), []byte("x"), 0o600)
	mustSymlink(t, outside, filepath.Join(root, "esc"))
	r, err := fsx.Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if err := r.Rename("src", "esc/src"); err == nil {
		t.Fatal("Rename through a symlink leaving the root succeeded")
	}
	if got := entries(t, outside); len(got) != 0 {
		t.Fatalf("outside holds %v, want nothing", got)
	}
}
