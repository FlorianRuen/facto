//go:build unix

package fsx_test

import (
	"io/fs"
	"path/filepath"
	"testing"
)

func TestLstat_Symlinks(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	outside := t.TempDir()
	mustWriteRaw(t, filepath.Join(outside, "victim.pdf"), []byte("outside"), 0o600)
	mustSymlink(t, filepath.Join(outside, "victim.pdf"), filepath.Join(dir, "link.pdf"))
	mustSymlink(t, outside, filepath.Join(dir, "esc"))

	fi, err := r.Lstat("link.pdf")
	if err != nil {
		t.Fatalf("Lstat(final symlink): %v", err)
	}
	if fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("Lstat(final symlink) mode = %v, want a symlink (not followed)", fi.Mode())
	}
	if fi, err := r.Lstat("esc/victim.pdf"); err == nil {
		t.Fatalf("Lstat through an escaping dir symlink = %v, want an error", fi.Mode())
	}
}
