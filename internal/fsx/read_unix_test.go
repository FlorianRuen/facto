//go:build unix

package fsx_test

import (
	"io/fs"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/fsx"
)

// TestReadAccess_NeverFollowsSymlinks: a final symlink is refused even when
// it points inside the root, and listed as a symlink by ReadDir.
func TestReadAccess_NeverFollowsSymlinks(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	mustMkdir(t, r, "d")
	mustAtomic(t, r, "d/f.pdf")
	outside := t.TempDir()
	mustWriteRaw(t, filepath.Join(outside, "victim.pdf"), []byte("outside"), 0o600)
	mustSymlink(t, filepath.Join(outside, "victim.pdf"), filepath.Join(dir, "out.pdf"))
	mustSymlink(t, "d/f.pdf", filepath.Join(dir, "in.pdf"))
	mustSymlink(t, "missing", filepath.Join(dir, "dangling.pdf"))
	mustSymlink(t, outside, filepath.Join(dir, "outdir"))
	mustSymlink(t, "d", filepath.Join(dir, "indir"))

	des, err := r.ReadDir()
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, de := range des {
		if de.Name() == "d" {
			continue
		}
		if de.Type()&fs.ModeSymlink == 0 {
			t.Errorf("ReadDir: %s type = %v, want a symlink", de.Name(), de.Type())
		}
	}

	for _, name := range []string{"out.pdf", "in.pdf", "dangling.pdf", "outdir", "indir"} {
		if f, err := r.OpenRegular(name); err == nil {
			_ = f.Close()
			t.Errorf("OpenRegular(%q) followed a symlink", name)
		} else {
			checkErr(t, "OpenRegular "+name, err, fsx.ErrNotRegular)
		}
		if sub, err := r.OpenDir(name); err == nil {
			_ = sub.Close()
			t.Errorf("OpenDir(%q) followed a symlink", name)
		} else {
			checkErr(t, "OpenDir "+name, err, fsx.ErrNotDir)
		}
	}
}

// TestOpenRegular_RefusesFIFOWithoutBlocking: a FIFO is refused, never opened.
func TestOpenRegular_RefusesFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.pdf"), 0o600); err != nil {
		t.Fatalf("setup Mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := r.OpenRegular("pipe.pdf")
		if err == nil {
			_ = f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		checkErr(t, "OpenRegular(fifo)", err, fsx.ErrNotRegular)
	case <-time.After(2 * time.Second):
		t.Fatal("OpenRegular on a FIFO blocked")
	}
}
