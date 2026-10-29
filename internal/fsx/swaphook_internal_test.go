// Identity-check tests for OpenDir and OpenRegular: an entry swapped between
// the Lstat and the open must be refused (os.SameFile). The swap is done in
// the test hooks openDirHook / openRegularHook, called exactly in that
// window. These tests swap package-level hooks, so they are NOT parallel and
// restore them with t.Cleanup.
package fsx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func setHook(t *testing.T, hook *func(), f func()) {
	t.Helper()
	prev := *hook
	*hook = f
	t.Cleanup(func() { *hook = prev })
}

// swap moves dir/name aside and puts dir/other in its place.
func swap(t *testing.T, dir, name, other string) {
	t.Helper()
	if err := os.Rename(filepath.Join(dir, name), filepath.Join(dir, name+".old")); err != nil {
		t.Errorf("swap: %v", err)
		return
	}
	if err := os.Rename(filepath.Join(dir, other), filepath.Join(dir, name)); err != nil {
		t.Errorf("swap: %v", err)
	}
}

func TestOpenDir_RefusesDirSwappedAfterLstat(t *testing.T) {
	r, dir := privateRoot(t)
	if err := os.Mkdir(filepath.Join(dir, "other"), 0o700); err != nil {
		t.Fatal(err)
	}
	calls := 0
	setHook(t, &openDirHook, func() {
		calls++
		swap(t, dir, "sub", "other")
	})

	sub, err := r.OpenDir("sub")
	if calls != 1 {
		t.Fatalf("openDirHook called %d times, want 1", calls)
	}
	if err == nil {
		_ = sub.Close()
		t.Fatal("OpenDir succeeded on a directory swapped after Lstat, want ErrNotDir")
	}
	if !errors.Is(err, ErrNotDir) {
		t.Fatalf("OpenDir error = %v, want ErrNotDir", err)
	}
}

func TestOpenDir_UnswappedStillOpens(t *testing.T) {
	r, _ := privateRoot(t)
	calls := 0
	setHook(t, &openDirHook, func() { calls++ })
	sub, err := r.OpenDir("sub")
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	_ = sub.Close()
	if calls != 1 {
		t.Errorf("openDirHook called %d times, want 1", calls)
	}
}

func TestOpenRegular_RefusesFileSwappedAfterLstat(t *testing.T) {
	r, dir := privateRoot(t)
	// Both are regular files: only the identity check can tell them apart.
	if err := os.WriteFile(filepath.Join(dir, "a.pdf"), []byte("scanned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.pdf"), []byte("swapped"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	setHook(t, &openRegularHook, func() {
		calls++
		swap(t, dir, "a.pdf", "b.pdf")
	})

	f, err := r.OpenRegular("a.pdf")
	if calls != 1 {
		t.Fatalf("openRegularHook called %d times, want 1", calls)
	}
	if err == nil {
		_ = f.Close()
		t.Fatal("OpenRegular succeeded on a file swapped after Lstat, want ErrNotRegular")
	}
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("OpenRegular error = %v, want ErrNotRegular", err)
	}
}

func TestOpenRegular_UnswappedStillOpens(t *testing.T) {
	r, dir := privateRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "a.pdf"), []byte("scanned"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	setHook(t, &openRegularHook, func() { calls++ })
	f, err := r.OpenRegular("a.pdf")
	if err != nil {
		t.Fatalf("OpenRegular: %v", err)
	}
	_ = f.Close()
	if calls != 1 {
		t.Errorf("openRegularHook called %d times, want 1", calls)
	}
}
