//go:build unix

// Check/remove race for RemoveTree: parent/name is swapped for a symlink to
// an outside directory between the Lstat and the removal (removeTreeHook).
// os.Root.RemoveAll unlinks the symlink itself and never follows it, so the
// swapped-in symlink's target must survive. These tests swap a package-level
// hook, so they are NOT parallel and restore it with t.Cleanup.
package fsx

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestRemoveTree_RootSwappedForSymlinkAfterLstat(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(parent, "victim"), filepath.Join(outside, "sub")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(outside, "sentinel.txt"), filepath.Join(outside, "sub", "deep.txt")} {
		if err := os.WriteFile(f, []byte("synthetic"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	setHook(t, &removeTreeHook, func() {
		calls++
		victim := filepath.Join(parent, "victim")
		if err := os.Rename(victim, filepath.Join(parent, "victim.old")); err != nil {
			t.Errorf("swap: %v", err)
			return
		}
		if err := os.Symlink(outside, victim); err != nil {
			t.Errorf("swap: %v", err)
		}
	})

	err := RemoveTree(parent, "victim")
	if calls != 1 {
		t.Fatalf("removeTreeHook called %d times, want 1", calls)
	}
	// Documented contract: the swapped-in symlink is unlinked, never
	// followed, and RemoveTree reports success.
	if err != nil {
		t.Fatalf("RemoveTree after swap = %v, want nil (symlink unlinked)", err)
	}
	if _, err := os.Lstat(filepath.Join(parent, "victim")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("swapped-in symlink still at parent/victim (Lstat err %v), want fs.ErrNotExist", err)
	}
	if got := dirEntries(t, outside); !slices.Equal(got, []string{"sentinel.txt", "sub"}) {
		t.Errorf("outside entries = %v, want [sentinel.txt sub]", got)
	}
	if got := dirEntries(t, filepath.Join(outside, "sub")); !slices.Equal(got, []string{"deep.txt"}) {
		t.Errorf("outside/sub entries = %v, want [deep.txt]", got)
	}
	for _, f := range []string{filepath.Join(outside, "sentinel.txt"), filepath.Join(outside, "sub", "deep.txt")} {
		if b, err := os.ReadFile(filepath.Clean(f)); err != nil || string(b) != "synthetic" {
			t.Errorf("%s damaged: %q %v", f, b, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(parent, "victim.old")); err != nil {
		t.Errorf("moved-aside directory touched: %v", err)
	}
}

func TestRemoveTree_UnswappedCallsHookOnce(t *testing.T) {
	parent := t.TempDir()
	if err := os.MkdirAll(filepath.Join(parent, "victim", "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	calls := 0
	setHook(t, &removeTreeHook, func() { calls++ })
	if err := RemoveTree(parent, "victim"); err != nil {
		t.Fatalf("RemoveTree: %v", err)
	}
	if calls != 1 {
		t.Errorf("removeTreeHook called %d times, want 1", calls)
	}
	if got := dirEntries(t, parent); len(got) != 0 {
		t.Errorf("parent entries = %v, want none", got)
	}
}
