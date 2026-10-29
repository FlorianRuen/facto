//go:build unix

// Mode and symlink tests for MkdirTempPrivate and RemoveTree (J1 task T4).
// See tree_test.go for the expected API.
package fsx_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/fsx"
)

func TestMkdirTempPrivate_Mode0700(t *testing.T) {
	t.Parallel()
	parent := privateTempDir(t)
	const n = 16
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		dirs []string
	)
	for i := range n {
		wg.Go(func() {
			got, err := fsx.MkdirTempPrivate(parent, "facto-profile-*")
			if err != nil {
				t.Errorf("goroutine %d: %v", i, err)
				return
			}
			mu.Lock()
			dirs = append(dirs, got)
			mu.Unlock()
		})
	}
	wg.Wait()
	if len(dirs) != n {
		t.Fatalf("%d dirs created, want %d", len(dirs), n)
	}
	for _, d := range dirs {
		if got := perm(t, d); got != 0o700 {
			t.Errorf("%s mode %#o, want 0700", d, got)
		}
		if err := fsx.CheckPrivate(d); err != nil {
			t.Errorf("CheckPrivate(%s): %v", d, err)
		}
	}
}

func TestMkdirTempPrivate_RefusesBroadParent(t *testing.T) {
	t.Parallel()
	for _, mode := range []fs.FileMode{0o701, 0o707, 0o710, 0o750, 0o755, 0o770, 0o777} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			parent := filepath.Join(t.TempDir(), "parent")
			mustMkdirRaw(t, parent, mode)
			got, err := fsx.MkdirTempPrivate(parent, "facto-profile-*")
			if !errors.Is(err, fsx.ErrInsecurePerms) {
				t.Fatalf("MkdirTempPrivate(parent %#o) = %q, %v; want errors.Is ErrInsecurePerms", mode, got, err)
			}
			if e := entries(t, parent); len(e) != 0 {
				t.Fatalf("something was created in a broad parent: %v", e)
			}
			if p := perm(t, parent); p != mode {
				t.Fatalf("parent mode changed %#o -> %#o", mode, p)
			}
		})
	}
}

// outsideTree builds base/outside with a synthetic file and subdir, and
// returns its path. outsideIntact checks it afterwards.
func outsideTree(t *testing.T, base string) string {
	t.Helper()
	buildTree(t, base, []string{"outside/sentinel.txt", "outside/sub/deep.txt"})
	return filepath.Join(base, "outside")
}

func outsideIntact(t *testing.T, outside string) {
	t.Helper()
	if got := strings.Join(entries(t, outside), "|"); got != "sentinel.txt|sub" {
		t.Errorf("outside entries changed: %q", got)
	}
	if got := strings.Join(entries(t, filepath.Join(outside, "sub")), "|"); got != "deep.txt" {
		t.Errorf("outside/sub entries changed: %q", got)
	}
	assertContent(t, filepath.Join(outside, "sentinel.txt"), "synthetic")
	assertContent(t, filepath.Join(outside, "sub", "deep.txt"), "synthetic")
}

func TestRemoveTree_NeverFollowsSymlinks(t *testing.T) {
	t.Parallel()
	type link struct{ at, target string } // at: slash path under victim; target: "<out>" is replaced
	tests := []struct {
		name  string
		tree  []string
		links []link
	}{
		{name: "top-level link to outside dir", links: []link{{"out", "<out>"}}},
		{name: "deep link to outside dir", tree: []string{"a/b/c/f"}, links: []link{{"a/b/c/out", "<out>"}}},
		{name: "link to outside file", tree: []string{"d/"}, links: []link{{"d/cookie", "<out>/sentinel.txt"}}},
		{name: "relative link out of parent", tree: []string{"d/"}, links: []link{{"d/rel", "../../../outside"}}},
		{name: "link to parent", links: []link{{"up", ".."}}},
		{name: "dangling link", links: []link{{"dangling", "<out>/missing"}}},
		{name: "link to sibling in parent", links: []link{{"sib", "../keep"}}},
		{name: "many links", tree: []string{"x/y/"}, links: []link{
			{"x/o1", "<out>"}, {"x/y/o2", "<out>/sub"}, {"x/y/o3", "<out>/sub/deep.txt"},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			outside := outsideTree(t, base)
			buildTree(t, base, []string{"parent/victim/", "parent/keep/k"})
			parent := filepath.Join(base, "parent")
			victim := filepath.Join(parent, "victim")
			buildTree(t, victim, tc.tree)
			for _, l := range tc.links {
				target := strings.ReplaceAll(l.target, "<out>", outside)
				mustSymlink(t, target, filepath.Join(victim, filepath.FromSlash(l.at)))
			}
			if err := fsx.RemoveTree(parent, "victim"); err != nil {
				t.Fatalf("RemoveTree: %v", err)
			}
			assertAbsent(t, victim)
			outsideIntact(t, outside)
			if got := strings.Join(entries(t, filepath.Join(parent, "keep")), "|"); got != "k" {
				t.Fatalf("sibling dir changed: %q", got)
			}
		})
	}
}

func TestRemoveTree_RefusesSymlinkRoot(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target func(base string) string
	}{
		{name: "to outside dir", target: func(base string) string { return filepath.Join(base, "outside") }},
		{name: "relative to outside dir", target: func(string) string { return "../outside" }},
		{name: "to sibling dir in parent", target: func(string) string { return "keep" }},
		{name: "to outside file", target: func(base string) string { return filepath.Join(base, "outside", "sentinel.txt") }},
		{name: "dangling", target: func(base string) string { return filepath.Join(base, "missing") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			outside := outsideTree(t, base)
			buildTree(t, base, []string{"parent/keep/k"})
			parent := filepath.Join(base, "parent")
			link := filepath.Join(parent, "victim")
			mustSymlink(t, tc.target(base), link)
			if err := fsx.RemoveTree(parent, "victim"); !errors.Is(err, fsx.ErrNotDir) {
				t.Fatalf("RemoveTree(symlink root) = %v, want errors.Is ErrNotDir", err)
			}
			if fi, err := os.Lstat(link); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
				t.Fatalf("symlink root was removed or replaced (err %v)", err)
			}
			outsideIntact(t, outside)
			if got := strings.Join(entries(t, filepath.Join(parent, "keep")), "|"); got != "k" {
				t.Fatalf("sibling dir changed: %q", got)
			}
		})
	}
}

// TestRemoveTree_RemovesFIFOWithoutBlocking: a FIFO in the tree is unlinked,
// never opened.
func TestRemoveTree_RemovesFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	buildTree(t, parent, []string{"victim/d/"})
	if err := syscall.Mkfifo(filepath.Join(parent, "victim", "d", "pipe"), 0o600); err != nil {
		t.Fatalf("setup Mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- fsx.RemoveTree(parent, "victim") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RemoveTree: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RemoveTree blocked on a FIFO")
	}
	assertAbsent(t, filepath.Join(parent, "victim"))
}
