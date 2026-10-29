// Tests for private temp directories and confined tree removal (J1 task T4).
// Used by the browser pool (T10) for disposable 0700 profiles and the
// stale-profile sweep. Mode and symlink cases live in tree_unix_test.go; the
// planted-symlink attack lives in attack_test.go.
//
// Expected API (implementer: follow exactly):
//
//	// MkdirTempPrivate creates a new directory in parent, like os.MkdirTemp
//	// (pattern: the last "*" is replaced by a random string, otherwise the
//	// random string is appended), with mode exactly 0700 whatever the umask,
//	// and returns its path (filepath.Join(parent, base)). Concurrent calls
//	// never return the same directory. parent must exist (fs.ErrNotExist),
//	// be a directory (ErrNotDir) and be private (ErrInsecurePerms, unix
//	// only, nothing is created). A pattern that is empty after removing "*"
//	// is allowed; a pattern holding a path separator ('/' everywhere, also
//	// '\\' on Windows) or a NUL wraps ErrInvalidName.
//	func MkdirTempPrivate(parent, pattern string) (string, error)
//
//	// RemoveTree deletes the directory parent/name and everything below it,
//	// through os.Root opened on parent: symlinks found in the tree are
//	// removed, never followed, so nothing outside parent/name is touched.
//	// name is one path component: empty, ".", "..", absolute, or holding a
//	// separator ('/' everywhere, also '\\' and a volume on Windows) or a NUL
//	// wraps ErrInvalidName before touching the disk. When parent/name is not
//	// a real directory (regular file, symlink to anything) the error wraps
//	// ErrNotDir and nothing is removed. A missing parent/name wraps
//	// fs.ErrNotExist.
//	func RemoveTree(parent, name string) error
package fsx_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

// buildTree creates rel (slash-separated) entries under dir: a trailing "/"
// makes a directory, anything else a regular file.
func buildTree(t *testing.T, dir string, rels []string) {
	t.Helper()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("Open(%q): %v", dir, err)
	}
	defer func() { _ = r.Close() }()
	for _, rel := range rels {
		if d, ok := strings.CutSuffix(rel, "/"); ok {
			mustMkdir(t, r, d)
			continue
		}
		if i := strings.LastIndex(rel, "/"); i > 0 {
			mustMkdir(t, r, rel[:i])
		}
		mustAtomic(t, r, rel)
	}
}

func TestMkdirTempPrivate_CreatesDirUnderParent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		pattern    string
		wantPrefix string
		wantSuffix string
	}{
		{name: "star at end", pattern: "facto-profile-*", wantPrefix: "facto-profile-"},
		{name: "no star appends", pattern: "facto-profile-", wantPrefix: "facto-profile-"},
		{name: "star in middle", pattern: "pre-*-suf", wantPrefix: "pre-", wantSuffix: "-suf"},
		{name: "empty pattern", pattern: ""},
		{name: "last star replaced", pattern: "a*b*", wantPrefix: "a*b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent := privateTempDir(t)
			got, err := fsx.MkdirTempPrivate(parent, tc.pattern)
			if runtime.GOOS == "windows" && strings.Contains(tc.pattern, "*") && tc.wantPrefix == "a*b" {
				if err == nil {
					t.Fatalf("MkdirTempPrivate(%q) = %q, want an error on Windows", tc.pattern, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("MkdirTempPrivate(%q): %v", tc.pattern, err)
			}
			if filepath.Dir(got) != filepath.Clean(parent) {
				t.Fatalf("dir %q is not directly under parent %q", got, parent)
			}
			base := filepath.Base(got)
			if !strings.HasPrefix(base, tc.wantPrefix) || !strings.HasSuffix(base, tc.wantSuffix) {
				t.Fatalf("base %q, want prefix %q and suffix %q", base, tc.wantPrefix, tc.wantSuffix)
			}
			if len(base) <= len(tc.wantPrefix)+len(tc.wantSuffix) {
				t.Fatalf("base %q has no random part", base)
			}
			fi, err := os.Lstat(got)
			if err != nil {
				t.Fatalf("Lstat(%q): %v", got, err)
			}
			if !fi.IsDir() {
				t.Fatalf("%q mode %v, want a real directory", got, fi.Mode())
			}
			if des, err := os.ReadDir(got); err != nil || len(des) != 0 {
				t.Fatalf("new dir not empty: %d entries, err %v", len(des), err)
			}
		})
	}
}

func TestMkdirTempPrivate_UniqueUnderConcurrency(t *testing.T) {
	t.Parallel()
	parent := privateTempDir(t)
	const n = 64
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		seen = make(map[string]int, n)
	)
	for i := range n {
		wg.Go(func() {
			got, err := fsx.MkdirTempPrivate(parent, "facto-profile-*")
			if err != nil {
				t.Errorf("goroutine %d: %v", i, err)
				return
			}
			mu.Lock()
			seen[got]++
			mu.Unlock()
		})
	}
	wg.Wait()
	if len(seen) != n {
		t.Fatalf("%d distinct dirs for %d calls", len(seen), n)
	}
	for p, c := range seen {
		if c != 1 {
			t.Errorf("%q returned %d times", p, c)
		}
		if filepath.Dir(p) != filepath.Clean(parent) {
			t.Errorf("%q not directly under parent", p)
		}
	}
	if got := entries(t, parent); len(got) != n {
		t.Fatalf("parent holds %d entries, want %d", len(got), n)
	}
}

func TestMkdirTempPrivate_RefusesBadParentOrPattern(t *testing.T) {
	t.Parallel()
	type setup func(t *testing.T) (parent string)
	tempParent := func(t *testing.T) string { return t.TempDir() }
	tests := []struct {
		name    string
		parent  setup
		pattern string
		wantErr error
	}{
		{
			name:    "missing parent",
			parent:  func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
			pattern: "p-*",
			wantErr: fs.ErrNotExist,
		},
		{
			name: "parent is a file",
			parent: func(t *testing.T) string {
				dir := t.TempDir()
				buildTree(t, dir, []string{"file"})
				return filepath.Join(dir, "file")
			},
			pattern: "p-*",
			wantErr: fsx.ErrNotDir,
		},
		{name: "slash in pattern", parent: tempParent, pattern: "a/b-*", wantErr: fsx.ErrInvalidName},
		{name: "dotdot slash in pattern", parent: tempParent, pattern: "../p-*", wantErr: fsx.ErrInvalidName},
		{name: "NUL in pattern", parent: tempParent, pattern: "p\x00-*", wantErr: fsx.ErrInvalidName},
	}
	if runtime.GOOS == "windows" {
		tests = append(tests,
			struct {
				name    string
				parent  setup
				pattern string
				wantErr error
			}{name: "backslash in pattern", parent: tempParent, pattern: `..\p-*`, wantErr: fsx.ErrInvalidName},
			struct {
				name    string
				parent  setup
				pattern string
				wantErr error
			}{name: "colon in pattern (drive or stream)", parent: tempParent, pattern: "C:p-*", wantErr: fsx.ErrInvalidName})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent := tc.parent(t)
			before := siblingsOf(t, parent)
			got, err := fsx.MkdirTempPrivate(parent, tc.pattern)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("MkdirTempPrivate(%q, %q) = %q, %v; want errors.Is %v", parent, tc.pattern, got, err, tc.wantErr)
			}
			if after := siblingsOf(t, parent); strings.Join(after, "|") != strings.Join(before, "|") {
				t.Fatalf("grandparent changed: %v -> %v", before, after)
			}
			if fi, err := os.Lstat(parent); err == nil && fi.IsDir() {
				if got := entries(t, parent); len(got) != 0 {
					t.Fatalf("parent changed: %v", got)
				}
			}
		})
	}
}

// siblingsOf lists the entries of parent's own parent, to prove nothing was
// created next to a missing or refused parent.
func siblingsOf(t *testing.T, parent string) []string {
	t.Helper()
	return entries(t, filepath.Dir(parent))
}

func TestRemoveTree_DeletesNestedContent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		tree []string // slash-separated, relative to parent/victim
	}{
		{name: "empty dir"},
		{name: "flat files", tree: []string{"a", "b", "c.pdf"}},
		{name: "nested", tree: []string{"Default/Cache/data_0", "Default/Cache/index", "Default/Cookies", "Local State", "x/y/z/w/v/deep"}},
		{name: "empty subdirs", tree: []string{"e1/", "e2/e3/", "f"}},
		{name: "dot files", tree: []string{".lock", ".hidden/.x"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent := t.TempDir()
			buildTree(t, parent, []string{"victim/", "keep/k", "keep.txt"})
			buildTree(t, filepath.Join(parent, "victim"), tc.tree)
			if err := fsx.RemoveTree(parent, "victim"); err != nil {
				t.Fatalf("RemoveTree: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(parent, "victim")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("victim still there (err %v)", err)
			}
			if got := strings.Join(entries(t, parent), "|"); got != "keep|keep.txt" {
				t.Fatalf("parent entries = %q, want siblings untouched", got)
			}
			if got := strings.Join(entries(t, filepath.Join(parent, "keep")), "|"); got != "k" {
				t.Fatalf("sibling dir changed: %q", got)
			}
		})
	}
}

func TestRemoveTree_RefusesEscapingNames(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		target func(parent string) string
	}{
		{name: "empty", target: func(string) string { return "" }},
		{name: "dot", target: func(string) string { return "." }},
		{name: "dotdot", target: func(string) string { return ".." }},
		{name: "dotdot slash sibling", target: func(string) string { return "../sibling" }},
		{name: "nested slash", target: func(string) string { return "victim/sub" }},
		{name: "trailing slash", target: func(string) string { return "victim/" }},
		{name: "inner dotdot", target: func(string) string { return "victim/../victim" }},
		{name: "absolute victim", target: func(parent string) string { return filepath.Join(parent, "victim") }},
		{name: "absolute sibling", target: func(parent string) string { return filepath.Join(filepath.Dir(parent), "sibling") }},
		{name: "NUL", target: func(string) string { return "victim\x00" }},
	}
	if runtime.GOOS == "windows" {
		tests = append(tests,
			struct {
				name   string
				target func(parent string) string
			}{name: "backslash dotdot", target: func(string) string { return `..\sibling` }},
			struct {
				name   string
				target func(parent string) string
			}{name: "backslash nested", target: func(string) string { return `victim\sub` }},
			struct {
				name   string
				target func(parent string) string
			}{name: "volume relative", target: func(parent string) string { return filepath.VolumeName(parent) + "sibling" }},
			struct {
				name   string
				target func(parent string) string
			}{name: "UNC", target: func(string) string { return `\\server\share\x` }},
		)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			buildTree(t, base, []string{"parent/victim/sub/f", "sibling/s"})
			parent := filepath.Join(base, "parent")
			target := tc.target(parent)
			err := fsx.RemoveTree(parent, target)
			if !errors.Is(err, fsx.ErrInvalidName) {
				t.Fatalf("RemoveTree(parent, %q) = %v, want errors.Is ErrInvalidName", target, err)
			}
			if got := strings.Join(entries(t, filepath.Join(parent, "victim", "sub")), "|"); got != "f" {
				t.Fatalf("victim tree changed: %q", got)
			}
			if got := strings.Join(entries(t, filepath.Join(base, "sibling")), "|"); got != "s" {
				t.Fatalf("sibling outside parent changed: %q", got)
			}
		})
	}
}

// TestRemoveTree_BackslashName: on unix "a\b" is one
// ordinary name, so it must never reach the directory a/b; on Windows it is
// refused as a path with a separator.
func TestRemoveTree_BackslashName(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	buildTree(t, parent, []string{"a/b/f"})
	err := fsx.RemoveTree(parent, `a\b`)
	want := fs.ErrNotExist
	if runtime.GOOS == "windows" {
		want = fsx.ErrInvalidName
	}
	if !errors.Is(err, want) {
		t.Fatalf(`RemoveTree(parent, "a\\b") = %v, want errors.Is %v`, err, want)
	}
	if got := strings.Join(entries(t, filepath.Join(parent, "a", "b")), "|"); got != "f" {
		t.Fatalf("a/b changed: %q", got)
	}
}

func TestRemoveTree_RefusesNonDirOrMissing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		target  string
		wantErr error
	}{
		{name: "regular file", target: "file.pdf", wantErr: fsx.ErrNotDir},
		{name: "missing", target: "missing", wantErr: fs.ErrNotExist},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent := t.TempDir()
			buildTree(t, parent, []string{"file.pdf", "keep/k"})
			if err := fsx.RemoveTree(parent, tc.target); !errors.Is(err, tc.wantErr) {
				t.Fatalf("RemoveTree(parent, %q) = %v, want errors.Is %v", tc.target, err, tc.wantErr)
			}
			if got := strings.Join(entries(t, parent), "|"); got != "file.pdf|keep" {
				t.Fatalf("parent changed: %q", got)
			}
		})
	}
}

func TestRemoveTree_MissingParent(t *testing.T) {
	t.Parallel()
	parent := filepath.Join(t.TempDir(), "missing")
	if err := fsx.RemoveTree(parent, "x"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("RemoveTree(missing parent) = %v, want errors.Is fs.ErrNotExist", err)
	}
}

// TestMkdirTempPrivate_RemoveTreeRoundTrip is the T10 profile lifecycle:
// create a disposable dir, fill it, remove it by base name.
func TestMkdirTempPrivate_RemoveTreeRoundTrip(t *testing.T) {
	t.Parallel()
	parent := privateTempDir(t)
	dir, err := fsx.MkdirTempPrivate(parent, "facto-profile-*")
	if err != nil {
		t.Fatalf("MkdirTempPrivate: %v", err)
	}
	buildTree(t, dir, []string{"Default/Cookies", "Local State"})
	if err := fsx.RemoveTree(parent, filepath.Base(dir)); err != nil {
		t.Fatalf("RemoveTree: %v", err)
	}
	if got := entries(t, parent); len(got) != 0 {
		t.Fatalf("parent not empty after round trip: %v", got)
	}
}

// privateTempDir returns a fresh 0700 directory: t.TempDir() itself is
// created 0777&^umask (0755 under the usual 022), which MkdirTempPrivate
// rightly refuses as a parent (see TestMkdirTempPrivate_RefusesBroadParent),
// so a subdirectory is made through fsx (MkdirPrivate, exactly 0700).
func privateTempDir(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	buildTree(t, base, []string{"private/"})
	return filepath.Join(base, "private")
}
