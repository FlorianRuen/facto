//go:build unix

package browser_test

import (
	"os"
	"path/filepath"
	"testing"
)

// writeExe creates dir/name with mode perm. dir is created with dirPerm
// under a fresh 0700 temp directory.
func writeExe(t *testing.T, dirPerm, perm os.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := writeTestFile(t, dir, "chrome", []byte("#!/bin/sh\nexit 0\n"))
	setMode(t, p, perm)
	setMode(t, dir, dirPerm)
	t.Cleanup(func() { _ = os.Chmod(dir, exeMode) })
	return p
}

func symlinkTo(t *testing.T, target string) string {
	t.Helper()
	link := filepath.Join(t.TempDir(), "chrome-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return link
}

func platformExecutableCases(t *testing.T) []execCase {
	t.Helper()
	good := writeExe(t, 0o700, 0o700)
	worldWritableDir := writeExe(t, 0o777, 0o700)
	// A sticky world-writable directory such as /tmp still lets any user
	// plant a file next to ours: the parent of the binary must be private.
	stickyWorldWritableDir := writeExe(t, 0o777|os.ModeSticky, 0o700)

	// Chain: link1 -> link2 -> binary in a world-writable directory.
	chain := symlinkTo(t, symlinkTo(t, worldWritableDir))

	return []execCase{
		{name: "private regular executable", path: good},
		{name: "system style 0755 in 0755 dir", path: writeExe(t, 0o755, 0o755)},
		{name: "world writable file", path: writeExe(t, 0o700, 0o757), wantErr: true},
		{name: "group writable file", path: writeExe(t, 0o700, 0o775), wantErr: true},
		{name: "not executable", path: writeExe(t, 0o700, 0o600), wantErr: true},
		{name: "setuid bit", path: writeExe(t, 0o700, 0o700|os.ModeSetuid), wantErr: true},
		{name: "world writable parent dir", path: worldWritableDir, wantErr: true},
		{name: "group writable parent dir", path: writeExe(t, 0o770, 0o700), wantErr: true},
		{name: "sticky world writable parent dir", path: stickyWorldWritableDir, wantErr: true},
		{name: "symlink to private executable", path: symlinkTo(t, good)},
		{name: "symlink out to world writable dir", path: symlinkTo(t, worldWritableDir), wantErr: true},
		{name: "symlink chain out to world writable dir", path: chain, wantErr: true},
		{name: "dangling symlink", path: symlinkTo(t, filepath.Join(t.TempDir(), "gone")), wantErr: true},
		{name: "relative symlink target out", path: relativeLinkOut(t, worldWritableDir), wantErr: true},
		{name: "symlink to directory", path: symlinkTo(t, t.TempDir()), wantErr: true},
		{name: "fifo", path: fifo(t), wantErr: true},
	}
}

// relativeLinkOut makes a symlink whose target is a relative path climbing
// out of its own directory to target.
func relativeLinkOut(t *testing.T, target string) string {
	t.Helper()
	dir := t.TempDir()
	rel, err := filepath.Rel(dir, target)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "chrome")
	if err := os.Symlink(rel, link); err != nil {
		t.Fatal(err)
	}
	return link
}
