//go:build linux

// Handle hygiene around the version swap (Windows CI, run 41792239500):
// Windows refuses to rename a directory while a handle on it or inside it
// is open, so nothing may keep one into <Dir>/<Version> when Install sets
// the previous version aside. Linux has no such lock; these tests read
// /proc/self/fd instead and fail on any handle left into the tree. The
// Windows run of TestInstall_Idempotent stays the end-to-end proof.
package cft_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser/cft"
)

// openUnder returns the targets of this process's open descriptors that
// are dir itself or lie below it.
func openUnder(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("list /proc/self/fd: %v", err)
	}
	var open []string
	for _, de := range des {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", de.Name()))
		if err != nil {
			continue // closed since the listing (the listing's own fd)
		}
		if target == dir || strings.HasPrefix(target, dir+string(filepath.Separator)) {
			open = append(open, target)
		}
	}
	return open
}

// TestWriteRaw_LeavesNoHandle: the setup helper closes the directory it
// wrote into at once, not at test end (an open fsx.Root on <Version>/
// made the Windows reinstall fail with a sharing violation).
func TestWriteRaw_LeavesNoHandle(t *testing.T) {
	t.Parallel()
	dir := privateDir(t)
	version := filepath.Join(dir, testVersion)
	mkdirRaw(t, version, 0o700)
	writeRaw(t, filepath.Join(version, cft.MarkerName), "synthetic marker")
	if open := openUnder(t, version); len(open) != 0 {
		t.Fatalf("handles still open into %s after writeRaw: %q", version, open)
	}
}

// TestInstall_NoHandleIntoVersionTree: Verified, reading a marker of
// another archive, and a reinstall over that version leave no handle into
// the version tree, nor into Dir once Install returns.
func TestInstall_NoHandleIntoVersionTree(t *testing.T) {
	t.Parallel()
	archive := chromeZip(t)
	s := newServer(t, serveBytes(archive))
	dir := privateDir(t)
	in := newInstaller(t, s, manifestFor(archive), dir, nil)
	if _, err := in.Install(t.Context()); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	version := filepath.Join(dir, testVersion)
	if open := openUnder(t, dir); len(open) != 0 {
		t.Fatalf("handles still open into %s after Install: %q", dir, open)
	}
	writeRaw(t, filepath.Join(version, cft.MarkerName), strings.Repeat("0", 64))

	if cft.Verified(openFsx(t, dir), manifestFor(archive)) {
		t.Fatal("Verified() = true for a marker of another archive")
	}
	if open := openUnder(t, version); len(open) != 0 {
		t.Fatalf("handles still open into %s after Verified: %q", version, open)
	}

	if _, err := in.Install(t.Context()); err != nil {
		t.Fatalf("second Install: %v", err)
	}
	if open := openUnder(t, version); len(open) != 0 {
		t.Fatalf("handles still open into %s after the reinstall: %q", version, open)
	}
}
