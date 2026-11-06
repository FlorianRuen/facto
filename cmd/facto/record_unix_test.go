//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecordOutPath_ResolvesSymlinkedParentAndRefusesSymlinkTarget(t *testing.T) {
	t.Parallel()
	dir := outsideDir(t)
	link := filepath.Join(outsideDir(t), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// The temp dir itself may sit behind a symlink (macOS: /var ->
	// /private/var): recordOutPath returns the fully resolved path.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := recordOutPath(filepath.Join(link, "a.har"), dir, false)
	if err != nil || got != filepath.Join(resolved, "a.har") {
		t.Fatalf("recordOutPath through a symlinked dir = %q, %v", got, err)
	}
	target := filepath.Join(dir, "t.har")
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), target); err != nil {
		t.Fatal(err)
	}
	if _, err := recordOutPath(target, dir, true); err == nil {
		t.Fatal("recordOutPath accepted a symlink as the output file")
	}
}
