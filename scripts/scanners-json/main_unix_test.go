//go:build unix

package main

import (
	"os"
	"testing"
)

func TestScannersJSON_OutputPrivate(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, s := range allScanners {
		e.status(t, s, "0\n")
	}
	if code, _, stderr := e.run(t); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr %q)", code, stderr)
	}
	fi, err := os.Lstat(e.out)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Errorf("scanners.json mode = %v, want -rw------- (written through fsx)", fi.Mode())
	}
}
