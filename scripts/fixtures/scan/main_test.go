package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

func TestRun_CountsFindings(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var so, se bytes.Buffer
	if code := run([]string{dir}, &so, &se); code != 0 || !strings.Contains(so.String(), "PII scan: 0 findings") {
		t.Fatalf("empty dir: %d %q", code, so.String())
	}
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WriteAtomic(t.Context(), "a.txt", []byte("x\nreach me at a.person@gmail.com\n")); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	so.Reset()
	if code := run([]string{dir}, &so, &se); code != 1 || !strings.Contains(so.String(), "a.txt:2: email") ||
		!strings.Contains(so.String(), "PII scan: 1 findings") || strings.Contains(so.String(), "gmail") {
		t.Fatalf("finding: %d %q", code, so.String())
	}
	for _, args := range [][]string{{}, {"-h"}, {dir + "/missing"}} {
		if code := run(args, &so, &se); code != 2 {
			t.Errorf("run(%q) = %d, want 2", args, code)
		}
	}
}
