package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
)

func TestRun_SanitizesAndReports(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WriteAtomic(t.Context(), "a.json", []byte(`{"email":"a.person@gmail.com"}`)); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	var so, se bytes.Buffer
	if code := run(t.Context(), []string{dir}, "", &so, &se); code != 0 {
		t.Fatalf("exit %d %s", code, se.String())
	}
	rt, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rt.Close() }()
	b, _ := rt.ReadFile("a.json")
	if strings.Contains(string(b), "gmail") || !strings.Contains(so.String(), "1 rewritten") {
		t.Fatalf("file %s, stdout %s", b, so.String())
	}
	for _, args := range [][]string{{}, {"-x"}, {filepath.Join(dir, "missing")}} {
		if code := run(t.Context(), args, "k", &so, &se); code != 2 {
			t.Errorf("run(%q) = %d, want 2", args, code)
		}
	}
}
