package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/fixtures"
	"github.com/FlorianRuen/facto/internal/fsx"
)

func TestRun_LikeCopiesLayoutOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	source := filepath.Join(dir, "real.pdf")
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	src := fixtures.BuildPDF(fixtures.PDFSpec{Pages: 2, Width: 612, Height: 792, Lines: []string{"Private Person 5 rue Secrete"}})
	if err := r.WriteAtomic(t.Context(), "real.pdf", src); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "fake.pdf")
	var so, se bytes.Buffer
	if code := run(t.Context(), []string{"-o", out, "--like", source, "--line", "Facture FA-0000-0001"}, &so, &se); code != 0 {
		t.Fatalf("exit %d: %s", code, se.String())
	}
	rt, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rt.Close() }()
	b, err := rt.ReadFile("fake.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("Secrete")) || !bytes.Contains(b, []byte("FA-0000-0001")) {
		t.Fatal("fake PDF holds source text, or lacks its own line")
	}
	l, err := fixtures.ReadLayout(t.Context(), bytes.NewReader(b))
	if err != nil || l.Pages != 2 || l.Width != 612 {
		t.Fatalf("layout = %+v, %v", l, err)
	}
	if err := fsx.CheckPrivate(out); err != nil {
		t.Error(err)
	}
}

func TestRun_UsageErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var so, se bytes.Buffer
	for _, args := range [][]string{
		{},
		{"-o", filepath.Join(dir, "x.txt")},
		{"-o", filepath.Join(dir, "x.pdf"), "--like", filepath.Join(dir, "missing.pdf")},
		{"-o", filepath.Join(dir, "x.pdf"), "--facturx", filepath.Join(dir, "missing.xml")},
		{"-o", filepath.Join(dir, "missing", "x.pdf")},
	} {
		if code := run(t.Context(), args, &so, &se); code != 2 {
			t.Errorf("run(%q) = %d, want 2", args, code)
		}
	}
}
