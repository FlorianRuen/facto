package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/har"
)

func writeHAR(t *testing.T, dir string, f *har.File) string {
	t.Helper()
	var b bytes.Buffer
	if err := har.Encode(&b, f); err != nil {
		t.Fatal(err)
	}
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(context.Background(), "rec.har", b.Bytes()); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "rec.har")
}

func TestRun_SlimsARedactedRecording(t *testing.T) {
	t.Parallel()
	f := har.New("facto", "test")
	f.Log.Entries = []har.Entry{
		{
			ResourceType: "document", Request: har.Request{Method: "GET", URL: "https://www.example.test/login"},
			Response: har.Response{Status: 200, Content: har.Content{MimeType: "text/html", Text: "<form></form>"}},
		},
		{
			ResourceType: "image", Request: har.Request{Method: "GET", URL: "https://www.example.test/a.png"},
			Response: har.Response{Status: 200, Content: har.Content{MimeType: "image/png"}},
		},
	}
	in := writeHAR(t, t.TempDir(), f)
	out := filepath.Join(t.TempDir(), "fx")
	var so, se bytes.Buffer
	if code := run(t.Context(), []string{in, "-o", out}, &so, &se); code != 0 {
		t.Fatalf("exit %d: %s", code, se.String())
	}
	for _, n := range []string{"flow.json", "001-get-login.html"} {
		if err := fsx.CheckPrivate(filepath.Join(out, n)); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "002-get-a-png.txt")); err == nil {
		t.Error("static asset kept")
	}
	if !strings.Contains(so.String(), "1 steps") {
		t.Errorf("stdout = %q", so.String())
	}
}

func TestRun_RefusesRawHARAndBadUsage(t *testing.T) {
	t.Parallel()
	f := har.New("browser", "x")
	f.Log.Entries = []har.Entry{{Request: har.Request{
		Method: "GET", URL: "https://a.test/",
		Headers: []har.NV{{Name: "Authorization", Value: "Bearer abcdefghijkl"}},
	}}}
	in := writeHAR(t, t.TempDir(), f)
	out := filepath.Join(t.TempDir(), "fx")
	var so, se bytes.Buffer
	if code := run(t.Context(), []string{in, "-o", out}, &so, &se); code != 1 || !strings.Contains(se.String(), "not redacted") {
		t.Fatalf("raw HAR: exit %d %q", code, se.String())
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("output written for a refused HAR")
	}
	for _, args := range [][]string{{}, {in}, {"-o", out}, {in, "extra", "-o", out}, {filepath.Join(t.TempDir(), "missing.har"), "-o", out}} {
		if code := run(t.Context(), args, &so, &se); code != 2 {
			t.Errorf("run(%q) = %d, want 2", args, code)
		}
	}
}
