//go:build unix

// Package fixtures_test runs the fixtures-from-har procedure through the
// real scripts on a fakeprovider recording, offline: harslim,
// sanitize.sh, scan.sh ("PII scan: 0 findings"), fakepdf.
package fixtures_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/har"
)

// recording is a redacted fakeprovider recording, as facto record writes
// it (test/e2e/record-fakeprovider.yaml), with invented personal data in
// the pages a real account would show.
func recording(t *testing.T) []byte {
	t.Helper()
	list, err := os.ReadFile(filepath.Join("..", "..", "connectors", "fakeprovider", "testdata", "list", "page1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var page map[string]any
	if err := json.Unmarshal(list, &page); err != nil {
		t.Fatal(err)
	}
	page["holder"] = map[string]any{
		"firstName": "Camille", "lastName": "Rousseau",
		"email": "camille.rousseau@laposte.net", "phone": "07 81 45 22 19",
		"street": "8 avenue Jean Jaurès", "zip": "31000", "city": "Toulouse",
	}
	body, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	e := func(method, u string, status int, rtype, mime, text string) har.Entry {
		return har.Entry{
			ResourceType: rtype, Request: har.Request{Method: method, URL: u},
			Response: har.Response{Status: status, Content: har.Content{MimeType: mime, Text: text}},
		}
	}
	f := har.New("facto", "test")
	f.Log.Entries = []har.Entry{
		e("GET", "https://www.fakeprovider.test/login", 200, "document", "text/html", `<form id="login-form"></form>`),
		e("POST", "https://www.fakeprovider.test/login", 303, "document", "", ""),
		e("GET", "https://www.fakeprovider.test/account", 200, "document", "text/html", `<div id="account">Bonjour Camille Rousseau, contrat 4012345678</div>`),
		e("GET", "https://www.fakeprovider.test/api/invoices?page=1", 200, "fetch", "application/json", string(body)),
		e("GET", "https://www.fakeprovider.test/api/invoices/FP-2025-0001/pdf", 200, "fetch", "application/pdf", ""),
	}
	f.Log.Entries[1].Request.PostData = &har.PostData{MimeType: "application/x-www-form-urlencoded", Text: "username=%5Bredacted%5D&password=%5Bredacted%5D"}
	var b bytes.Buffer
	if err := har.Encode(&b, f); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func sh(t *testing.T, want int, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*60e9)
	defer cancel()
	// #nosec G204 -- fixed repository scripts, arguments are test temp paths (J2 fixtures tools)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		t.Fatalf("%s: %v", name, err)
	}
	if code != want {
		t.Fatalf("%s %q: exit %d, want %d\n%s", name, args, code, want, out)
	}
	return string(out)
}

func TestScripts_FakeproviderRecordingToCleanFixtures(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	r, err := fsx.Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WriteAtomic(t.Context(), "recording.har", recording(t)); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	out := filepath.Join(tmp, "fakeprovider")
	abs := func(p string) string { a, _ := filepath.Abs(p); return a }

	so := sh(t, 0, "go", "run", "./scripts/harslim", filepath.Join(tmp, "recording.har"), "-o", out)
	if !strings.Contains(so, "5 steps") {
		t.Fatalf("harslim: %s", so)
	}
	// Before sanitize the scanner sees the personal data (not vacuous).
	so = sh(t, 1, abs("scan.sh"), out)
	if !strings.Contains(so, "email") || strings.Contains(so, "PII scan: 0 findings") {
		t.Fatalf("scan before sanitize: %s", so)
	}
	so = sh(t, 0, abs("sanitize.sh"), out)
	if !strings.Contains(so, "1 PDF skipped") {
		t.Fatalf("sanitize: %s", so)
	}
	pdf := filepath.Join(out, "005-get-api-invoices-fp-2025-0001-pdf.pdf")
	sh(t, 0, "go", "run", "./scripts/fakepdf", "-o", pdf, "--like", pdf, "--line", "Facture FP-2025-0001")
	so = sh(t, 0, abs("scan.sh"), out)
	if !strings.Contains(so, "PII scan: 0 findings") {
		t.Fatalf("scan after sanitize: %s", so)
	}
	for _, leaked := range []string{"Camille", "Rousseau", "laposte", "31000", "Jaur"} {
		b, err := exec.CommandContext(t.Context(), "grep", "-rl", leaked, out).Output() // #nosec G204 -- fixed tool, test temp dir
		if err == nil && len(b) > 0 {
			t.Errorf("%q still in %s", leaked, b)
		}
	}
}

func TestScripts_UsageErrors(t *testing.T) {
	t.Parallel()
	abs := func(p string) string { a, _ := filepath.Abs(p); return a }
	sh(t, 2, abs("scan.sh"))
	sh(t, 2, abs("scan.sh"), filepath.Join(t.TempDir(), "missing"))
	sh(t, 2, abs("sanitize.sh"))
}
