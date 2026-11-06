package fixtures_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fixtures"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/har"
)

// fakeproviderRecording is a redacted recording of the fake supplier, the
// shape `facto record` writes (test/e2e/record-fakeprovider.yaml), with
// invented personal data in the pages: what a real account would show.
func fakeproviderRecording(t *testing.T) *har.File {
	t.Helper()
	list, err := os.ReadFile(filepath.Join("..", "..", "connectors", "fakeprovider", "testdata", "list", "page1.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Personal data a real list page carries next to the invoices.
	var page map[string]any
	if err := json.Unmarshal(list, &page); err != nil {
		t.Fatal(err)
	}
	page["holder"] = map[string]any{
		"firstName": "Camille", "lastName": "Rousseau", "email": "camille.rousseau@laposte.net",
		"phone": "07 81 45 22 19", "street": "8 avenue Jean Jaurès", "zip": "31000", "city": "Toulouse",
		"iban": "FR76 3000 6000 0112 3456 7890 189",
	}
	listBody, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	e := func(method, u string, status int, rtype, mime, body string) har.Entry {
		return har.Entry{
			ResourceType: rtype, Request: har.Request{Method: method, URL: u},
			Response: har.Response{Status: status, Content: har.Content{MimeType: mime, Text: body}},
		}
	}
	f := har.New("facto", "test")
	f.Log.Entries = []har.Entry{
		e("GET", "https://www.fakeprovider.test/login", 200, "document", "text/html",
			`<form id="login-form"><input id="username" name="username"><input id="password" type="password" name="password"></form>`),
		e("GET", "https://evil.test/pixel.png", 0, "image", "", ""),
		e("POST", "https://www.fakeprovider.test/login", 303, "document", "", ""),
		e("GET", "https://www.fakeprovider.test/account", 200, "document", "text/html",
			`<div id="account">Bonjour Camille Rousseau</div><p>Contrat n° 4012345678</p><p>8 avenue Jean Jaurès, 31000 TOULOUSE</p>`),
		e("GET", "https://www.fakeprovider.test/api/invoices?from=2025-01-01&to=2026-01-01&page=1", 200, "fetch", "application/json", string(listBody)),
		e("GET", "https://www.fakeprovider.test/api/invoices/FP-2025-0001/pdf", 200, "fetch", "application/pdf", ""),
	}
	f.Log.Entries[2].Request.PostData = &har.PostData{
		MimeType: "application/x-www-form-urlencoded",
		Text:     "csrf_token=%5Bredacted%5D&username=%5Bredacted%5D&password=%5Bredacted%5D",
	}
	f.Log.Entries[2].Response.RedirectURL = "/account"
	f.Log.Entries[5].Response.Content.Comment = "binary body not recorded"
	return f
}

// TestPipeline_FakeproviderRecordingScansClean is the fixtures-from-har
// procedure end to end on a fakeprovider recording: harslim, sanitize,
// scan prints 0 findings; before sanitize the scan does find the personal
// data (the scanner is not vacuous).
func TestPipeline_FakeproviderRecordingScansClean(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	dir := t.TempDir()
	rec := fakeproviderRecording(t)
	slim, err := fixtures.Slim(rec, fixtures.SlimOptions{})
	if err != nil {
		t.Fatalf("Slim: %v", err)
	}
	flow, err := json.MarshalIndent(slim.Flow, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := fixtures.WriteSlimmed(ctx, dir, slim, flow); err != nil {
		t.Fatalf("WriteSlimmed: %v", err)
	}
	before, err := fixtures.ScanTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) == 0 {
		t.Fatal("scan before sanitize found nothing: the scanner is vacuous")
	}
	res, err := fixtures.SanitizeTree(ctx, dir, []byte("pipeline"))
	if err != nil {
		t.Fatalf("SanitizeTree: %v", err)
	}
	if len(res.Rewritten) == 0 || len(res.Skipped) != 1 {
		t.Fatalf("sanitize result = %+v, want rewritten files and the PDF skipped", res)
	}
	after, err := fixtures.ScanTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 0 {
		var b strings.Builder
		for _, f := range after {
			b.WriteString(f.String() + "\n")
		}
		t.Fatalf("PII scan after sanitize: %d findings\n%s", len(after), b.String())
	}
	// Every file private, flow.json still parses, ids still match the PDF URL.
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := fsx.CheckPrivate(filepath.Join(dir, f.Name())); err != nil {
			t.Errorf("%s: %v", f.Name(), err)
		}
	}
	var fl fixtures.Flow
	rt, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rt.Close() }()
	raw, _ := rt.ReadFile("flow.json")
	if err := json.Unmarshal(raw, &fl); err != nil || len(fl.Steps) != 5 {
		t.Fatalf("flow.json = %s (%v)", raw, err)
	}
	listFile, _ := rt.ReadFile(fl.Steps[3].Body)
	if !bytes.Contains(listFile, []byte(`"FP-2025-0001"`)) || !strings.Contains(fl.Steps[4].Path, "FP-2025-0001") {
		t.Errorf("the invoice id no longer matches between list and PDF step")
	}
}

func TestScanTree_PDFTextAndUnredactedHAR(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeBytes(t, dir, "real.pdf", fixtures.BuildPDF(fixtures.PDFSpec{Lines: []string{"Client: someone@gmail.com"}}))
	raw := har.New("x", "y")
	raw.Log.Entries = []har.Entry{{Request: har.Request{
		Method: "GET", URL: "https://a.test/",
		Headers: []har.NV{{Name: "Cookie", Value: "sid=abcdef0123456789"}},
	}}}
	var b bytes.Buffer
	if err := har.Encode(&b, raw); err != nil {
		t.Fatal(err)
	}
	writeBytes(t, dir, "raw.har", b.Bytes())
	got, err := fixtures.ScanTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	var k []string
	for _, f := range got {
		k = append(k, f.File+":"+f.Kind)
	}
	joined := strings.Join(k, ",")
	if !strings.Contains(joined, "real.pdf:email") || !strings.Contains(joined, "raw.har:unredacted-har") {
		t.Fatalf("findings = %s", joined)
	}
}

func write(t *testing.T, dir, name, s string) { t.Helper(); writeBytes(t, dir, name, []byte(s)) }

func writeBytes(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(context.Background(), name, b); err != nil {
		t.Fatal(err)
	}
}
