package fixtures_test

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fixtures"
	"github.com/FlorianRuen/facto/internal/har"
)

func entry(method, u string, status int, rtype, mime, body string) har.Entry {
	return har.Entry{
		ResourceType: rtype,
		Request:      har.Request{Method: method, URL: u},
		Response:     har.Response{Status: status, Content: har.Content{MimeType: mime, Text: body, Size: len(body)}},
	}
}

func recording() *har.File {
	f := har.New("facto", "test")
	f.Log.Entries = []har.Entry{
		entry("GET", "https://www.example.test/login", 200, "document", "text/html", "<form id=login-form></form>"),
		entry("GET", "https://www.example.test/static/app.css", 200, "stylesheet", "text/css", "body{}"),
		entry("GET", "https://www.example.test/static/logo.png", 200, "image", "image/png", ""),
		entry("GET", "https://evil.test/pixel", 0, "image", "", ""),
		entry("GET", "https://www.example.test/favicon.ico", 404, "other", "text/plain", "404"),
		entry("POST", "https://www.example.test/login", 303, "document", "", ""),
		entry("GET", "https://www.example.test/account", 200, "document", "text/html", "<div id=account></div>"),
		entry("GET", "https://cdn.analytics.test/collect?v=1", 204, "ping", "", ""),
		entry("GET", "https://www.example.test/api/invoices?page=1", 200, "fetch", "application/json", `{"invoices":[]}`),
		entry("GET", "https://www.example.test/api/invoices/FA-1/pdf", 200, "fetch", "application/pdf", ""),
		entry("GET", "https://www.example.test/api/invoices/FA-2/pdf", 200, "fetch", "application/pdf", ""),
		entry("GET", "https://www.example.test/static/app.js", 200, "script", "application/javascript", "x()"),
	}
	f.Log.Entries[3].Comment = "failed: net::ERR_BLOCKED_BY_CLIENT"
	f.Log.Entries[5].Request.PostData = &har.PostData{MimeType: "application/x-www-form-urlencoded", Text: "username=%5Bredacted%5D&password=%5Bredacted%5D"}
	f.Log.Entries[5].Response.RedirectURL = "/account"
	return f
}

func TestSlim_KeepsLoginListAndOnePDF(t *testing.T) {
	t.Parallel()
	out, err := fixtures.Slim(recording(), fixtures.SlimOptions{Hosts: []string{"www.example.test"}})
	if err != nil {
		t.Fatalf("Slim: %v", err)
	}
	var got []string
	for _, s := range out.Flow.Steps {
		got = append(got, s.Method+" "+s.Path+" "+itoa(s.Status)+" "+s.Body)
	}
	want := []string{
		"GET /login 200 001-get-login.html",
		"POST /login 303 ",
		"GET /account 200 003-get-account.html",
		"GET /api/invoices?page=1 200 004-get-api-invoices.json",
		"GET /api/invoices/FA-1/pdf 200 005-get-api-invoices-fa-1-pdf.pdf",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("steps:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if out.Flow.Steps[1].RequestBody == "" || out.Flow.Steps[1].Location != "/account" {
		t.Errorf("login POST lost its form or redirect: %+v", out.Flow.Steps[1])
	}
	if len(out.Files) != 4 {
		t.Fatalf("files = %d (%v), want 4 (3 text bodies + the PDF placeholder)", len(out.Files), keys(out.Files))
	}
	if !strings.Contains(string(out.Files["005-get-api-invoices-fa-1-pdf.pdf"]), "%PDF-") {
		t.Errorf("PDF placeholder is not a PDF: %q", out.Files["005-get-api-invoices-fa-1-pdf.pdf"])
	}
}

func TestSlim_RefusesUnredactedRecordings(t *testing.T) {
	t.Parallel()
	f := recording()
	f.Log.Entries[0].Request.Headers = []har.NV{{Name: "Cookie", Value: "sid=abcdef123456"}}
	if _, err := fixtures.Slim(f, fixtures.SlimOptions{}); !errors.Is(err, fixtures.ErrUnredacted) {
		t.Fatalf("Slim on a raw HAR = %v, want ErrUnredacted", err)
	}
}

func TestSlim_DefaultHostsAreTheFirstDocument(t *testing.T) {
	t.Parallel()
	out, err := fixtures.Slim(recording(), fixtures.SlimOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range out.Flow.Steps {
		if s.Host != "www.example.test" {
			t.Fatalf("step on %s kept, want only the first document's host", s.Host)
		}
	}
}

func TestSlim_NamesAreSafe(t *testing.T) {
	t.Parallel()
	f := har.New("facto", "test")
	f.Log.Entries = []har.Entry{entry("GET", "https://www.example.test/../../etc/passwd%00/..%2F..%2Fx?a=b", 200, "document", "text/html", "x")}
	out, err := fixtures.Slim(f, fixtures.SlimOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name := range out.Files {
		if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") || strings.ContainsRune(name, 0) {
			t.Fatalf("unsafe file name %q", name)
		}
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func itoa(i int) string { return strconv.Itoa(i) }

// TestSlim_DropsStaticAssetsByMIMEWhateverTheirResourceType (J2, Wecasa):
// an SVG sprite, a stylesheet, a font or a script fetched by the app (type
// "fetch"/"xhr"/"other") is not data a connector needs: dropped by its
// response type, so no image coordinates reach the fixtures.
func TestSlim_DropsStaticAssetsByMIMEWhateverTheirResourceType(t *testing.T) {
	t.Parallel()
	f := har.New("facto", "test")
	for _, c := range []struct{ rtype, mime, path string }{
		{"fetch", "image/svg+xml", "/packs/sprite.svg"},
		{"other", "image/svg+xml; charset=utf-8", "/packs/icons.svg"},
		{"xhr", "text/css", "/packs/app.css"},
		{"fetch", "font/woff2", "/f.woff2"},
		{"fetch", "application/javascript", "/chunk.js"},
		{"fetch", "text/javascript", "/chunk2.js"},
		{"other", "image/png", "/a.png"},
	} {
		// Recorded as facto record writes them: binary bodies dropped.
		f.Log.Entries = append(f.Log.Entries, har.RedactEntry(entry("GET", "https://www.example.test"+c.path, 200, c.rtype, c.mime, "x")))
	}
	f.Log.Entries = append(f.Log.Entries, entry("GET", "https://www.example.test/api/v1/user", 200, "fetch", "application/json", `{"id":1}`))
	out, err := fixtures.Slim(f, fixtures.SlimOptions{Hosts: []string{"www.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Flow.Steps) != 1 || out.Flow.Steps[0].Path != "/api/v1/user" {
		t.Fatalf("steps = %+v, want only the API call", out.Flow.Steps)
	}
}

// TestSlim_DropsTrackersAndBotChallenges (J2, Wecasa): Cloudflare's
// /cdn-cgi/ challenge calls are not part of the supplier flow, and the
// Google Analytics linker (_gl, _ga, utm_*, gclid, fbclid) is dropped from
// kept URLs.
func TestSlim_DropsTrackersAndBotChallenges(t *testing.T) {
	t.Parallel()
	f := har.New("facto", "test")
	f.Log.Entries = []har.Entry{
		entry("GET", "https://www.example.test/login?_gl=1*abc*_ga*MTIz&next=%2Fa&utm_source=x&gclid=1&fbclid=2", 200, "document", "text/html", "<form></form>"),
		entry("POST", "https://www.example.test/cdn-cgi/challenge-platform/h/b/jsd/oneshot/1/0.5:1:x/abc", 200, "fetch", "text/plain", "ok"),
		entry("GET", "https://www.example.test/cdn-cgi/rum?x", 204, "fetch", "", ""),
	}
	out, err := fixtures.Slim(f, fixtures.SlimOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Flow.Steps) != 1 || out.Flow.Steps[0].Path != "/login?next=%2Fa" {
		t.Fatalf("steps = %+v", out.Flow.Steps)
	}
}
