package record_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/har"
	"github.com/FlorianRuen/facto/internal/record"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// fakeTap is a scripted record.Source.
type fakeTap struct {
	ch     chan browser.Event
	mu     sync.Mutex
	bodies map[string]struct {
		body string
		b64  bool
	}
	dropped int64
}

func newFakeTap() *fakeTap {
	return &fakeTap{ch: make(chan browser.Event, 64), bodies: map[string]struct {
		body string
		b64  bool
	}{}}
}

func (f *fakeTap) Events() <-chan browser.Event { return f.ch }
func (f *fakeTap) Dropped() int64               { return f.dropped }
func (f *fakeTap) Body(_ context.Context, id string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.bodies[id]
	if !ok {
		return "", false, errors.New("no body")
	}
	return b.body, b.b64, nil
}

func (f *fakeTap) emit(t *testing.T, method string, params any) {
	t.Helper()
	b, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	f.ch <- browser.Event{Method: method, SessionID: "page", Params: b}
}

func (f *fakeTap) setBody(id, body string, b64 bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bodies[id] = struct {
		body string
		b64  bool
	}{body, b64}
}

// loginFlow scripts a login POST (password, CSRF, session cookie) then a
// JSON list and a PDF.
func loginFlow(t *testing.T, f *fakeTap) []string {
	t.Helper()
	pw := testsecrets.Canary(t, testsecrets.Password)
	csrf := testsecrets.Canary(t, testsecrets.Token)
	sess := testsecrets.Canary(t, testsecrets.Session)
	login := "user-" + testsecrets.Canary(t, testsecrets.Token)

	f.emit(t, "Network.requestWillBeSent", map[string]any{
		"requestId": "1", "type": "Document", "wallTime": 1767225600.0,
		"request": map[string]any{
			"url": "https://www.example.test/login", "method": "POST",
			"headers":     map[string]any{"Content-Type": "application/x-www-form-urlencoded"},
			"hasPostData": true,
			"postData":    "csrf_token=" + csrf + "&username=" + login + "&password=" + pw,
		},
	})
	f.emit(t, "Network.requestWillBeSentExtraInfo", map[string]any{
		"requestId": "1",
		"headers":   map[string]any{"Cookie": "fp_csrf=" + csrf, "Content-Type": "application/x-www-form-urlencoded"},
	})
	f.emit(t, "Network.responseReceivedExtraInfo", map[string]any{
		"requestId": "1",
		"headers":   map[string]any{"Set-Cookie": "fp_session=" + sess + "; Path=/; Secure; HttpOnly", "Location": "/account"},
	})
	f.emit(t, "Network.requestWillBeSent", map[string]any{
		"requestId": "1", "type": "Document",
		"redirectResponse": map[string]any{
			"url": "https://www.example.test/login", "status": 303, "statusText": "See Other",
			"headers": map[string]any{"Location": "/account"}, "mimeType": "text/html", "protocol": "h2",
		},
		"request": map[string]any{"url": "https://www.example.test/account", "method": "GET", "headers": map[string]any{}},
	})
	f.emit(t, "Network.responseReceived", map[string]any{
		"requestId": "1", "type": "Document",
		"response": map[string]any{
			"url": "https://www.example.test/account", "status": 200, "statusText": "OK",
			"headers": map[string]any{"Content-Type": "text/html"}, "mimeType": "text/html", "protocol": "h2",
		},
	})
	f.setBody("1", `<html><div id="account">ok</div></html>`, false)
	f.emit(t, "Network.loadingFinished", map[string]any{"requestId": "1", "encodedDataLength": 40})

	f.emit(t, "Network.requestWillBeSent", map[string]any{
		"requestId": "2", "type": "Fetch",
		"request": map[string]any{"url": "https://www.example.test/api/invoices?page=1", "method": "GET", "headers": map[string]any{"Authorization": "Bearer " + sess}},
	})
	f.emit(t, "Network.responseReceived", map[string]any{
		"requestId": "2", "type": "Fetch",
		"response": map[string]any{"url": "https://www.example.test/api/invoices?page=1", "status": 200, "headers": map[string]any{"Content-Type": "application/json"}, "mimeType": "application/json"},
	})
	f.setBody("2", `{"invoices":[{"id":"FP-1","amount_cents":100}],"session_token":"`+sess+`"}`, false)
	f.emit(t, "Network.loadingFinished", map[string]any{"requestId": "2"})

	f.emit(t, "Network.requestWillBeSent", map[string]any{
		"requestId": "3", "type": "Other",
		"request": map[string]any{"url": "https://www.example.test/api/invoices/FP-1/pdf", "method": "GET", "headers": map[string]any{}},
	})
	f.emit(t, "Network.responseReceived", map[string]any{
		"requestId": "3", "type": "Other",
		"response": map[string]any{"url": "https://www.example.test/api/invoices/FP-1/pdf", "status": 200, "headers": map[string]any{"Content-Type": "application/pdf"}, "mimeType": "application/pdf"},
	})
	f.setBody("3", base64.StdEncoding.EncodeToString([]byte("%PDF-1.7 "+pw)), true)
	f.emit(t, "Network.loadingFinished", map[string]any{"requestId": "3", "encodedDataLength": 20})

	// A request still in flight when the recording stops.
	f.emit(t, "Network.requestWillBeSent", map[string]any{
		"requestId": "4", "type": "XHR",
		"request": map[string]any{"url": "https://www.example.test/api/slow", "method": "GET", "headers": map[string]any{"Cookie": "fp_session=" + sess}},
	})
	return []string{pw, csrf, sess, login}
}

// run records every scripted event: the closed channel ends Run, as the
// end of the browser does.
func run(t *testing.T, f *fakeTap) *har.File {
	t.Helper()
	close(f.ch)
	rec := record.New(record.Options{Clock: clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)), Creator: "facto", Version: "test"})
	return rec.Run(t.Context(), f)
}

func TestRecorder_LoginFlowRedactedInMemory(t *testing.T) {
	t.Parallel()
	f := newFakeTap()
	secrets := loginFlow(t, f)
	out := run(t, f)

	var buf bytes.Buffer
	if err := har.Encode(&buf, out); err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if bytes.Contains(buf.Bytes(), []byte(s)) {
			t.Fatalf("recorded HAR holds a secret canary:\n%s", buf.Bytes())
		}
	}
	if got := har.Check(out); len(got) != 0 {
		t.Fatalf("har.Check findings on a recording: %q", got)
	}
	// Structure kept: redirect hop, final page, list, PDF, unfinished.
	var urls []string
	for _, e := range out.Log.Entries {
		urls = append(urls, e.Request.Method+" "+e.Request.URL+" "+itoa(e.Response.Status))
	}
	want := []string{
		"POST https://www.example.test/login 303",
		"GET https://www.example.test/account 200",
		"GET https://www.example.test/api/invoices?page=1 200",
		"GET https://www.example.test/api/invoices/FP-1/pdf 200",
		"GET https://www.example.test/api/slow 0",
	}
	if strings.Join(urls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("entries:\n%s\nwant:\n%s", strings.Join(urls, "\n"), strings.Join(want, "\n"))
	}
	e0 := out.Log.Entries[0]
	if e0.Response.RedirectURL != "/account" {
		t.Errorf("redirect URL = %q", e0.Response.RedirectURL)
	}
	if e0.Request.PostData == nil || !strings.Contains(e0.Request.PostData.Text, "password="+url(har.Redacted)) {
		t.Errorf("login form not kept with a redacted password: %+v", e0.Request.PostData)
	}
	if len(e0.Request.Cookies) != 1 || e0.Request.Cookies[0].Name != "fp_csrf" {
		t.Errorf("request cookie names not kept: %+v", e0.Request.Cookies)
	}
	if len(e0.Response.Cookies) != 1 || e0.Response.Cookies[0].Name != "fp_session" || !e0.Response.Cookies[0].HTTPOnly {
		t.Errorf("response cookie names/flags not kept: %+v", e0.Response.Cookies)
	}
	list := out.Log.Entries[2]
	if !strings.Contains(list.Response.Content.Text, `"amount_cents":100`) {
		t.Errorf("JSON list body lost: %q", list.Response.Content.Text)
	}
	pdf := out.Log.Entries[3]
	if pdf.Response.Content.Text != "" || pdf.Response.Content.MimeType != "application/pdf" || pdf.Response.Content.Size == 0 {
		t.Errorf("PDF content = %+v, want dropped body, type and size kept", pdf.Response.Content)
	}
	if out.Log.Entries[4].Comment == "" {
		t.Errorf("unfinished request has no comment")
	}
}

func TestRecorder_LoadingFailedAndBlockedRequestsKept(t *testing.T) {
	t.Parallel()
	f := newFakeTap()
	f.emit(t, "Network.requestWillBeSent", map[string]any{
		"requestId": "9", "type": "Image",
		"request": map[string]any{"url": "https://evil.test/pixel?token=abc", "method": "GET", "headers": map[string]any{}},
	})
	f.emit(t, "Network.loadingFailed", map[string]any{"requestId": "9", "errorText": "net::ERR_BLOCKED_BY_CLIENT", "blockedReason": "inspector"})
	out := run(t, f)
	if len(out.Log.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(out.Log.Entries))
	}
	e := out.Log.Entries[0]
	if !strings.Contains(e.Comment, "ERR_BLOCKED_BY_CLIENT") || strings.Contains(e.Request.URL, "abc") {
		t.Fatalf("failed entry = %+v", e)
	}
}

func TestRecorder_CapsEntries(t *testing.T) {
	t.Parallel()
	f := newFakeTap()
	for i := range 5 {
		f.emit(t, "Network.requestWillBeSent", map[string]any{
			"requestId": itoa(i), "request": map[string]any{"url": "https://a.test/" + itoa(i), "method": "GET", "headers": map[string]any{}},
		})
	}
	close(f.ch)
	rec := record.New(record.Options{Clock: clock.NewFake(time.Unix(0, 0)), MaxEntries: 2})
	out := rec.Run(t.Context(), f)
	if len(out.Log.Entries) != 2 || !strings.Contains(out.Log.Comment, "entries dropped") {
		t.Fatalf("entries = %d comment %q, want 2 and a drop note", len(out.Log.Entries), out.Log.Comment)
	}
}

func TestRecorder_UndecodableEventsIgnored(t *testing.T) {
	t.Parallel()
	f := newFakeTap()
	f.ch <- browser.Event{Method: "Network.requestWillBeSent", Params: []byte("{not json")}
	f.ch <- browser.Event{Method: "Network.responseReceived", Params: []byte(`{"requestId":"unknown","response":{"status":200}}`)}
	out := run(t, f)
	if len(out.Log.Entries) != 0 {
		t.Fatalf("entries = %+v, want none", out.Log.Entries)
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func url(s string) string {
	return strings.NewReplacer("[", "%5B", "]", "%5D").Replace(s)
}

// TestRecorder_StopsOnContextEnd: a cancelled context ends Run with what
// was recorded so far, even though the source stays open.
func TestRecorder_StopsOnContextEnd(t *testing.T) {
	t.Parallel()
	f := newFakeTap()
	f.emit(t, "Network.requestWillBeSent", map[string]any{
		"requestId": "1", "request": map[string]any{"url": "https://a.test/", "method": "GET", "headers": map[string]any{}},
	})
	ctx, cancel := context.WithCancel(t.Context())
	rec := record.New(record.Options{Clock: clock.NewFake(time.Unix(0, 0))})
	done := make(chan *har.File, 1)
	go func() { done <- rec.Run(ctx, f) }()
	cancel()
	out := <-done
	if out == nil || out.Log.Version != "1.2" {
		t.Fatalf("Run after cancel = %+v", out)
	}
}

// TestRecorder_CapsTotalBodyBytes (SEC-J2-5): text bodies are kept until
// MaxBodyTotal bytes in all; later ones are not fetched into the file and
// say so. Entries are still recorded.
func TestRecorder_CapsTotalBodyBytes(t *testing.T) {
	t.Parallel()
	f := newFakeTap()
	for i := range 3 {
		id := itoa(i)
		f.emit(t, "Network.requestWillBeSent", map[string]any{
			"requestId": id, "request": map[string]any{"url": "https://a.test/" + id, "method": "GET", "headers": map[string]any{}},
		})
		f.emit(t, "Network.responseReceived", map[string]any{
			"requestId": id, "response": map[string]any{"status": 200, "mimeType": "text/plain", "headers": map[string]any{}},
		})
		f.setBody(id, strings.Repeat("x", 40), false)
		f.emit(t, "Network.loadingFinished", map[string]any{"requestId": id, "encodedDataLength": 40})
	}
	close(f.ch)
	rec := record.New(record.Options{Clock: clock.NewFake(time.Unix(0, 0)), MaxBodyTotal: 100})
	out := rec.Run(t.Context(), f)
	if len(out.Log.Entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(out.Log.Entries))
	}
	kept := 0
	for _, e := range out.Log.Entries {
		if e.Response.Content.Text != "" {
			kept++
			continue
		}
		if !strings.Contains(e.Response.Content.Comment, "size cap") {
			t.Errorf("dropped body comment = %q, want a size cap note", e.Response.Content.Comment)
		}
	}
	if kept != 2 {
		t.Fatalf("bodies kept = %d, want 2 under a 100-byte cap", kept)
	}
}
