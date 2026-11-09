package browser_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
)

// Path-scoped static allowlist (J2, ADR 0008 A11 "per-connector CDN"):
// a supplier's JavaScript app may live on shared storage
// (storage.googleapis.com/<bucket>/…) that the domain allowlist refuses on
// purpose. A static entry lets the login page GET (or HEAD) one exact
// https host under one path prefix, and nothing else: no other path, no
// other method, no navigation, no typing, no cookie export. Chrome never
// resolves that host (SEC-J2-1: a WebSocket, which Fetch never sees, would
// otherwise reach any path of it): facto downloads an allowed request
// itself (StaticClients) and fulfills it.

const testStatic = "https://storage.googleapis.com/supplier-app-prod/"

func TestParseStatic_AcceptsOnlyExactHTTPSPathPrefixes(t *testing.T) {
	t.Parallel()
	ok := []string{
		"https://storage.googleapis.com/supplier-app-prod/",
		"https://storage.googleapis.com/supplier-app-prod/customer-area/assets/",
		"https://cdn.example.net/app/v1/",
		"https://STORAGE.googleapis.com/supplier-app-prod/",
	}
	for _, s := range ok {
		if _, err := browser.ParseStatic([]string{s}); err != nil {
			t.Errorf("ParseStatic(%q) = %v, want ok", s, err)
		}
	}
	bad := []string{
		"",
		"http://storage.googleapis.com/b/",
		"https://storage.googleapis.com/",           // whole host
		"https://storage.googleapis.com",            // no path
		"https://storage.googleapis.com/b",          // no trailing slash: /b2 would match
		"https://*.googleapis.com/b/",               // wildcard
		"https://storage.googleapis.com:8443/b/",    // port
		"https://storage.googleapis.com:443/b/",     // explicit port, keep one spelling
		"https://u:p@storage.googleapis.com/b/",     // userinfo
		"https://storage.googleapis.com/b/?x=1",     // query
		"https://storage.googleapis.com/b/#f",       // fragment
		"https://storage.googleapis.com/a/../b/",    // dot segment
		"https://storage.googleapis.com/a/./b/",     // dot segment
		"https://storage.googleapis.com//b/",        // empty segment
		"https://storage.googleapis.com/a%2fb/",     // escape
		"https://storage.googleapis.com/a\\b/",      // backslash
		"https://storage.googleapis.com/a b/",       // space
		"https://127.0.0.1/b/",                      // IP literal
		"https://[::1]/b/",                          // IP literal
		"https://localhost/b/",                      // loopback name
		"https://storage.googleapis.com/b,EXCLUDE/", // flag syntax
		"https://storage.googleapis.com/b/\x00/",    // control
		"https://com/b/",                            // single label
	}
	for _, s := range bad {
		if _, err := browser.ParseStatic([]string{s}); !errors.Is(err, browser.ErrInvalidStatic) {
			t.Errorf("ParseStatic(%q) = %v, want ErrInvalidStatic", s, err)
		}
	}
}

// staticCall is one facto-side download a test page asked for.
type staticCall struct {
	host, prefix, method, url string
	header                    map[string][]string
}

// fakeStatic records the downloads and answers them with resp (or err).
type fakeStatic struct {
	mu    sync.Mutex
	calls []staticCall
	resp  browser.StaticResponse
	err   error
	block chan struct{} // when set, every download waits for it
}

func (s *fakeStatic) clients() browser.StaticClients {
	return func(host, prefix string) (browser.StaticGet, error) {
		return func(ctx context.Context, method, rawURL string, header map[string][]string) (browser.StaticResponse, error) {
			if s.block != nil {
				select {
				case <-s.block:
				case <-ctx.Done():
					return browser.StaticResponse{}, ctx.Err()
				}
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			s.calls = append(s.calls, staticCall{host: host, prefix: prefix, method: method, url: rawURL, header: header})
			return s.resp, s.err
		}, nil
	}
}

func (s *fakeStatic) snapshot() []staticCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

const staticJS = "console.log('app')"

func newStaticPage(t *testing.T) (*pageEnv, *fakeStatic) {
	t.Helper()
	f, c, opts, logs := newEnv(t)
	fs := &fakeStatic{resp: browser.StaticResponse{
		Status: 200,
		Header: map[string][]string{
			"Content-Type":                {"text/javascript"},
			"Access-Control-Allow-Origin": {"*"},
			"Set-Cookie":                  {"tracker=1"},
			"Content-Encoding":            {"gzip"},
			"X-Goog-Meta-Owner":           {"someone"},
		},
		Body: []byte(staticJS),
	}}
	opts.Static = []string{testStatic}
	opts.StaticClients = fs.clients()
	p, err := browser.NewPage(testCtx(t), c, opts)
	if err != nil {
		t.Fatalf("NewPage = %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return &pageEnv{f: f, c: c, p: p, logs: logs}, fs
}

// fulfilled waits for the fulfillRequest of requestID on the page session and
// returns its params; the request is never continued (Chrome cannot
// resolve a static host).
func fulfilled(t *testing.T, f *fakeCDP, requestID string) map[string]any {
	t.Helper()
	got := f.waitCalls(t, 1, isCall("Fetch.fulfillRequest", fakeSessionID, requestID))
	for _, c := range f.snapshot() {
		if c.Method == "Fetch.continueRequest" && c.Params["requestId"] == requestID {
			t.Errorf("static request %s continued to Chrome's network", requestID)
		}
	}
	return got[0].Params
}

func TestFetch_StaticFulfilledByFactoUnderPrefixOnly(t *testing.T) {
	t.Parallel()
	e, fs := newStaticPage(t)
	e.navigate(t, loginURL)
	allowed := []string{
		testStatic + "customer-area/assets/main-BrDrKFCX.js",
		testStatic + "x.css?v=3",
		"https://Storage.GoogleAPIs.com/supplier-app-prod/a.js",
		"https://storage.googleapis.com:443/supplier-app-prod/a.js",
	}
	for i, u := range allowed {
		id := fmt.Sprintf("ok-%d", i)
		e.f.requestPaused(fakeSessionID, id, u, "Script", nil)
		params := fulfilled(t, e.f, id)
		if params["responseCode"] != float64(200) {
			t.Errorf("%s responseCode = %v, want 200", id, params["responseCode"])
		}
		if params["body"] != base64.StdEncoding.EncodeToString([]byte(staticJS)) {
			t.Errorf("%s body = %v, want the downloaded file", id, params["body"])
		}
	}
	calls := fs.snapshot()
	if len(calls) != len(allowed) {
		t.Fatalf("facto-side downloads = %d, want %d", len(calls), len(allowed))
	}
	for i, c := range calls {
		if c.host != "storage.googleapis.com" || c.prefix != "/supplier-app-prod/" || c.method != "GET" || c.url != allowed[i] {
			t.Errorf("download %d = %+v, want GET %s on the entry's pinned client", i, c, allowed[i])
		}
	}
	refused := []string{
		"https://storage.googleapis.com/other-bucket/evil.js",
		"https://storage.googleapis.com/supplier-app-prod-evil/x.js",
		"https://storage.googleapis.com/supplier-app-prod",
		"https://storage.googleapis.com/supplier-app-prod/../other/x.js",
		"https://storage.googleapis.com/supplier-app-prod/%2e%2e/other/x.js",
		"https://storage.googleapis.com/supplier-app-prod/a%2f..%2f..%2fother/x.js",
		"https://storage.googleapis.com/supplier-app-prod/a%5c..%5cother/x.js",
		"https://storage.googleapis.com/supplier-app-prod/a\\b.js",
		"http://storage.googleapis.com/supplier-app-prod/a.js",
		"https://storage.googleapis.com:8443/supplier-app-prod/a.js",
		"https://u@storage.googleapis.com/supplier-app-prod/a.js",
		"https://googleapis.com/supplier-app-prod/a.js",
		"https://evil.storage.googleapis.com/supplier-app-prod/a.js",
		"wss://storage.googleapis.com/supplier-app-prod/ws",
		// The pinned client refuses these too: never sent to it.
		"https://storage.googleapis.com/supplier-app-prod/a%20b.js",
		"https://storage.googleapis.com/supplier-app-prod//x.js",
	}
	for i, u := range refused {
		id := fmt.Sprintf("no-%d", i)
		e.f.requestPaused(fakeSessionID, id, u, "Script", nil)
		blocked(t, e.f, fakeSessionID, id)
		neverContinued(t, e.f, fakeSessionID, id)
	}
	if n := len(fs.snapshot()); n != len(allowed) {
		t.Errorf("refused requests reached the facto-side download: %d calls, want %d", n, len(allowed))
	}
}

// TestFetch_StaticHeadersFiltered: only CORS/range/cache request headers
// reach the static host (never a cookie, an authorization or a header the
// page chose), and only the listed response headers reach Chrome (never
// Set-Cookie, never Content-Encoding of a body httpx already decoded).
func TestFetch_StaticHeadersFiltered(t *testing.T) {
	t.Parallel()
	e, fs := newStaticPage(t)
	e.navigate(t, loginURL)
	e.f.requestPaused(fakeSessionID, "h-1", testStatic+"a.js", "Script", map[string]any{
		"request": map[string]any{"url": testStatic + "a.js", "method": "GET", "headers": map[string]any{
			"Origin": "https://login.supplier.example", "Range": "bytes=0-9", "Accept": "*/*",
			"Cookie": "sid=SECRET", "Authorization": "Bearer SECRET", "X-Exfil": "SECRET", "Referer": "https://login.supplier.example/?u=SECRET",
		}},
	})
	params := fulfilled(t, e.f, "h-1")
	calls := fs.snapshot()
	if len(calls) != 1 {
		t.Fatalf("downloads = %d, want 1", len(calls))
	}
	for k, v := range calls[0].header {
		if strings.Contains(strings.Join(v, ","), "SECRET") {
			t.Errorf("request header %s forwarded to the static host", k)
		}
	}
	for _, k := range []string{"Origin", "Range", "Accept"} {
		if len(calls[0].header[k]) != 1 {
			t.Errorf("request header %s not forwarded: %v", k, calls[0].header)
		}
	}
	hdrs, _ := params["responseHeaders"].([]any)
	names := map[string]bool{}
	for _, h := range hdrs {
		m, _ := h.(map[string]any)
		names[strings.ToLower(fmt.Sprint(m["name"]))] = true
	}
	for _, want := range []string{"content-type", "access-control-allow-origin"} {
		if !names[want] {
			t.Errorf("response header %s not handed back: %v", want, names)
		}
	}
	for _, never := range []string{"set-cookie", "content-encoding", "x-goog-meta-owner"} {
		if names[never] {
			t.Errorf("response header %s handed back to Chrome", never)
		}
	}
}

func TestFetch_StaticRefusesWritesAndCredentials(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "post"} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			e, fs := newStaticPage(t)
			e.navigate(t, loginURL)
			e.f.requestPaused(fakeSessionID, "w-1", testStatic+"collect", "XHR", map[string]any{
				"request": map[string]any{"url": testStatic + "collect", "method": method, "headers": map[string]any{}},
			})
			blocked(t, e.f, fakeSessionID, "w-1")
			if n := len(fs.snapshot()); n != 0 {
				t.Errorf("%s reached the facto-side download (%d calls)", method, n)
			}
		})
	}
	// HEAD is a read.
	e, fs := newStaticPage(t)
	e.navigate(t, loginURL)
	e.f.requestPaused(fakeSessionID, "h-1", testStatic+"a.js", "Script", map[string]any{
		"request": map[string]any{"url": testStatic + "a.js", "method": "HEAD", "headers": map[string]any{}},
	})
	fulfilled(t, e.f, "h-1")
	if c := fs.snapshot(); len(c) != 1 || c[0].method != "HEAD" {
		t.Errorf("HEAD download = %+v, want one HEAD", c)
	}
	// A missing method is not a read.
	e.f.requestPaused(fakeSessionID, "m-1", testStatic+"a.js", "Script", map[string]any{
		"request": map[string]any{"url": testStatic + "a.js", "headers": map[string]any{}},
	})
	blocked(t, e.f, fakeSessionID, "m-1")
}

func TestFetch_StaticRedirectOffPrefixBlocked(t *testing.T) {
	t.Parallel()
	e, _ := newStaticPage(t)
	e.navigate(t, loginURL)
	e.f.requestPaused(fakeSessionID, "s-1", testStatic+"main.js", "Script", nil)
	fulfilled(t, e.f, "s-1")
	e.f.requestPaused(fakeSessionID, "s-2", "https://storage.googleapis.com/attacker/main.js", "Script", map[string]any{
		"redirectedRequestId": "s-1",
	})
	blocked(t, e.f, fakeSessionID, "s-2")
}

// TestFetch_StaticDownloadFailureFailsRequest: a facto-side error (pin
// refused a redirect hop, network, body over MaxStaticBody) fails the
// request; it is never continued to Chrome's network.
func TestFetch_StaticDownloadFailureFailsRequest(t *testing.T) {
	t.Parallel()
	for name, set := range map[string]func(*fakeStatic){
		"error":     func(s *fakeStatic) { s.err = errors.New("pinned: path not allowed") },
		"too large": func(s *fakeStatic) { s.resp.Body = make([]byte, browser.MaxStaticBody+1) },
		"no status": func(s *fakeStatic) { s.resp.Status = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e, fs := newStaticPage(t)
			fs.mu.Lock()
			set(fs)
			fs.mu.Unlock()
			e.navigate(t, loginURL)
			e.f.requestPaused(fakeSessionID, "f-1", testStatic+"main.js", "Script", nil)
			e.f.waitCalls(t, 1, isCall("Fetch.failRequest", fakeSessionID, "f-1"))
			for _, c := range e.f.snapshot() {
				if (c.Method == "Fetch.continueRequest" || c.Method == "Fetch.fulfillRequest") && c.Params["requestId"] == "f-1" {
					t.Errorf("failed static download answered with %s", c.Method)
				}
			}
		})
	}
}

func TestPage_StaticNeverNavigable(t *testing.T) {
	t.Parallel()
	e, fs := newStaticPage(t)
	if err := e.p.Navigate(testCtx(t), testStatic+"index.html"); !errors.Is(err, browser.ErrURLRefused) {
		t.Fatalf("Navigate to a static prefix = %v, want ErrURLRefused", err)
	}
	// A top-level document on the static host is blocked too: a page there
	// would run with the login page's privileges in the browser context.
	e.navigate(t, loginURL)
	e.f.requestPaused(fakeSessionID, "d-1", testStatic+"index.html", "Document", nil)
	blocked(t, e.f, fakeSessionID, "d-1")
	if n := len(fs.snapshot()); n != 0 {
		t.Errorf("a document reached the facto-side download (%d calls)", n)
	}
}

func TestNewPage_RefusesBadStatic(t *testing.T) {
	t.Parallel()
	_, c, opts, _ := newEnv(t)
	opts.Static = []string{"https://storage.googleapis.com/"}
	opts.StaticClients = (&fakeStatic{}).clients()
	if _, err := browser.NewPage(testCtx(t), c, opts); !errors.Is(err, browser.ErrInvalidStatic) {
		t.Fatalf("NewPage with a whole-host static entry = %v, want ErrInvalidStatic", err)
	}
}

// TestNewPage_StaticNeedsFactoSideClient: static entries without
// StaticClients are refused (nothing would serve them; continuing them
// would need a resolvable host).
func TestNewPage_StaticNeedsFactoSideClient(t *testing.T) {
	t.Parallel()
	_, c, opts, _ := newEnv(t)
	opts.Static = []string{testStatic}
	if _, err := browser.NewPage(testCtx(t), c, opts); !errors.Is(err, browser.ErrInvalidStatic) {
		t.Fatalf("NewPage with static entries and no StaticClients = %v, want ErrInvalidStatic", err)
	}
	opts.StaticClients = func(string, string) (browser.StaticGet, error) { return nil, errors.New("no client") }
	if _, err := browser.NewPage(testCtx(t), c, opts); !errors.Is(err, browser.ErrInvalidStatic) {
		t.Fatalf("NewPage with a failing StaticClients = %v, want ErrInvalidStatic", err)
	}
}

// TestFlags_StaticHostsNeverResolvable (SEC-J2-1): a static host stays
// ~NOTFOUND in Chrome, so no WebSocket (which Fetch never sees) or any
// other request can reach it; paths never reach the flags.
func TestFlags_StaticHostsNeverResolvable(t *testing.T) {
	t.Parallel()
	opts := browser.Options{GOOS: "linux", ProfileDir: "/tmp/p", AllowedDomains: testAllow, Static: []string{testStatic}}
	args, err := browser.Flags(opts)
	if err != nil {
		t.Fatalf("Flags: %v", err)
	}
	i := slices.IndexFunc(args, func(a string) bool { return strings.HasPrefix(a, "--host-resolver-rules=") })
	if i < 0 || !strings.Contains(args[i], "MAP * ~NOTFOUND") {
		t.Fatalf("resolver rules missing: %q", args)
	}
	if strings.Contains(args[i], "storage.googleapis.com") || strings.Contains(args[i], "supplier-app-prod") {
		t.Fatalf("the static host is resolvable in Chrome: %q", args[i])
	}
	opts.Static = []string{"https://storage.googleapis.com/"}
	if _, err := browser.Flags(opts); !errors.Is(err, browser.ErrInvalidStatic) {
		t.Fatalf("Flags with a whole-host static entry = %v, want ErrInvalidStatic", err)
	}
}

// TestFetch_StaticPendingCapped: a page that floods static requests while
// downloads are slow gets the extra ones failed at once, never queued
// without bound.
func TestFetch_StaticPendingCapped(t *testing.T) {
	t.Parallel()
	e, fs := newStaticPage(t)
	fs.mu.Lock()
	fs.block = make(chan struct{})
	fs.mu.Unlock()
	e.navigate(t, loginURL)
	const n = 200
	for i := range n {
		e.f.requestPaused(fakeSessionID, fmt.Sprintf("p-%d", i), testStatic+fmt.Sprintf("a%d.js", i), "Script", nil)
	}
	// Every request beyond the cap is failed while the first ones are
	// still blocked in their download.
	failed := e.f.waitCalls(t, n-128, func(c cdpCall) bool { return c.Method == "Fetch.failRequest" })
	if len(failed) < n-128 {
		t.Fatalf("failed = %d, want >= %d", len(failed), n-128)
	}
	close(fs.block)
	e.f.waitCalls(t, 128, func(c cdpCall) bool { return c.Method == "Fetch.fulfillRequest" })
}

// TestFetch_StaticBodiesHeldBounded (SEC-J2-9): one slot covers the
// download and the hand-over to Chrome. While fulfillRequest is stuck, no
// more than the in-flight limit (6) of downloads ever start, so at most
// that many bodies (and their base64 copies) are held.
func TestFetch_StaticBodiesHeldBounded(t *testing.T) {
	t.Parallel()
	e, fs := newStaticPage(t)
	release := make(chan struct{})
	e.f.setIntercept("Fetch.fulfillRequest", func(cdpCall) any {
		<-release
		return nil
	})
	e.navigate(t, loginURL)
	const n = 20
	for i := range n {
		e.f.requestPaused(fakeSessionID, fmt.Sprintf("b-%d", i), testStatic+fmt.Sprintf("b%d.js", i), "Script", nil)
	}
	e.f.waitCalls(t, 1, func(c cdpCall) bool { return c.Method == "Fetch.fulfillRequest" })
	deadline := time.NewTimer(300 * time.Millisecond)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for done := false; !done; {
		select {
		case <-deadline.C:
			done = true
		case <-tick.C:
		}
		if got := len(fs.snapshot()); got > 6 {
			close(release)
			t.Fatalf("%d downloads started while fulfillRequest was stuck, want <= 6", got)
		}
	}
	close(release)
	e.f.waitCalls(t, n, func(c cdpCall) bool { return c.Method == "Fetch.fulfillRequest" })
}
