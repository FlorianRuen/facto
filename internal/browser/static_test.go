package browser_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// Path-scoped static allowlist (J2, ADR 0008 A11 "per-connector CDN"):
// a supplier's JavaScript app may live on shared storage
// (storage.googleapis.com/<bucket>/…) that the domain allowlist refuses on
// purpose. A static entry lets the login page GET (or HEAD) one exact
// https host under one path prefix, and nothing else: no other path, no
// other method, no navigation, no typing, no cookie export, no httpx.

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

func newStaticPage(t *testing.T) *pageEnv {
	t.Helper()
	f, c, opts, logs := newEnv(t)
	opts.Static = []string{testStatic}
	p, err := browser.NewPage(testCtx(t), c, opts)
	if err != nil {
		t.Fatalf("NewPage = %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return &pageEnv{f: f, c: c, p: p, logs: logs}
}

func TestFetch_StaticAllowsGETUnderPrefixOnly(t *testing.T) {
	t.Parallel()
	e := newStaticPage(t)
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
		continued(t, e.f, fakeSessionID, id)
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
	}
	for i, u := range refused {
		id := fmt.Sprintf("no-%d", i)
		e.f.requestPaused(fakeSessionID, id, u, "Script", nil)
		blocked(t, e.f, fakeSessionID, id)
		neverContinued(t, e.f, fakeSessionID, id)
	}
}

func TestFetch_StaticRefusesWritesAndCredentials(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "post"} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			e := newStaticPage(t)
			e.navigate(t, loginURL)
			e.f.requestPaused(fakeSessionID, "w-1", testStatic+"collect", "XHR", map[string]any{
				"request": map[string]any{"url": testStatic + "collect", "method": method, "headers": map[string]any{}},
			})
			blocked(t, e.f, fakeSessionID, "w-1")
		})
	}
	// HEAD is a read.
	e := newStaticPage(t)
	e.navigate(t, loginURL)
	e.f.requestPaused(fakeSessionID, "h-1", testStatic+"a.js", "Script", map[string]any{
		"request": map[string]any{"url": testStatic + "a.js", "method": "HEAD", "headers": map[string]any{}},
	})
	continued(t, e.f, fakeSessionID, "h-1")
	// A missing method is not a read.
	e.f.requestPaused(fakeSessionID, "m-1", testStatic+"a.js", "Script", map[string]any{
		"request": map[string]any{"url": testStatic + "a.js", "headers": map[string]any{}},
	})
	blocked(t, e.f, fakeSessionID, "m-1")
}

func TestFetch_StaticRedirectOffPrefixBlocked(t *testing.T) {
	t.Parallel()
	e := newStaticPage(t)
	e.navigate(t, loginURL)
	e.f.requestPaused(fakeSessionID, "s-1", testStatic+"main.js", "Script", nil)
	continued(t, e.f, fakeSessionID, "s-1")
	e.f.requestPaused(fakeSessionID, "s-2", "https://storage.googleapis.com/attacker/main.js", "Script", map[string]any{
		"redirectedRequestId": "s-1",
	})
	blocked(t, e.f, fakeSessionID, "s-2")
}

func TestPage_StaticNeverNavigable(t *testing.T) {
	t.Parallel()
	e := newStaticPage(t)
	if err := e.p.Navigate(testCtx(t), testStatic+"index.html"); !errors.Is(err, browser.ErrURLRefused) {
		t.Fatalf("Navigate to a static prefix = %v, want ErrURLRefused", err)
	}
	// A top-level document on the static host is blocked too: a page there
	// would run with the login page's privileges in the browser context.
	e.navigate(t, loginURL)
	e.f.requestPaused(fakeSessionID, "d-1", testStatic+"index.html", "Document", nil)
	blocked(t, e.f, fakeSessionID, "d-1")
}

func TestNewPage_RefusesBadStatic(t *testing.T) {
	t.Parallel()
	_, c, opts, _ := newEnv(t)
	opts.Static = []string{"https://storage.googleapis.com/"}
	if _, err := browser.NewPage(testCtx(t), c, opts); !errors.Is(err, browser.ErrInvalidStatic) {
		t.Fatalf("NewPage with a whole-host static entry = %v, want ErrInvalidStatic", err)
	}
}

func TestFlags_StaticHostsResolvable(t *testing.T) {
	t.Parallel()
	opts := browser.Options{GOOS: "linux", ProfileDir: "/tmp/p", AllowedDomains: testAllow, Static: []string{testStatic}}
	args, err := browser.Flags(opts)
	if err != nil {
		t.Fatalf("Flags: %v", err)
	}
	i := slices.IndexFunc(args, func(a string) bool { return strings.HasPrefix(a, "--host-resolver-rules=") })
	if i < 0 || !strings.Contains(args[i], "EXCLUDE storage.googleapis.com") {
		t.Fatalf("resolver rules %q lack the static host", args)
	}
	if strings.Contains(args[i], "supplier-app-prod") {
		t.Fatalf("a path leaked into the resolver rules: %q", args[i])
	}
	opts.Static = []string{"https://storage.googleapis.com/"}
	if _, err := browser.Flags(opts); !errors.Is(err, browser.ErrInvalidStatic) {
		t.Fatalf("Flags with a whole-host static entry = %v, want ErrInvalidStatic", err)
	}
}
