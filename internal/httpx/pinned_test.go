// Tests for NewPinned (J1 task T11, ADR 0008 "Chrome for Testing (A10)"):
// the exact-host, path-prefix client used to download from shared storage
// hosts, which ParseAllowlist keeps refusing. Every hop, the first request
// included, is checked before dialing: scheme, exact host, port 443, no
// userinfo, canonical path under the prefix. Uses the TLS test server and
// recording dialer of httpx_test.go; nothing touches the real network.
package httpx_test

import (
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/httpx"
)

const (
	pinHost   = "fournisseur.test"
	pinPrefix = "/bucket/pub/"
	pinOK     = "https://" + pinHost + pinPrefix + "1.0.0.0/linux64/archive.zip"
)

func pinnedClient(t *testing.T, e *env) *httpx.Client {
	t.Helper()
	c, err := httpx.NewPinned(pinHost, pinPrefix, e.opts())
	if err != nil {
		t.Fatalf("NewPinned: %v", err)
	}
	return c
}

func TestNewPinned_RejectsBadPins(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, host, prefix string
	}{
		{"empty host", "", pinPrefix},
		{"wildcard host", "*.fournisseur.test", pinPrefix},
		{"host with port", pinHost + ":443", pinPrefix},
		{"host with userinfo", "u@" + pinHost, pinPrefix},
		{"uppercase host", "Fournisseur.test", pinPrefix},
		{"trailing dot", pinHost + ".", pinPrefix},
		{"single label", "localhost", pinPrefix},
		{"ipv4 literal", "192.0.2.1", pinPrefix},
		{"ipv6 literal", "[::1]", pinPrefix},
		{"non-ascii host", "fournisseur.tést", pinPrefix},
		{"host with a path", pinHost + "/x", pinPrefix},
		{"empty prefix", pinHost, ""},
		{"root prefix", pinHost, "/"},
		{"prefix without leading slash", pinHost, "bucket/"},
		{"prefix without trailing slash", pinHost, "/bucket"},
		{"prefix with dot-dot", pinHost, "/bucket/../"},
		{"prefix with dot", pinHost, "/bucket/./"},
		{"prefix with empty segment", pinHost, "/bucket//pub/"},
		{"prefix percent-encoded", pinHost, "/bucket%2f/"},
		{"prefix with backslash", pinHost, `/bucket\pub/`},
		{"prefix with wildcard", pinHost, "/bucket-*/"},
		{"prefix with query", pinHost, "/bucket/?x/"},
		{"prefix with space", pinHost, "/buc ket/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := httpx.NewPinned(tt.host, tt.prefix, httpx.Options{}); !errors.Is(err, httpx.ErrInvalidAllowlist) {
				t.Fatalf("NewPinned(%q, %q) = %v, want errors.Is ErrInvalidAllowlist", tt.host, tt.prefix, err)
			}
		})
	}
}

// TestNewPinned_SharedStorageHostOnlyThroughPin: the shared storage host is
// accepted by NewPinned with a path prefix, and still refused by
// ParseAllowlist (and so by New and connector allowlists).
func TestNewPinned_SharedStorageHostOnlyThroughPin(t *testing.T) {
	t.Parallel()

	const host = "storage.googleapis.com"
	if _, err := httpx.NewPinned(host, "/chrome-for-testing-public/", httpx.Options{}); err != nil {
		t.Fatalf("NewPinned(%q) = %v, want nil", host, err)
	}
	if _, err := httpx.ParseAllowlist([]string{host}); !errors.Is(err, httpx.ErrInvalidAllowlist) {
		t.Fatalf("ParseAllowlist(%q) = %v, want it still refused", host, err)
	}
	if _, err := httpx.New([]string{host}, httpx.Options{}); !errors.Is(err, httpx.ErrInvalidAllowlist) {
		t.Fatalf("New(%q) = %v, want it still refused", host, err)
	}
}

func TestPinned_AllowsExactHostUnderPrefix(t *testing.T) {
	t.Parallel()

	for _, u := range []string{
		pinOK,
		"https://" + pinHost + ":443" + pinPrefix + "x.zip",
		pinOK + "?sig=synthetic",
		"https://" + pinHost + pinPrefix,
		// net/url drops an empty port at parse time: same target.
		"https://" + pinHost + ":" + pinPrefix + "x.zip",
	} {
		t.Run(u, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, ok)
			code, body, err := get(t, pinnedClient(t, e), u)
			if err != nil || code != http.StatusOK || body != "ok" {
				t.Fatalf("Get(%q) = %d, %q, %v; want 200 ok", u, code, body, err)
			}
		})
	}
}

// pinTricks are URLs a pinned client must refuse, with the sentinel the
// refusal wraps (nil: any error, the URL may not even parse).
// As a redirect Location, the entries listed in pinResolvesInside are
// resolved by net/http (RFC 3986 dot-segment removal, scheme-relative
// reference) to a canonical URL under the prefix, so they are followed.
var pinTricks = []struct {
	url  string
	want error
}{
	// Host, port, userinfo.
	{"https://autre.test" + pinPrefix + "x.zip", httpx.ErrDomainNotAllowed},
	{"https://x." + pinHost + pinPrefix + "x.zip", httpx.ErrDomainNotAllowed},
	{"https://" + pinHost + ".autre.test" + pinPrefix + "x.zip", httpx.ErrDomainNotAllowed},
	{"https://FOURNISSEUR.TEST" + pinPrefix + "x.zip", httpx.ErrDomainNotAllowed},
	{"https://Fournisseur.test" + pinPrefix + "x.zip", httpx.ErrDomainNotAllowed},
	{"https://" + pinHost + "." + pinPrefix + "x.zip", httpx.ErrDomainNotAllowed},
	{"https://" + pinHost + ":8443" + pinPrefix + "x.zip", httpx.ErrDomainNotAllowed},
	{"https://" + pinHost + ":0443" + pinPrefix + "x.zip", httpx.ErrDomainNotAllowed},
	{"https://" + pinHost + ":443:443" + pinPrefix + "x.zip", nil},
	{"https://user@" + pinHost + pinPrefix + "x.zip", httpx.ErrDomainNotAllowed},
	{"https://user:pw@" + pinHost + pinPrefix + "x.zip", httpx.ErrDomainNotAllowed},
	{"https://" + pinHost + "@autre.test" + pinPrefix + "x.zip", httpx.ErrDomainNotAllowed},
	{"https://xn--fournisseur-9db.test" + pinPrefix + "x.zip", httpx.ErrDomainNotAllowed},
	{"https://fournisseur.tést" + pinPrefix + "x.zip", nil},
	{"https://fournisseur\u3002test" + pinPrefix + "x.zip", nil},
	{"https://" + pinHost + "\u200b" + pinPrefix + "x.zip", nil},
	{"https://127.0.0.1" + pinPrefix + "x.zip", httpx.ErrDomainNotAllowed},
	{"https://[::1]" + pinPrefix + "x.zip", httpx.ErrDomainNotAllowed},
	// Scheme.
	{"http://" + pinHost + pinPrefix + "x.zip", httpx.ErrInsecureScheme},
	{"ftp://" + pinHost + pinPrefix + "x.zip", httpx.ErrInsecureScheme},
	{"//" + pinHost + pinPrefix + "x.zip", nil},
	// Path.
	{"https://" + pinHost + "/bucket/other/x.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + "/bucket/pubx/x.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + "/bucket/PUB/x.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + "/bucket/pub", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + "/bucket", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + "/", httpx.ErrPathNotAllowed},
	{"https://" + pinHost, httpx.ErrPathNotAllowed},
	{"https://" + pinHost + pinPrefix + "../other/x.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + pinPrefix + "a/../../other/x.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + pinPrefix + "a/../x.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + pinPrefix + "./x.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + pinPrefix + "..", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + pinPrefix + "%2e%2e/other/x.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + pinPrefix + "%2E%2E/other/x.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + pinPrefix + ".%2e/other/x.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + "/bucket/pub%2f..%2fother/x.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + pinPrefix + "a%2fb.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + pinPrefix + "a%5cb.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + pinPrefix + "%41.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + pinPrefix + "a%00.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + pinPrefix + "a b.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + pinPrefix + `a\..\..\x.zip`, httpx.ErrPathNotAllowed},
	{"https://" + pinHost + "/bucket//pub/x.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + pinPrefix + "a//x.zip", httpx.ErrPathNotAllowed},
	{"https://" + pinHost + "//bucket/pub/x.zip", httpx.ErrPathNotAllowed},
}

// pinResolvesInside are the pinTricks a redirect may follow: once resolved
// against the request URL they name a canonical path under the prefix on
// the pinned host.
var pinResolvesInside = []string{
	"https://" + pinHost + pinPrefix + "a/../x.zip",
	"https://" + pinHost + pinPrefix + "./x.zip",
	"//" + pinHost + pinPrefix + "x.zip",
}

// assertPinRefusal fails unless err is a refusal wrapping want (any error
// when want is nil).
func assertPinRefusal(t *testing.T, u string, err, want error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%q was not refused", u)
	}
	if want != nil && !errors.Is(err, want) {
		t.Fatalf("%q: err = %v, want errors.Is %v", u, err, want)
	}
}

func TestPinned_DirectTricksNeverDial(t *testing.T) {
	t.Parallel()

	for _, tt := range pinTricks {
		t.Run(tt.url, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, ok)
			_, _, err := get(t, pinnedClient(t, e), tt.url)
			assertPinRefusal(t, tt.url, err, tt.want)
			if d := e.dialed(); len(d) != 0 || e.hits.Load() != 0 {
				t.Fatalf("Get(%q) dialed %q, %d server hits; want the request refused before dialing", tt.url, d, e.hits.Load())
			}
		})
	}
}

func TestPinned_RedirectTricksRefusedBeforeSending(t *testing.T) {
	t.Parallel()

	relative := []struct {
		url  string
		want error
	}{
		{"/bucket/other/x.zip", httpx.ErrPathNotAllowed},
		{"../other/x.zip", httpx.ErrPathNotAllowed},
		{"../../x.zip", httpx.ErrPathNotAllowed},
		{pinPrefix + "../other/x.zip", httpx.ErrPathNotAllowed},
		{pinPrefix + "%2e%2e/other/x.zip", httpx.ErrPathNotAllowed},
		{"//autre.test" + pinPrefix + "x.zip", httpx.ErrDomainNotAllowed},
	}
	var locations []struct {
		url  string
		want error
	}
	for _, tt := range slices.Concat(pinTricks, relative) {
		if !slices.Contains(pinResolvesInside, tt.url) {
			locations = append(locations, tt)
		}
	}
	for _, tt := range locations {
		for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
			t.Run(http.StatusText(code)+" "+tt.url, func(t *testing.T) {
				t.Parallel()
				e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == pinPrefix+"start" {
						w.Header().Set("Location", tt.url)
						w.WriteHeader(code)
						return
					}
					ok(w, r)
				})
				resp, err := pinnedClient(t, e).Get(t.Context(), "https://"+pinHost+pinPrefix+"start")
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					// A Location net/http cannot parse leaves the 30x to
					// the caller: not followed, not a leak.
					if resp.StatusCode != code {
						t.Fatalf("redirect to %q was followed (status %d)", tt.url, resp.StatusCode)
					}
				} else if tt.want != nil && !errors.Is(err, tt.want) {
					t.Fatalf("redirect to %q: err = %v, want errors.Is %v", tt.url, err, tt.want)
				}
				if got := slices.Compact(e.dialed()); len(got) != 1 || got[0] != pinHost+":443" {
					t.Fatalf("dialed %q, want only %s:443", got, pinHost)
				}
				if e.hits.Load() != 1 {
					t.Fatalf("server hit %d times, want 1 (the redirect hop must be refused before sending)", e.hits.Load())
				}
			})
		}
	}
}

func TestPinned_FollowsRedirectUnderPrefix(t *testing.T) {
	t.Parallel()

	locs := append([]string{pinPrefix + "mirror/x.zip", "mirror/x.zip", "https://" + pinHost + pinPrefix + "m/x.zip?sig=synthetic"}, pinResolvesInside...)
	for _, loc := range locs {
		t.Run(loc, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == pinPrefix+"start" {
					http.Redirect(w, r, loc, http.StatusFound)
					return
				}
				ok(w, r)
			})
			code, body, err := get(t, pinnedClient(t, e), "https://"+pinHost+pinPrefix+"start")
			if err != nil || code != http.StatusOK || body != "ok" {
				t.Fatalf("Get = %d, %q, %v; want the same-prefix redirect followed", code, body, err)
			}
			if e.hits.Load() != 2 {
				t.Fatalf("server hit %d times, want 2", e.hits.Load())
			}
		})
	}
}

func TestPinned_HostHeaderOverrideRefused(t *testing.T) {
	t.Parallel()

	for _, h := range []string{"autre.test", "FOURNISSEUR.TEST", pinHost + ".", pinHost + ":8443", "x." + pinHost} {
		t.Run(h, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, ok)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, pinOK, http.NoBody)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = h
			resp, err := pinnedClient(t, e).Do(req)
			if err == nil {
				_ = resp.Body.Close()
			}
			assertPinRefusal(t, h, err, httpx.ErrDomainNotAllowed)
			if len(e.dialed()) != 0 {
				t.Fatalf("dialed %q, want nothing", e.dialed())
			}
		})
	}
}

func TestPinned_ErrorsOmitPathQueryAndFragment(t *testing.T) {
	t.Parallel()

	// Named marker, not secret, so that no secret-shaped assignment sits in
	// the source for secret scanners (SEC-J1-9); the value is unchanged.
	const marker = "synthetic-pin-secret-0f3c"
	loc := "/bucket/other/" + marker + "/x.zip?sig=" + marker + "#" + marker
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == pinPrefix+"start" {
			w.Header().Set("Location", loc)
			w.WriteHeader(http.StatusFound)
			return
		}
		ok(w, r)
	})
	_, _, err := get(t, pinnedClient(t, e), "https://"+pinHost+pinPrefix+"start")
	if !errors.Is(err, httpx.ErrPathNotAllowed) {
		t.Fatalf("err = %v, want errors.Is ErrPathNotAllowed", err)
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		if strings.Contains(e.Error(), marker) {
			t.Fatalf("error chain carries the refused path, query or fragment: %v", e)
		}
	}
}
