// Tests for package httpx (J0 task T11): the only way facto does network I/O
// (CLAUDE.md rule 5). Spec: docs/spec.md "Threat model" (exfiltration by a
// connector: per-connector domain allowlist enforced by the HTTP client) and
// the security checklist (Network).
//
// No test touches the real network: servers are httptest TLS servers with a
// certificate generated here for *.test names, and every client gets
// Options.DialContext routing all connections to that server while recording
// the requested addresses.
//
// Import rule: httpx imports only the standard library. It must NOT import
// internal/connector. The allowlist syntax lives here (ParseAllowlist) and
// connector.ValidateInfo is expected to delegate to it so there is a single
// source of truth; TestParseAllowlist_AgreesWithConnectorValidateInfo pins
// that they agree.
//
// Expected API (implementer: follow exactly):
//
//	var (
//	    ErrDomainNotAllowed = errors.New("httpx: domain not allowed")
//	    ErrInsecureScheme   = errors.New("httpx: only https is allowed")
//	    ErrInvalidAllowlist = errors.New("httpx: invalid allowlist")
//	    ErrBodyTooLarge     = errors.New("httpx: body too large")
//	)
//
//	const (
//	    DefaultTimeout      = 60 * time.Second
//	    DefaultMaxRedirects = 10
//	)
//
//	// Allowlist is a parsed set of host patterns. The zero value allows nothing.
//	type Allowlist struct{ /* unexported */ }
//	// ParseAllowlist accepts one or more patterns, each either a bare host
//	// ("api.example.com") or "*." followed by a bare host. Refused (wraps
//	// ErrInvalidAllowlist): empty list, empty entry, scheme, path, port,
//	// userinfo, query, whitespace, NUL, any other "*", leading/trailing ".",
//	// "..". Exactly the rules of connector.ValidateInfo for AllowedDomains.
//	func ParseAllowlist(patterns []string) (Allowlist, error)
//	// Allows reports whether host (optionally "host:port"; any port) matches.
//	// Comparison is ASCII case-insensitive. "example.com" matches only
//	// example.com. "*.example.com" matches any host ending in ".example.com"
//	// with at least one more label (a.example.com, a.b.example.com) but NOT
//	// example.com itself. A trailing dot, an empty host, IP literals that are
//	// not listed, and non-ASCII hosts never match.
//	func (a Allowlist) Allows(host string) bool
//
//	type Options struct {
//	    RootCAs      *x509.CertPool // nil: system roots. Verification is never disabled.
//	    Timeout      time.Duration  // whole request incl. redirects; 0: DefaultTimeout
//	    Jar          http.CookieJar // nil: a fresh in-memory cookiejar
//	    MaxRedirects int            // redirects followed; 0: DefaultMaxRedirects
//	    // Proxy is nil by default: no proxy, and proxy environment variables
//	    // (HTTPS_PROXY…) are ignored; httpx never reads the environment.
//	    // cmd/facto sets Proxy = http.ProxyFromEnvironment only when
//	    // FACTO_ALLOW_PROXY=1.
//	    Proxy func(*http.Request) (*url.URL, error)
//	    // DialContext replaces the TCP dialer (tests, resolver pinning).
//	    // TLS verification still applies on top of it.
//	    DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
//	}
//
//	// Client is an allowlisted HTTPS client. Safe for concurrent use.
//	type Client struct{ /* unexported */ }
//	// New parses allowed (ParseAllowlist) and builds a client: TLS >= 1.2,
//	// certificate verification on, HTTPS only, timeouts, cookie jar.
//	func New(allowed []string, opts Options) (*Client, error)
//	// Do sends req. Before ANY connection, for the request and for every
//	// redirect hop: a scheme other than https wraps ErrInsecureScheme; a URL
//	// host (or an explicit req.Host) outside the allowlist wraps
//	// ErrDomainNotAllowed. Following more than MaxRedirects redirects is an
//	// error. Returned errors keep their cause chain (errors.Is/As work for
//	// the sentinels above, context.Canceled, context.DeadlineExceeded,
//	// *tls.CertificateVerificationError…) and name the host involved, but
//	// neither the message nor any error in the chain contains a query
//	// string, fragment, userinfo or header value (so *url.Error, which
//	// embeds the full URL, must not be in the chain).
//	func (c *Client) Do(req *http.Request) (*http.Response, error)
//	// Get builds a GET request with ctx and calls Do. A malformed rawURL
//	// is an error that does not echo rawURL.
//	func (c *Client) Get(ctx context.Context, rawURL string) (*http.Response, error)
//	// Jar returns the cookie jar (Options.Jar or the default one), so
//	// cookies captured by the browser at login can be injected.
//	func (c *Client) Jar() http.CookieJar
//
//	// LimitBody returns a ReadCloser yielding at most max bytes of rc. If rc
//	// holds more, the read that would exceed max returns ErrBodyTooLarge
//	// (never a silent truncation: a cut PDF must not be stored). Close
//	// closes rc.
//	func LimitBody(rc io.ReadCloser, max int64) io.ReadCloser
package httpx_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/httpx"
)

// certHosts are the names the test certificate is valid for.
var certHosts = []string{"fournisseur.test", "*.fournisseur.test", "autre.test"}

// testCert returns a self-signed certificate for certHosts and a pool trusting
// it. Validity dates are fixed (no time.Now in tests).
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "facto test server"},
		DNSNames:              certHosts,
		NotBefore:             time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// env is one TLS test server plus the recording dialer that routes every
// client connection to it.
type env struct {
	srv  *httptest.Server
	pool *x509.CertPool
	hits atomic.Int64

	mu    sync.Mutex
	dials []string
}

func newEnv(t *testing.T, h http.HandlerFunc) *env {
	return newEnvTLS(t, h, nil)
}

// newEnvTLS starts a TLS server; tweak may adjust its tls.Config (versions).
func newEnvTLS(t *testing.T, h http.HandlerFunc, tweak func(*tls.Config)) *env {
	t.Helper()
	e := &env{}
	cert, pool := testCert(t)
	e.pool = pool
	e.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits.Add(1)
		if h != nil {
			h(w, r)
		}
	}))
	e.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if tweak != nil {
		tweak(e.srv.TLS)
	}
	e.srv.StartTLS()
	t.Cleanup(e.srv.Close)
	return e
}

// dial records the requested address and connects to the test server.
func (e *env) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	e.mu.Lock()
	e.dials = append(e.dials, addr)
	e.mu.Unlock()
	var d net.Dialer
	return d.DialContext(ctx, "tcp", e.srv.Listener.Addr().String())
}

func (e *env) dialed() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.dials)
}

// opts returns Options trusting the test certificate and dialing the server.
func (e *env) opts() httpx.Options {
	return httpx.Options{RootCAs: e.pool, DialContext: e.dial}
}

func (e *env) client(t *testing.T, allowed ...string) *httpx.Client {
	t.Helper()
	return mustNew(t, allowed, e.opts())
}

func mustNew(t *testing.T, allowed []string, o httpx.Options) *httpx.Client {
	t.Helper()
	c, err := httpx.New(allowed, o)
	if err != nil {
		t.Fatalf("httpx.New(%q): %v", allowed, err)
	}
	return c
}

// get performs a GET and closes the body; it returns the status and body.
func get(t *testing.T, c *httpx.Client, rawURL string) (int, string, error) {
	t.Helper()
	resp, err := c.Get(t.Context(), rawURL)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), err
}

func ok(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }

func TestClient_AllowedRequestSucceeds(t *testing.T) {
	t.Parallel()
	var gotHost string
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		ok(w, r)
	})
	status, body, err := get(t, e.client(t, "fournisseur.test"), "https://fournisseur.test/invoices")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if status != http.StatusOK || body != "ok" || gotHost != "fournisseur.test" {
		t.Errorf("got %d %q host %q, want 200 \"ok\" host fournisseur.test", status, body, gotHost)
	}
	if got := e.dialed(); !slices.Equal(got, []string{"fournisseur.test:443"}) {
		t.Errorf("dialed %q, want [fournisseur.test:443]", got)
	}
}

func TestClient_RejectsDisallowedDomain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		allowed []string
		url     string
		host    string // overrides req.Host when set
	}{
		{name: "other domain", allowed: []string{"fournisseur.test"}, url: "https://evil.test/collect"},
		{name: "suffix lookalike", allowed: []string{"fournisseur.test"}, url: "https://evil-fournisseur.test/"},
		{name: "allowed as subdomain of attacker", allowed: []string{"fournisseur.test"}, url: "https://fournisseur.test.evil.test/"},
		{name: "subdomain of exact entry", allowed: []string{"fournisseur.test"}, url: "https://api.fournisseur.test/"},
		{name: "apex under wildcard", allowed: []string{"*.fournisseur.test"}, url: "https://fournisseur.test/"},
		{name: "userinfo trick", allowed: []string{"fournisseur.test"}, url: "https://fournisseur.test@evil.test/"},
		{name: "ip literal", allowed: []string{"fournisseur.test"}, url: "https://127.0.0.1/"},
		{name: "trailing dot", allowed: []string{"fournisseur.test"}, url: "https://fournisseur.test./"},
		{name: "host header override", allowed: []string{"fournisseur.test"}, url: "https://fournisseur.test/", host: "evil.test"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, ok)
			c := e.client(t, tc.allowed...)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tc.url, http.NoBody)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if tc.host != "" {
				req.Host = tc.host
			}
			resp, err := c.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if !errors.Is(err, httpx.ErrDomainNotAllowed) {
				t.Fatalf("Do(%s) error = %v, want ErrDomainNotAllowed", tc.url, err)
			}
			if d := e.dialed(); len(d) != 0 {
				t.Errorf("dialed %q for a disallowed host, want no connection", d)
			}
			if n := e.hits.Load(); n != 0 {
				t.Errorf("server hit %d times, want 0", n)
			}
		})
	}
}

func TestClient_ErrorNamesRejectedHost(t *testing.T) {
	t.Parallel()
	e := newEnv(t, ok)
	_, _, err := get(t, e.client(t, "fournisseur.test"), "https://evil.test/x")
	if err == nil || !strings.Contains(err.Error(), "evil.test") {
		t.Fatalf("error = %v, want it to name the rejected host evil.test", err)
	}
}

func TestClient_RechecksRedirects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		allowed   []string
		location  string
		wantErr   error // nil: redirect followed
		wantDials []string
	}{
		{
			name: "same host followed", allowed: []string{"fournisseur.test"},
			location: "https://fournisseur.test/final", wantDials: []string{"fournisseur.test:443"},
		},
		{
			name: "allowed subdomain followed", allowed: []string{"fournisseur.test", "*.fournisseur.test"},
			location: "https://cdn.fournisseur.test/final", wantDials: []string{"fournisseur.test:443", "cdn.fournisseur.test:443"},
		},
		{
			name: "other allowed domain followed", allowed: []string{"fournisseur.test", "autre.test"},
			location: "https://autre.test/final", wantDials: []string{"fournisseur.test:443", "autre.test:443"},
		},
		{
			name: "off allowlist refused", allowed: []string{"fournisseur.test"},
			location: "https://evil.test/steal", wantErr: httpx.ErrDomainNotAllowed, wantDials: []string{"fournisseur.test:443"},
		},
		{
			name: "subdomain not allowed refused", allowed: []string{"fournisseur.test"},
			location: "https://cdn.fournisseur.test/final", wantErr: httpx.ErrDomainNotAllowed, wantDials: []string{"fournisseur.test:443"},
		},
		{
			name: "downgrade to http refused", allowed: []string{"fournisseur.test"},
			location: "http://fournisseur.test/final", wantErr: httpx.ErrInsecureScheme, wantDials: []string{"fournisseur.test:443"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					http.Redirect(w, r, tc.location, http.StatusFound)
					return
				}
				ok(w, r)
			})
			status, body, err := get(t, e.client(t, tc.allowed...), "https://fournisseur.test/start")
			if tc.wantErr == nil {
				if err != nil || status != http.StatusOK || body != "ok" {
					t.Fatalf("got %d %q %v, want 200 \"ok\"", status, body, err)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			// The client may reuse the first connection for same-host hops.
			if got := slices.Compact(e.dialed()); !slices.Equal(got, tc.wantDials) {
				t.Errorf("dialed %q, want %q", got, tc.wantDials)
			}
		})
	}
}

func TestClient_StopsAfterMaxRedirects(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	o := e.opts()
	o.MaxRedirects = 3
	_, _, err := get(t, mustNew(t, []string{"fournisseur.test"}, o), "https://fournisseur.test/loop")
	if err == nil {
		t.Fatal("redirect loop: nil error")
	}
	if n := e.hits.Load(); n != 4 {
		t.Errorf("server hit %d times, want 4 (1 request + MaxRedirects 3)", n)
	}
}

func TestClient_DefaultMaxRedirects(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	_, _, err := get(t, e.client(t, "fournisseur.test"), "https://fournisseur.test/loop")
	if err == nil {
		t.Fatal("redirect loop: nil error")
	}
	if n := e.hits.Load(); n != httpx.DefaultMaxRedirects+1 {
		t.Errorf("server hit %d times, want %d", n, httpx.DefaultMaxRedirects+1)
	}
}

func TestClient_DomainMatching(t *testing.T) {
	t.Parallel()
	tests := []struct {
		allowed []string
		host    string
		want    bool
	}{
		{[]string{"example.com"}, "example.com", true},
		{[]string{"example.com"}, "EXAMPLE.com", true},
		{[]string{"Example.COM"}, "example.com", true},
		{[]string{"example.com"}, "example.com:443", true},
		{[]string{"example.com"}, "example.com:8443", false}, // only the default HTTPS port is allowed
		{[]string{"example.com"}, "www.example.com", false},
		{[]string{"example.com"}, "evil-example.com", false},
		{[]string{"example.com"}, "example.com.evil.net", false},
		{[]string{"example.com"}, "notexample.com", false},
		{[]string{"example.com"}, "example.co", false},
		{[]string{"example.com"}, "example.com.", false},
		{[]string{"example.com"}, "", false},
		{[]string{"example.com"}, ":443", false},
		{[]string{"example.com"}, "127.0.0.1", false},
		{[]string{"example.com"}, "[::1]:443", false},
		{[]string{"example.com"}, "exаmple.com", false}, // Cyrillic "а"
		{[]string{"example.com"}, "xn--exmple-4nf.com", false},
		{[]string{"*.example.com"}, "a.example.com", true},
		{[]string{"*.example.com"}, "A.Example.Com:443", true},
		{[]string{"*.example.com"}, "a.b.example.com", true},
		{[]string{"*.example.com"}, "example.com", false},
		{[]string{"*.example.com"}, ".example.com", false},
		{[]string{"*.example.com"}, "evil-example.com", false},
		{[]string{"*.example.com"}, "a.evil-example.com", false},
		{[]string{"*.example.com"}, "a.example.com.evil.net", false},
		{[]string{"*.example.com"}, "aexample.com", false},
		{[]string{"example.com", "*.cdn.example.net"}, "x.cdn.example.net", true},
		{[]string{"example.com", "*.cdn.example.net"}, "example.net", false},
		{[]string{"example.com", "*.cdn.example.net"}, "cdn.example.net", false},
		{[]string{"127.0.0.1"}, "127.0.0.1:443", true},
	}
	for _, tc := range tests {
		a, err := httpx.ParseAllowlist(tc.allowed)
		if err != nil {
			t.Fatalf("ParseAllowlist(%q): %v", tc.allowed, err)
		}
		if got := a.Allows(tc.host); got != tc.want {
			t.Errorf("ParseAllowlist(%q).Allows(%q) = %v, want %v", tc.allowed, tc.host, got, tc.want)
		}
	}
	if (httpx.Allowlist{}).Allows("example.com") {
		t.Error("zero Allowlist allows example.com, want nothing allowed")
	}
}

func TestParseAllowlist_Rejects(t *testing.T) {
	t.Parallel()
	for _, list := range invalidAllowlists {
		if _, err := httpx.ParseAllowlist(list); !errors.Is(err, httpx.ErrInvalidAllowlist) {
			t.Errorf("ParseAllowlist(%q) error = %v, want ErrInvalidAllowlist", list, err)
		}
		c, err := httpx.New(list, httpx.Options{})
		if !errors.Is(err, httpx.ErrInvalidAllowlist) || c != nil {
			t.Errorf("New(%q) = %v, %v; want nil, ErrInvalidAllowlist", list, c, err)
		}
	}
}

var invalidAllowlists = [][]string{
	nil,
	{},
	{""},
	{"*"},
	{"*."},
	{"*.*.example.com"},
	{"a.*.example.com"},
	{"*example.com"},
	{"https://example.com"},
	{"example.com/"},
	{"example.com/path"},
	{"example.com:443"},
	{"user@example.com"},
	{"example.com?x=1"},
	{"example.com#x"},
	{"ex ample.com"},
	{" example.com"},
	{"example.com\n"},
	{"exa\x00mple.com"},
	{`example.com\`},
	{".example.com"},
	{"example.com."},
	{"example..com"},
	{"example.com", "bad/"},
}

var validAllowlists = [][]string{
	{"example.com"},
	{"*.example.com"},
	{"api.example.com", "*.cdn.example.net"},
	{"fournisseur.test"},
}

func TestClient_RejectsPlainHTTP(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"http://fournisseur.test/",
		"HTTP://fournisseur.test/",
		"ftp://fournisseur.test/",
		"ws://fournisseur.test/",
		"//fournisseur.test/",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, ok)
			_, _, err := get(t, e.client(t, "fournisseur.test"), raw)
			if !errors.Is(err, httpx.ErrInsecureScheme) {
				t.Fatalf("Get(%s) error = %v, want ErrInsecureScheme", raw, err)
			}
			if d := e.dialed(); len(d) != 0 {
				t.Errorf("dialed %q, want no connection", d)
			}
		})
	}
}

func TestClient_VerifiesCertificates(t *testing.T) {
	t.Parallel()
	e := newEnv(t, ok)
	o := e.opts()
	o.RootCAs = nil // system roots do not trust the test certificate
	_, _, err := get(t, mustNew(t, []string{"fournisseur.test"}, o), "https://fournisseur.test/")
	var verr *tls.CertificateVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("error = %v, want a *tls.CertificateVerificationError in the chain", err)
	}
	if n := e.hits.Load(); n != 0 {
		t.Errorf("handler reached %d times over an unverified connection", n)
	}
}

func TestClient_RequiresTLS12(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		min     uint16
		max     uint16
		wantErr bool
	}{
		{name: "tls1.0 only", min: tls.VersionTLS10, max: tls.VersionTLS10, wantErr: true},
		{name: "tls1.1 only", min: tls.VersionTLS10, max: tls.VersionTLS11, wantErr: true},
		{name: "tls1.2 only", min: tls.VersionTLS12, max: tls.VersionTLS12},
		{name: "tls1.3 only", min: tls.VersionTLS13, max: tls.VersionTLS13},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnvTLS(t, ok, func(c *tls.Config) { c.MinVersion, c.MaxVersion = tc.min, tc.max })
			_, _, err := get(t, e.client(t, "fournisseur.test"), "https://fournisseur.test/")
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && e.hits.Load() != 0 {
				t.Error("handler reached over TLS < 1.2")
			}
		})
	}
}

// TestClient_IgnoresProxyEnvUnlessAllowed is not parallel: it sets the
// process environment.
func TestClient_IgnoresProxyEnvUnlessAllowed(t *testing.T) {
	const proxyAddr = "127.0.0.1:9"
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "http://"+proxyAddr)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	t.Setenv("FACTO_ALLOW_PROXY", "1") // httpx itself never reads the environment

	// Sanity: the environment really asks for a proxy. ProxyFromEnvironment
	// caches the environment on first use; only a client honouring the
	// proxy env in an earlier test could have triggered it.
	probe, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://fournisseur.test/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if u, err := http.ProxyFromEnvironment(probe); err != nil || u == nil || u.Host != proxyAddr {
		t.Fatalf("ProxyFromEnvironment = %v, %v; want %s (proxy env read before this test: httpx honours it somewhere)", u, err, proxyAddr)
	}

	e := newEnv(t, ok)
	status, _, err := get(t, e.client(t, "fournisseur.test"), "https://fournisseur.test/")
	if err != nil || status != http.StatusOK {
		t.Fatalf("Get = %d, %v; want a direct 200", status, err)
	}
	if got := e.dialed(); !slices.Equal(got, []string{"fournisseur.test:443"}) {
		t.Errorf("dialed %q, want only the target (no proxy)", got)
	}

	// An injected Proxy is consulted (cmd/facto injects it only when
	// FACTO_ALLOW_PROXY=1). Returning nil keeps the connection direct.
	var consulted atomic.Int64
	o := e.opts()
	o.Proxy = func(r *http.Request) (*url.URL, error) {
		if r.URL.Hostname() == "fournisseur.test" {
			consulted.Add(1)
		}
		return nil, nil
	}
	if _, _, err := get(t, mustNew(t, []string{"fournisseur.test"}, o), "https://fournisseur.test/"); err != nil {
		t.Fatalf("Get with injected proxy: %v", err)
	}
	if consulted.Load() == 0 {
		t.Error("injected Options.Proxy never consulted")
	}
}

func TestClient_Timeout(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	e := newEnv(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) }) // runs before the server closes
	o := e.opts()
	o.Timeout = 100 * time.Millisecond
	_, _, err := get(t, mustNew(t, []string{"fournisseur.test"}, o), "https://fournisseur.test/slow")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded in the chain", err)
	}
}

func TestClient_ContextCanceled(t *testing.T) {
	t.Parallel()
	e := newEnv(t, ok)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	resp, err := e.client(t, "fournisseur.test").Get(ctx, "https://fournisseur.test/")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if n := e.hits.Load(); n != 0 {
		t.Errorf("server hit %d times with a canceled context", n)
	}
}

func TestClient_CookieJar(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "synthetic-session-id", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			return
		}
		c, err := r.Cookie("sid")
		if err != nil {
			http.Error(w, "no cookie", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, c.Value)
	})

	t.Run("default jar keeps cookies", func(t *testing.T) {
		c := e.client(t, "fournisseur.test")
		if c.Jar() == nil {
			t.Fatal("Jar() = nil, want a default cookie jar")
		}
		if _, _, err := get(t, c, "https://fournisseur.test/login"); err != nil {
			t.Fatal(err)
		}
		status, body, err := get(t, c, "https://fournisseur.test/me")
		if err != nil || status != http.StatusOK || body != "synthetic-session-id" {
			t.Fatalf("second request = %d %q %v, want 200 with the cookie", status, body, err)
		}
	})

	t.Run("injected jar is used", func(t *testing.T) {
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		u := &url.URL{Scheme: "https", Host: "fournisseur.test", Path: "/"}
		jar.SetCookies(u, []*http.Cookie{testCookie("injected-from-browser")})
		o := e.opts()
		o.Jar = jar
		c := mustNew(t, []string{"fournisseur.test"}, o)
		if c.Jar() != jar {
			t.Error("Jar() is not the injected jar")
		}
		status, body, err := get(t, c, "https://fournisseur.test/me")
		if err != nil || status != http.StatusOK || body != "injected-from-browser" {
			t.Fatalf("got %d %q %v, want the injected cookie sent", status, body, err)
		}
	})
}

func testCookie(v string) *http.Cookie {
	return &http.Cookie{Name: "sid", Value: v, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

func TestNew_ClientsDoNotShareJars(t *testing.T) {
	t.Parallel()
	a := mustNew(t, []string{"fournisseur.test"}, httpx.Options{})
	b := mustNew(t, []string{"fournisseur.test"}, httpx.Options{})
	u := &url.URL{Scheme: "https", Host: "fournisseur.test", Path: "/"}
	a.Jar().SetCookies(u, []*http.Cookie{testCookie("only-in-a")})
	if got := b.Jar().Cookies(u); len(got) != 0 {
		t.Errorf("client b sees cookies of client a: %v", got)
	}
}

// failingDial makes every connection fail with an error naming the address.
func failingDial(_ context.Context, network, addr string) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: network, Err: fmt.Errorf("synthetic refusal for %s", addr)}
}

func TestClient_KeepsErrorChain(t *testing.T) {
	t.Parallel()
	o := httpx.Options{DialContext: failingDial}
	_, _, err := get(t, mustNew(t, []string{"fournisseur.test"}, o), "https://fournisseur.test/x")
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("error = %v, want the *net.OpError cause in the chain", err)
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		t.Errorf("chain contains *url.Error (%v): it embeds the full URL", uerr)
	}
	if !strings.Contains(err.Error(), "fournisseur.test") {
		t.Errorf("error %q does not name the host", err)
	}
}

func TestClient_GetRejectsMalformedURL(t *testing.T) {
	t.Parallel()
	const marker = "zz-malformed-marker"
	c := mustNew(t, []string{"fournisseur.test"}, httpx.Options{DialContext: failingDial})
	for _, raw := range []string{
		"https://fournisseur.test/%zz?k=" + marker,
		"https://fournisseur.test:bad/?k=" + marker,
		"::" + marker,
	} {
		resp, err := c.Get(t.Context(), raw)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Errorf("Get(%q) = nil error", raw)
			continue
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("Get(%q) error %q echoes the URL", raw, err)
		}
	}
}
