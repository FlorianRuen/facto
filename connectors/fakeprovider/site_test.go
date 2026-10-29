package fakeprovider_test

// Plan J1 T20: fakeprovider connector, HTTP side (login over BrowserPool is
// T21). Tests written first; the package does not exist yet.
//
// Expected API (package connectors/fakeprovider, no net/http import in
// non-test code: every request goes through the *httpx.Client the session
// carries):
//
//	const ID = "fakeprovider"
//	const (
//	    HostWWW = "www.fakeprovider.test" // API + PDFs
//	    HostSSO = "sso.fakeprovider.test" // login pages (T21)
//	)
//	// Caps, applied when the matching Options field is zero.
//	const (
//	    DefaultMaxListBytes int64 = 1 << 20  // one list page body
//	    DefaultMaxItems           = 2000     // items across all pages
//	    DefaultMaxPages           = 50       // pages per List call
//	    DefaultMaxPDFBytes  int64 = 20 << 20 // one PDF body
//	)
//	type Options struct {
//	    MaxListBytes int64
//	    MaxItems     int
//	    MaxPages     int
//	    MaxPDFBytes  int64
//	}
//	func New(opts Options) *Connector
//	func (c *Connector) Info() connector.Info // fresh slices on every call
//	func (c *Connector) Login(ctx, connector.Env) (connector.Session, error) // T21
//	func (c *Connector) List(ctx, connector.Session, connector.Period) ([]connector.DocumentRef, error)
//	func (c *Connector) Fetch(ctx, connector.Session, connector.DocumentRef) (io.ReadCloser, error)
//	// Probe checks the session is still valid: GET https://www.fakeprovider.test/api/me.
//	func (c *Connector) Probe(ctx, connector.Session) error
//
//	// Session implements connector.Persistable. Its String/GoString/Format/
//	// LogValue never render a cookie value.
//	type Session struct{ /* *httpx.Client, ... */ }
//	// NewSession injects cookies (e.g. from Browser.Cookies after T21's
//	// login) into hc's jar. Cookies whose Domain is not an Info()
//	// AllowedDomains host are dropped and never persisted.
//	func NewSession(hc *httpx.Client, cookies []connector.Cookie) (*Session, error)
//	// Persist exports the cookies hc's jar holds for the allowed hosts
//	// (server-rotated values included) as an opaque secret blob.
//	func (s *Session) Persist(ctx context.Context) (secret.Secret, error)
//	// Restore rebuilds a session from a Persist blob (Env.Saved) into hc.
//	// A zero, malformed or foreign blob wraps connector.ErrNeedsLogin and the
//	// error never echoes the blob.
//	func Restore(hc *httpx.Client, blob secret.Secret) (*Session, error)
//
//	// register_e2e.go, //go:build e2e ONLY (plan T17: the release build must
//	// not contain fakeprovider). There is no package-level registry
//	// (cmd/facto builds one and injects it), hence a function, not init().
//	func Register(r *connector.Registry) error
//
// Wire contract with the fake site (shared with test/e2e, plan T22):
//
//	GET /api/me                                   200 {"account":"..."} | 401 | 302 -> sso /login
//	GET /api/invoices?from=YYYY-MM-DD&to=YYYY-MM-DD&page=N   (N starts at 1)
//	    200 application/json
//	    {"invoices":[{"id","contract","issued_at","period_start"?,"period_end"?,
//	                  "amount_cents"?,"currency"?}], "next_page": N+1 | null}
//	GET /api/invoices/{id}/pdf                    200 application/pdf
//
// List rules: unknown fields, trailing data, missing or null "invoices",
// non-JSON content type, invalid id (^[A-Z0-9][A-Z0-9-]{0,63}$), contract
// (^[A-Z0-9-]{1,32}$), dates (strict 2006-01-02, period_start <= period_end,
// both or neither), amount (integer, |cents| <= 100_000_000), currency
// (^[A-Z]{3}$, required with an amount), duplicate ids, next_page other than
// page+1, and every cap → connector.ErrBroken (a body cap also matches
// httpx.ErrBodyTooLarge). Items whose issued_at is outside the period are
// dropped. Errors never echo response body values.
//
// Status mapping (List, Fetch, Probe): 401 or a redirect ending on the SSO
// login page → ErrNeedsLogin; 403 → ErrAuthFailed; 429 → ErrRateLimited
// after exactly one request (no retry, Retry-After never slept on); 404 →
// ErrBroken naming the endpoint path, never its query.
//
// Fetch rules: ProviderID re-validated before any request; Content-Type
// media type exactly application/pdf; body starts with "%PDF-"; a declared
// Content-Length over MaxPDFBytes fails Fetch with httpx.ErrBodyTooLarge
// without reading; an undeclared oversized body fails the read with
// httpx.ErrBodyTooLarge (never silently truncated).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/connectors/fakeprovider"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

const (
	wwwHost   = "www.fakeprovider.test"
	ssoHost   = "sso.fakeprovider.test"
	evilHost  = "evil.test"
	cookieKey = "fp_session"
)

// errDialRefused is what the test dialer returns for a host the fake site
// does not serve: reaching it at all is a failure the tests assert on.
var errDialRefused = errors.New("test dialer: host not served")

// site is a synthetic fakeprovider web site: one TLS server answering for
// www. and sso.fakeprovider.test, reached through httpx with a test root CA
// and a dialer that maps only those two hosts to the listener.
type site struct {
	srv  *httptest.Server
	pool *x509.CertPool

	mu    sync.Mutex
	hits  []string // "METHOD host path", query excluded
	dials []string // every address the client asked to dial
}

// newSite starts the fake site with handler h.
func newSite(t *testing.T, h http.HandlerFunc) *site {
	t.Helper()
	s := &site{}
	cert, pool := siteCert(t)
	s.pool = pool
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits = append(s.hits, r.Method+" "+r.Host+" "+r.URL.Path)
		s.mu.Unlock()
		h(w, r)
	}))
	s.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	return s
}

// siteCert returns a self-signed certificate for the fake hosts (evil.test
// included, so only the allowlist can stop a request to it). Fixed validity
// dates: no time.Now in tests.
func siteCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fakeprovider test site"},
		DNSNames:              []string{wwwHost, ssoHost, evilHost, "fakeprovider.test", "x.fakeprovider.test"},
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

// dial records addr and connects only the two fakeprovider hosts.
func (s *site) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	s.mu.Lock()
	s.dials = append(s.dials, addr)
	s.mu.Unlock()
	if addr != wwwHost+":443" && addr != ssoHost+":443" {
		return nil, errDialRefused
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", s.srv.Listener.Addr().String())
}

func (s *site) hitList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.hits)
}

func (s *site) dialList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.dials)
}

// client builds the httpx client the connector would get: allowlist from
// Info(), test CA, test dialer.
func (s *site) client(t *testing.T) *httpx.Client {
	t.Helper()
	info := fakeprovider.New(fakeprovider.Options{}).Info()
	hc, err := httpx.New(info.AllowedDomains, httpx.Options{RootCAs: s.pool, DialContext: s.dial})
	if err != nil {
		t.Fatalf("httpx.New(%q): %v", info.AllowedDomains, err)
	}
	return hc
}

// sessionCookie is the synthetic session cookie the site accepts.
func sessionCookie(value string) connector.Cookie {
	return connector.Cookie{
		Name:     cookieKey,
		Value:    secret.FromString(value),
		Domain:   wwwHost,
		Path:     "/",
		Expires:  time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		Secure:   true,
		HTTPOnly: true,
	}
}

// session returns a session on a fresh client of s carrying cookie value.
func (s *site) session(t *testing.T, value string) *fakeprovider.Session {
	t.Helper()
	sess, err := fakeprovider.NewSession(s.client(t), []connector.Cookie{sessionCookie(value)})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return sess
}

// authed reports whether r carries the expected session cookie; when not,
// it answers 401.
func authed(w http.ResponseWriter, r *http.Request, want string) bool {
	c, err := r.Cookie(cookieKey)
	if err != nil || c.Value != want {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// canaryCookie returns a fresh canary standing in for a session cookie.
func canaryCookie(t *testing.T) string {
	t.Helper()
	return testsecrets.Canary(t, testsecrets.Cookie)
}

// noQueryInError fails when err's message carries a query string.
func noQueryInError(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "?") {
		t.Errorf("error %q carries a query string", err)
	}
}

// year2025 is the period most tests list.
var year2025 = connector.Year(2025)
