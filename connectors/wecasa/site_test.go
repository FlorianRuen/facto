package wecasa_test

// Offline test site for the Wecasa connector (docs/connectors/wecasa.md).
// One TLS server answers for www.wecasa.fr with the sanitized fixtures of
// testdata/, reached through httpx with a test root CA and a dialer that
// maps only www.wecasa.fr:443 to the listener: nothing ever dials the real
// site. The bookings page carries a synthetic canary token in place of
// '[redacted]'; every /api/v1/ call must send "Authorization: Bearer
// <that token>" or gets a 401.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/connectors/wecasa"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

const (
	wwwHost    = "www.wecasa.fr"
	evilHost   = "evil.test"
	sessionKey = "_wecasa_session"

	pathPage      = "/my-customer-area/bookings-list"
	pathLoginPage = "/customer-area/login"
	pathUser      = "/api/v1/user"
	pathDelivered = "/api/v1/customer/bookings/delivered"
	pathOrders    = "/api/v1/customer/orders/"

	// Fixture files (testdata/, sanitized).
	fxLogin     = "003-get-customer-area-login.html"
	fxPage      = "006-get-my-customer-area-bookings-list.html"
	fxUser      = "008-get-api-v1-user.json"
	fxDelivered = "011-get-api-v1-customer-bookings-delivered.json"
	fxPDF       = "017-get-api-v1-customer-orders-acmmbqztpfdb-download-invoices.pdf"

	// redactedToken is how the sanitized page carries the token: the
	// sanitizer's placeholder, not a credential.
	redactedToken       = "token: '" + redactedPlaceholder + "'"
	redactedPlaceholder = "[redacted]"
)

// orderFixtures maps the orders recorded in detail to their fixture.
var orderFixtures = map[string]string{
	"aCMmbqzTPFDb": "013-get-api-v1-customer-orders-acmmbqztpfdb.json",
	"sz4Jk11V7Q4H": "022-get-api-v1-customer-orders-sz4jk11v7q4h.json",
	"PK6iZymjbDf3": "030-get-api-v1-customer-orders-pk6izymjbdf3.json",
}

// errDialRefused is what the test dialer returns for any host but
// www.wecasa.fr: reaching it at all is a failure the tests assert on.
var errDialRefused = errors.New("test dialer: host not served")

// fixture reads one sanitized fixture.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS("testdata"), name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// pageWithToken returns the bookings page with tok in place of the
// redacted token (raw: the whole "token: '...'" line content).
func pageWithToken(t *testing.T, tokLine string) []byte {
	t.Helper()
	page := fixture(t, fxPage)
	if n := bytes.Count(page, []byte(redactedToken)); n != 1 {
		t.Fatalf("fixture %s holds %d redacted tokens, want 1", fxPage, n)
	}
	return bytes.Replace(page, []byte(redactedToken), []byte(tokLine), 1)
}

// site is the synthetic www.wecasa.fr.
type site struct {
	t    *testing.T
	srv  *httptest.Server
	pool *x509.CertPool

	cookie string // the _wecasa_session value the site accepts
	token  string // the bearer token the API accepts

	mu        sync.Mutex
	page      []byte                      // bookings page body
	delivered []byte                      // bookings/delivered body
	orders    map[string][]byte           // order id -> /orders/<id> body
	pdf       []byte                      // download_invoices body
	routes    map[string]http.HandlerFunc // path -> override, checked first
	hits      []string                    // "METHOD path", query excluded
	dials     []string
	badAuth   int // /api/v1/ requests without the right bearer token
}

// newSite starts the site; cookie and token are fresh canaries.
func newSite(t *testing.T) *site {
	t.Helper()
	s := &site{
		t:      t,
		cookie: testsecrets.Canary(t, testsecrets.Cookie),
		token:  testsecrets.Canary(t, testsecrets.Token),
		routes: map[string]http.HandlerFunc{},
		orders: map[string][]byte{},
	}
	s.page = pageWithToken(t, "token: '"+s.token+"'")
	s.delivered = fixture(t, fxDelivered)
	s.pdf = fixture(t, fxPDF)
	for id, f := range orderFixtures {
		s.orders[id] = fixture(t, f)
	}
	cert, pool := siteCert(t)
	s.pool = pool
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	return s
}

// siteCert returns a self-signed certificate for www.wecasa.fr and
// evil.test (so only the allowlist can stop a request to evil.test). Fixed
// validity dates: no time.Now in tests.
func siteCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "wecasa test site"},
		DNSNames:              []string{wwwHost, evilHost, "wecasa.fr"},
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

// route overrides the answer for one path.
func (s *site) route(path string, h http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[path] = h
}

// setDelivered replaces the bookings/delivered body.
func (s *site) setDelivered(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delivered = b
}

// setOrder replaces one order body.
func (s *site) setOrder(id string, b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orders[id] = b
}

// setPage replaces the bookings page body.
func (s *site) setPage(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.page = b
}

func (s *site) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits = append(s.hits, r.Method+" "+r.URL.Path)
	h := s.routes[r.URL.Path]
	api := strings.HasPrefix(r.URL.Path, "/api/v1/")
	if api && r.Header.Get("Authorization") != "Bearer "+s.token {
		s.badAuth++
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		return
	}
	page, delivered, pdf := s.page, s.delivered, s.pdf
	s.mu.Unlock()
	if h != nil {
		h(w, r)
		return
	}
	switch p := r.URL.Path; {
	case p == pathLoginPage:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(fixture(s.t, fxLogin))
	case p == pathPage:
		if c, err := r.Cookie(sessionKey); err != nil || c.Value != s.cookie {
			http.Redirect(w, r, "https://"+wwwHost+pathLoginPage, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(page)
	case p == pathUser:
		writeJSON(w, fixture(s.t, fxUser))
	case p == pathDelivered:
		writeJSON(w, delivered)
	case strings.HasPrefix(p, pathOrders) && strings.HasSuffix(p, "/download_invoices"):
		id := strings.TrimSuffix(strings.TrimPrefix(p, pathOrders), "/download_invoices")
		if _, ok := s.order(id); !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		_, _ = w.Write(pdf)
	case strings.HasPrefix(p, pathOrders):
		body, ok := s.order(strings.TrimPrefix(p, pathOrders))
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, body)
	default:
		http.NotFound(w, r)
	}
}

// order returns the body of order id: its fixture when recorded, else the
// aCMmbqzTPFDb fixture with the id swapped in (every listed order is Done
// and invoiced in the recording). Unknown-shaped ids are not served.
func (s *site) order(id string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.orders[id]; ok {
		return b, true
	}
	if !bytes.Contains(s.delivered, []byte(`"public_id":"`+id+`"`)) {
		return nil, false
	}
	return bytes.ReplaceAll(fixture(s.t, orderFixtures["aCMmbqzTPFDb"]), []byte("aCMmbqzTPFDb"), []byte(id)), true
}

// writeJSON serves a fixture body (never request data) as JSON.
func writeJSON(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.Copy(w, bytes.NewReader(b))
}

// dial records addr and connects www.wecasa.fr only.
func (s *site) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	s.mu.Lock()
	s.dials = append(s.dials, addr)
	s.mu.Unlock()
	if addr != wwwHost+":443" {
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

func (s *site) badAuthCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.badAuth
}

// hitsWithPrefix counts the requests whose "METHOD path" starts with p.
func (s *site) hitsWithPrefix(p string) int {
	n := 0
	for _, h := range s.hitList() {
		if strings.HasPrefix(h, p) {
			n++
		}
	}
	return n
}

// client builds the httpx client the core would hand the connector:
// allowlist from Info(), test CA, test dialer.
func (s *site) client(t *testing.T) *httpx.Client {
	t.Helper()
	info := wecasa.New(wecasa.Options{}).Info()
	hc, err := httpx.New(info.AllowedDomains, httpx.Options{RootCAs: s.pool, DialContext: s.dial})
	if err != nil {
		t.Fatalf("httpx.New(%q): %v", info.AllowedDomains, err)
	}
	return hc
}

// sessionCookie is a browser cookie for www.wecasa.fr.
func sessionCookie(name, value string) connector.Cookie {
	return connector.Cookie{
		Name:     name,
		Value:    secret.FromString(value),
		Domain:   wwwHost,
		Path:     "/",
		Expires:  time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		Secure:   true,
		HTTPOnly: true,
	}
}

// session opens a session the way Login does after the browser: inject
// the site's cookie, read the token from the bookings page.
func (s *site) session(t *testing.T) *wecasa.Session {
	t.Helper()
	sess, err := wecasa.NewSession(t.Context(), s.client(t), []connector.Cookie{sessionCookie(sessionKey, s.cookie)})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return sess
}

// noSecretIn fails when text holds the site's cookie or token.
func (s *site) noSecretIn(t *testing.T, where, text string) {
	t.Helper()
	for _, v := range []string{s.cookie, s.token} {
		if strings.Contains(text, v) {
			t.Errorf("%s leaks a canary: %s", where, text)
		}
	}
}

// noQueryInError fails when err's message carries a query string.
func noQueryInError(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "?") {
		t.Errorf("error %q carries a query string", err)
	}
}

// utc is a shorthand for test dates.
func utc(y int, m time.Month, d, h int) time.Time {
	return time.Date(y, m, d, h, 0, 0, 0, time.UTC)
}
