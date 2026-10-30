//go:build e2e

package e2e

// The e2e fake site (plan J1 A7, T22): one TLS server bound to 127.0.0.1
// only, serving www.fakeprovider.test, sso.fakeprovider.test and evil.test
// with a certificate from a CA generated per site. It implements the
// "Login flow" contract of docs/connectors/fakeprovider.md and the site API
// (/api/me, /api/invoices, /api/invoices/{id}/pdf). Every value is
// synthetic; the request log keeps method, host, path and status only.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP uses HMAC-SHA1 (J1 T22, test-only fake site, SEC-J0-14 tracking issue (BLOCKED H1))
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/clock"
)

// TOTP parameters (RFC 6238 defaults): 30 s steps, 6 digits, one step of
// tolerance on each side.
const (
	totpStep   = 30
	totpDigits = 6
	totpWindow = 1
)

// siteOptions configures one fake site.
type siteOptions struct {
	Mode            string
	Login, Password string // accepted credentials (synthetic or canary)
	ExpireAfter     int    // expired-session: API requests per session before 401
	RateLimitAfter  int    // rate-limit: API requests before 429
	Invoices        []siteInvoice
	TOTPSeed        []byte           // nil = 20 random bytes
	Now             func() time.Time // nil = clock.Real
	// OnLoginPage runs synchronously while a login page (form or captcha)
	// is served, before the response is written: the browser that asked
	// for it is alive and waiting.
	OnLoginPage func(r *http.Request)
}

// siteInvoice is a seeded document and its PDF bytes.
type siteInvoice struct {
	FakeInvoice
	PDF []byte
}

// fakeSite is a running fake site. Safe for concurrent use.
type fakeSite struct {
	opts   siteOptions
	srv    *http.Server
	ln     net.Listener
	addr   netip.AddrPort
	ca     *x509.Certificate
	caPEM  []byte
	caPool *x509.CertPool
	seed   []byte

	mu       sync.Mutex
	log      []loggedRequest
	apiCalls int                 // API requests served (rate-limit)
	sessions map[string]*session // fp_session value -> state
	pending  map[string]string   // fp_pending value -> next step path
	tickets  map[string]bool     // SSO tickets not yet redeemed
	email    map[string]string   // fp_pending value -> email code
	outbox   []string
	outboxCh chan struct{} // closed and replaced on every new message
}

type session struct{ apiCalls int }

// startFakeSite starts a site on 127.0.0.1:<random port>; it stops with t.
func startFakeSite(t *testing.T, opts siteOptions) *fakeSite {
	t.Helper()
	if opts.Now == nil {
		opts.Now = clock.Real{}.Now
	}
	s := &fakeSite{
		opts:     opts,
		seed:     opts.TOTPSeed,
		sessions: map[string]*session{},
		pending:  map[string]string{},
		tickets:  map[string]bool{},
		email:    map[string]string{},
		outboxCh: make(chan struct{}),
	}
	if s.seed == nil {
		s.seed = randomBytes(t, 20)
	}
	leaf := s.newCA(t)
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake site: listen: %v", err)
	}
	s.ln = ln
	s.addr = ln.Addr().(*net.TCPAddr).AddrPort()
	s.srv = &http.Server{
		Handler:           http.HandlerFunc(s.serve),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12},
		ErrorLog:          slog.NewLogLogger(slog.DiscardHandler, slog.LevelError), // handshake noise of refused probes
	}
	go func() { _ = s.srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(ctx)
	})
	return s
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func randomToken() string { return rand.Text() }

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err) // constant URLs only
	}
	return u
}

// newCA generates the site's CA and a leaf for the three served hosts.
// The leaf chain carries the CA, so Chrome's SPKI allowlist can match it.
func (s *fakeSite) newCA(t *testing.T) tls.Certificate {
	t.Helper()
	now := clock.Real{}.Now() // TLS clients check validity against the real time
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "facto e2e fake site test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if s.ca, err = x509.ParseCertificate(caDER); err != nil {
		t.Fatal(err)
	}
	s.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	s.caPool = x509.NewCertPool()
	s.caPool.AddCert(s.ca)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: HostWWW},
		DNSNames:     []string{HostWWW, HostSSO, EvilHost},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, s.ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key}
}

// Addr is the listening address, always 127.0.0.1:<port>.
func (s *fakeSite) Addr() netip.AddrPort { return s.addr }

// CAPEM is the test CA certificate (PEM).
func (s *fakeSite) CAPEM() []byte { return slices.Clone(s.caPEM) }

// CAPool trusts the test CA only.
func (s *fakeSite) CAPool() *x509.CertPool { return s.caPool }

// CASPKI is the base64 SHA-256 of the CA's SubjectPublicKeyInfo, the form
// Chrome's --ignore-certificate-errors-spki-list takes.
func (s *fakeSite) CASPKI() string {
	sum := sha256Sum(s.ca.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum)
}

// Client returns an HTTP client that dials the site for every host, trusts
// only the test CA, keeps cookies and never follows redirects.
func (s *fakeSite) Client(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp4", s.addr.String())
		},
		TLSClientConfig: &tls.Config{RootCAs: s.caPool, MinVersion: tls.VersionTLS12},
		Proxy:           nil,
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{
		Transport:     tr,
		Jar:           jar,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Requests returns a copy of the request log.
func (s *fakeSite) Requests() []loggedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.log)
}

// ResetLog empties the request log (between runs of a scenario).
func (s *fakeSite) ResetLog() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log = nil
}

// TOTP returns the site's code for the step holding at.
func (s *fakeSite) TOTP(at time.Time) string { return totpCode(s.seed, at) }

// WaitOutbox returns the i-th (0-based) email code the site sent, waiting
// for it until ctx ends.
func (s *fakeSite) WaitOutbox(ctx context.Context, i int) (string, error) {
	for {
		s.mu.Lock()
		if i < len(s.outbox) {
			code := s.outbox[i]
			s.mu.Unlock()
			return code, nil
		}
		ch := s.outboxCh
		s.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return "", fmt.Errorf("outbox[%d]: %w", i, ctx.Err())
		}
	}
}

// openSessionForTest opens a session for c without the login pages (unit
// tests of modes whose form cannot be posted).
func (s *fakeSite) openSessionForTest(t *testing.T, c *http.Client) {
	t.Helper()
	v := s.newSession()
	u := mustURL("https://" + HostWWW + "/")
	c.Jar.SetCookies(u, []*http.Cookie{{Name: "fp_session", Value: v, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}})
}

// totpCode is RFC 6238 TOTP (HMAC-SHA1, 30 s, 6 digits) for at.
func totpCode(seed []byte, at time.Time) string {
	return hotp(seed, uint64(at.Unix()/totpStep)) //nolint:gosec // Unix time after 1970: non-negative (J1 T22, SEC-J0-14 tracking issue (BLOCKED H1))
}

func hotp(seed []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, seed)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1_000_000)
}

var sixDigits = regexp.MustCompile(`^[0-9]{6}$`)

// totpValid accepts a code of the current step or one step around it.
func (s *fakeSite) totpValid(code string) bool {
	if !sixDigits.MatchString(code) {
		return false
	}
	now := s.opts.Now().Unix() / totpStep
	for d := int64(-totpWindow); d <= totpWindow; d++ {
		want := hotp(s.seed, uint64(now+d)) //nolint:gosec // non-negative step count (J1 T22, SEC-J0-14 tracking issue (BLOCKED H1))
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// statusWriter records the response status for the log.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

var hostRE = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)

// logHost keeps a Host header for the log only when it is a plain name.
func logHost(h string) string {
	h = strings.ToLower(h)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	if !hostRE.MatchString(h) {
		return "(invalid)"
	}
	return h
}

func (s *fakeSite) serve(w http.ResponseWriter, r *http.Request) {
	sw := &statusWriter{ResponseWriter: w}
	host := logHost(r.Host)
	defer func() {
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		s.mu.Lock()
		s.log = append(s.log, loggedRequest{Method: r.Method, Host: host, Path: r.URL.Path, Status: status})
		s.mu.Unlock()
	}()
	sw.Header().Set("Cache-Control", "no-store")
	switch host {
	case HostWWW:
		s.serveWWW(sw, r)
	case HostSSO:
		s.serveSSO(sw, r)
	case EvilHost:
		// Off every allowlist: served (so a leak is logged), never linked
		// to any state.
		sw.Header().Set("Content-Type", "image/gif")
		_, _ = sw.Write([]byte("GIF89a"))
	default:
		http.Error(sw, "misdirected", http.StatusMisdirectedRequest)
	}
}

func (s *fakeSite) serveWWW(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/login" && r.Method == http.MethodGet:
		switch s.opts.Mode {
		case ModeSSORedirect:
			http.Redirect(w, r, "https://"+HostSSO+"/login", http.StatusFound)
		case ModeCaptcha:
			http.Redirect(w, r, "/login/captcha", http.StatusFound)
		default:
			s.loginForm(w, r, false)
		}
	case r.URL.Path == "/login" && r.Method == http.MethodPost:
		s.loginPost(w, r)
	case r.URL.Path == "/login/captcha" && r.Method == http.MethodGet:
		s.hook(r)
		s.page(w, captchaTmpl, nil)
	case r.URL.Path == "/login/totp" || r.URL.Path == "/login/email":
		s.codeStep(w, r)
	case r.URL.Path == "/sso/callback" && r.Method == http.MethodGet:
		s.ssoCallback(w, r)
	case r.URL.Path == "/account" && r.Method == http.MethodGet:
		if s.session(r) == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		s.page(w, accountTmpl, nil)
	case strings.HasPrefix(r.URL.Path, "/api/") && r.Method == http.MethodGet:
		s.api(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *fakeSite) serveSSO(w http.ResponseWriter, r *http.Request) {
	switch {
	case s.opts.Mode != ModeSSORedirect:
		http.NotFound(w, r)
	case r.URL.Path == "/login" && r.Method == http.MethodGet:
		s.loginForm(w, r, false)
	case r.URL.Path == "/login" && r.Method == http.MethodPost:
		s.loginPost(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *fakeSite) hook(r *http.Request) {
	if s.opts.OnLoginPage != nil {
		s.opts.OnLoginPage(r)
	}
}

// newCSRF sets a fresh double-submit token cookie (host-only) and returns
// the value for the hidden field.
func newCSRF(w http.ResponseWriter) string {
	tok := randomToken()
	http.SetCookie(w, &http.Cookie{Name: "fp_csrf", Value: tok, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return tok
}

// csrfOK checks the double-submit token of a form post.
func csrfOK(r *http.Request) bool {
	c, err := r.Cookie("fp_csrf")
	field := r.PostFormValue("csrf_token")
	return err == nil && c.Value != "" && field != "" && subtle.ConstantTimeCompare([]byte(c.Value), []byte(field)) == 1
}

func (s *fakeSite) loginForm(w http.ResponseWriter, r *http.Request, failed bool) {
	s.hook(r)
	tmpl := loginTmpl
	if s.opts.Mode == ModeSiteChanged {
		tmpl = changedLoginTmpl
	}
	s.page(w, tmpl, map[string]any{"CSRF": newCSRF(w), "Error": failed})
}

func (s *fakeSite) loginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if !csrfOK(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	user, pw := r.PostFormValue("username"), r.PostFormValue("password")
	ok := s.opts.Mode != ModeBadPassword && s.opts.Mode != ModeSiteChanged && s.opts.Mode != ModeCaptcha &&
		subtle.ConstantTimeCompare([]byte(user), []byte(s.opts.Login)) == 1 &&
		subtle.ConstantTimeCompare([]byte(pw), []byte(s.opts.Password)) == 1
	if !ok {
		s.loginForm(w, r, true)
		return
	}
	switch {
	case logHost(r.Host) == HostSSO:
		tk := randomToken()
		s.mu.Lock()
		s.tickets[tk] = true
		s.mu.Unlock()
		http.Redirect(w, r, "https://"+HostWWW+"/sso/callback?ticket="+tk, http.StatusSeeOther)
	case s.opts.Mode == ModeTOTP:
		s.startPending(w, "/login/totp")
		http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
	case s.opts.Mode == ModeEmailOTP:
		p := s.startPending(w, "/login/email")
		code := hotp(randomBytes0(), 0)
		s.mu.Lock()
		s.email[p] = code
		s.outbox = append(s.outbox, code)
		close(s.outboxCh)
		s.outboxCh = make(chan struct{})
		s.mu.Unlock()
		http.Redirect(w, r, "/login/email", http.StatusSeeOther)
	default:
		s.setSession(w)
		http.Redirect(w, r, "/account", http.StatusSeeOther)
	}
}

// randomBytes0 is randomBytes without a testing.TB (request goroutines).
func randomBytes0() []byte {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return b
}

func (s *fakeSite) startPending(w http.ResponseWriter, step string) string {
	p := randomToken()
	s.mu.Lock()
	s.pending[p] = step
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "fp_pending", Value: p, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return p
}

// codeStep serves and checks the TOTP and email code pages.
func (s *fakeSite) codeStep(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("fp_pending")
	s.mu.Lock()
	step := ""
	if err == nil {
		step = s.pending[c.Value]
	}
	s.mu.Unlock()
	if step != r.URL.Path {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	tmpl, field := otpTmpl, "otp"
	if step == "/login/email" {
		tmpl, field = emailTmpl, "email_code"
	}
	if r.Method == http.MethodGet {
		s.page(w, tmpl, map[string]any{"CSRF": newCSRF(w), "Error": false})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if !csrfOK(r) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	code := r.PostFormValue(field)
	var ok bool
	if step == "/login/totp" {
		ok = s.totpValid(code)
	} else {
		s.mu.Lock()
		want := s.email[c.Value]
		s.mu.Unlock()
		ok = want != "" && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1
	}
	if !ok {
		s.page(w, tmpl, map[string]any{"CSRF": newCSRF(w), "Error": true})
		return
	}
	s.mu.Lock()
	delete(s.pending, c.Value)
	delete(s.email, c.Value)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "fp_pending", Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	s.setSession(w)
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (s *fakeSite) ssoCallback(w http.ResponseWriter, r *http.Request) {
	tk := r.URL.Query().Get("ticket")
	s.mu.Lock()
	ok := tk != "" && s.tickets[tk]
	delete(s.tickets, tk)
	s.mu.Unlock()
	if !ok {
		http.Redirect(w, r, "https://"+HostSSO+"/login", http.StatusFound)
		return
	}
	s.setSession(w)
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (s *fakeSite) newSession() string {
	v := randomToken()
	s.mu.Lock()
	s.sessions[v] = &session{}
	s.mu.Unlock()
	return v
}

// setSession sets fp_session host-only on www (no Domain attribute).
func (s *fakeSite) setSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: "fp_session", Value: s.newSession(), Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (s *fakeSite) session(r *http.Request) *session {
	c, err := r.Cookie("fp_session")
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[c.Value]
}

var pdfPathRE = regexp.MustCompile(`^/api/invoices/([A-Z0-9][A-Z0-9-]{0,63})/pdf$`)

func (s *fakeSite) api(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.apiCalls++
	limited := s.opts.Mode == ModeRateLimit && s.apiCalls > s.opts.RateLimitAfter
	s.mu.Unlock()
	if limited {
		w.Header().Set("Retry-After", "3600")
		http.Error(w, "slow down", http.StatusTooManyRequests)
		return
	}
	sess := s.session(r)
	if sess == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	sess.apiCalls++
	expired := s.opts.Mode == ModeExpiredSession && sess.apiCalls > s.opts.ExpireAfter
	s.mu.Unlock()
	if expired {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/api/me":
		if s.opts.Mode == ModeSiteChanged {
			writeJSON(w, map[string]any{"profile": map[string]string{"ref": "FP-ACCOUNT-1"}})
			return
		}
		writeJSON(w, map[string]string{"account": "FP-ACCOUNT-1"})
	case "/api/invoices":
		if s.opts.Mode == ModeSiteChanged {
			http.NotFound(w, r)
			return
		}
		s.list(w, r)
	default:
		m := pdfPathRE.FindStringSubmatch(r.URL.Path)
		if m == nil || s.opts.Mode == ModeSiteChanged {
			http.NotFound(w, r)
			return
		}
		for _, inv := range s.opts.Invoices {
			if inv.ID == m[1] {
				w.Header().Set("Content-Type", "application/pdf")
				w.Header().Set("Content-Length", strconv.Itoa(len(inv.PDF)))
				_, _ = w.Write(inv.PDF)
				return
			}
		}
		http.NotFound(w, r)
	}
}

type invoiceJSON struct {
	ID          string `json:"id"`
	Contract    string `json:"contract"`
	IssuedAt    string `json:"issued_at"`
	AmountCents *int64 `json:"amount_cents,omitempty"`
	Currency    string `json:"currency,omitempty"`
}

// list serves one page holding every invoice issued in [from, to).
func (s *fakeSite) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, err1 := time.Parse(time.DateOnly, q.Get("from"))
	to, err2 := time.Parse(time.DateOnly, q.Get("to"))
	if err1 != nil || err2 != nil || q.Get("page") != "1" {
		http.Error(w, "bad query", http.StatusBadRequest)
		return
	}
	out := []invoiceJSON{}
	for _, inv := range s.opts.Invoices {
		at, err := time.Parse(time.DateOnly, inv.IssuedAt)
		if err != nil || at.Before(from) || !at.Before(to) {
			continue
		}
		out = append(out, invoiceJSON{ID: inv.ID, Contract: inv.Contract, IssuedAt: inv.IssuedAt, AmountCents: inv.AmountCents, Currency: inv.Currency})
	}
	writeJSON(w, struct {
		Invoices []invoiceJSON `json:"invoices"`
		NextPage *int          `json:"next_page"`
	}{Invoices: out})
}

func writeJSON(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "json", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func (s *fakeSite) page(w http.ResponseWriter, tmpl *template.Template, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Evil"] = "https://" + EvilHost + "/pixel.png"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = tmpl.Execute(w, data)
}

// Pages. Every login page also tries to load an off-allowlist resource
// (A11): the browser must block it, the request log proves it did.
const pageHead = `<!doctype html><html><head><meta charset="utf-8"><title>Fake Provider</title></head><body>
<img src="{{.Evil}}" alt="" width="1" height="1">
`

var (
	loginTmpl = template.Must(template.New("login").Parse(pageHead + `<form id="login-form" method="post" action="/login">
{{if .Error}}<p id="login-error">Invalid credentials</p>{{end}}
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<label>Login <input id="username" name="username" autocomplete="off"></label>
<label>Password <input id="password" name="password" type="password"></label>
<button id="login-submit" type="submit">Sign in</button>
</form></body></html>`))

	// changedLoginTmpl is the site-changed form: same flow, every
	// contract selector and field name renamed.
	changedLoginTmpl = template.Must(template.New("changed").Parse(pageHead + `<form id="signin-form" method="post" action="/login">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<label>Login <input id="user-id" name="user_id"></label>
<label>Password <input id="secret-word" name="secret_word" type="password"></label>
<button id="signin-go" type="submit">Sign in</button>
</form></body></html>`))

	otpTmpl = template.Must(template.New("otp").Parse(pageHead + `<form id="otp-form" method="post" action="/login/totp">
{{if .Error}}<p id="otp-error">Wrong code</p>{{end}}
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<label>Authenticator code <input id="otp" name="otp" inputmode="numeric" autocomplete="one-time-code"></label>
<button id="otp-submit" type="submit">Verify</button>
</form></body></html>`))

	emailTmpl = template.Must(template.New("email").Parse(pageHead + `<form id="email-code-form" method="post" action="/login/email">
{{if .Error}}<p id="email-code-error">Wrong code</p>{{end}}
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<label>Code sent by email <input id="email-code" name="email_code" inputmode="numeric"></label>
<button id="email-code-submit" type="submit">Verify</button>
</form></body></html>`))

	captchaTmpl = template.Must(template.New("captcha").Parse(pageHead + `<div id="captcha">Prove you are human (never automated)</div></body></html>`))

	accountTmpl = template.Must(template.New("account").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>Account</title></head><body>
<div id="account">Synthetic account FP-ACCOUNT-1</div></body></html>`))
)
