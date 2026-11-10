package wecasa_test

// Login over connector.BrowserPool (docs/connectors/wecasa.md "Login"):
//
//  1. Saved session: Restore + Probe; ok → reused, no browser, no secret.
//     ErrNeedsLogin → the jar is cleared and the browser login runs; any
//     other error is returned.
//  2. Login and password resolved before any launch.
//  3. Headless launch with Info().AllowedDomains and Info().BrowserStatic,
//     Navigate(login URL), wait for the form, the logout link or a
//     Cloudflare challenge, then classify by CurrentURL (and, on the login
//     URL, by whether the form is shown).
//  4. Login form: type #user_email and #user_password, click
//     input[name=commit] (the Rails CSRF field travels with the form).
//  5. After submit: logout link on /customer-area → success; the form on
//     the login URL again → ErrAuthFailed; a challenge or any other page →
//     never automated: non-interactive → ErrNeedsLogin; interactive → the
//     headless browser is closed and a visible one opens the login URL for
//     the user (UserTimeout), the connector types and clicks nothing.
//  6. Success: browser cookies of www.wecasa.fr → env.HTTP's jar, then the
//     bookings page is read over httpx for the bearer token.
//  7. A selector the flow needs missing on a known page → ErrBroken naming
//     it; a page outside the allowlist → ErrBroken.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/connectors/wecasa"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// Synthetic secret references (never real ones).
const (
	refLogin  = "keyring://facto/wecasa/login"
	refPhrase = "keyring://facto/wecasa/password"
)

const staticPrefix = "https://storage.googleapis.com/wecasa-react-prod/"

type harness struct {
	t      *testing.T
	c      *wecasa.Connector
	env    connector.Env
	rec    *recorder
	pool   *fakePool
	res    *fakeResolver
	prompt *fakePrompter
	logs   *syncBuffer
	site   *site

	login, password string
}

func newHarness(t *testing.T, opts wecasa.Options) *harness {
	t.Helper()
	h := &harness{
		t:        t,
		c:        wecasa.New(opts),
		rec:      &recorder{},
		logs:     &syncBuffer{},
		login:    testsecrets.Canary(t, testsecrets.Token),
		password: testsecrets.Canary(t, testsecrets.Password),
	}
	h.site = newSite(t)
	h.pool = &fakePool{rec: h.rec}
	h.res = &fakeResolver{rec: h.rec, vals: map[string]string{refLogin: h.login, refPhrase: h.password}}
	h.prompt = &fakePrompter{rec: h.rec}
	h.env = connector.Env{
		Secrets:     h.res,
		Browser:     h.pool,
		HTTP:        h.site.client(t),
		Prompt:      h.prompt,
		Log:         slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Credentials: connector.Credentials{Login: refLogin, Password: refPhrase},
	}
	return h
}

func (h *harness) interactive(v bool) {
	h.env.Interactive = v
	h.prompt.interactive = v
}

func (h *harness) use(scripts ...*script) { h.pool.scripts = append(h.pool.scripts, scripts...) }

// cookies is what the browser hands out after a login: the site's session
// cookie and a cookie of another domain the connector must drop.
func (h *harness) cookies() []connector.Cookie {
	foreign := sessionCookie("_ga", "FOREIGN-COOKIE-VALUE")
	foreign.Domain = ".google.com"
	return []connector.Cookie{sessionCookie(sessionKey, h.site.cookie), sessionCookie("_wecasa_signed_in", "1"), foreign}
}

func (h *harness) run(ctx context.Context) (connector.Session, error) {
	return h.c.Login(ctx, h.env)
}

func (h *harness) browser(i int) *fakeBrowser {
	h.t.Helper()
	bs := h.pool.launched()
	if i >= len(bs) {
		h.t.Fatalf("browser #%d was never launched (%d launched)", i+1, len(bs))
	}
	return bs[i]
}

func (h *harness) assertAllClosed() {
	h.t.Helper()
	for i, b := range h.pool.launched() {
		if n := b.closeCount(); n != 1 {
			h.t.Errorf("browser #%d closed %d times, want exactly 1", i+1, n)
		}
	}
}

// assertNoLeak fails if a secret shows in err, the logs or the session.
func (h *harness) assertNoLeak(sess connector.Session, err error) {
	h.t.Helper()
	var out strings.Builder
	if err != nil {
		fmt.Fprintf(&out, "%v|%+v|%#v|%s|", err, err, err, err.Error())
	}
	if sess != nil {
		out.WriteString(rendered(sess))
	}
	out.WriteString(h.logs.String())
	text := out.String()
	for _, v := range []string{h.login, h.password, h.site.cookie, h.site.token} {
		if strings.Contains(text, v) {
			h.t.Errorf("a secret leaks into the error, the logs or the session: %s", text)
		}
	}
}

// mustWork proves sess is a usable Wecasa session.
func (h *harness) mustWork(sess connector.Session) {
	h.t.Helper()
	if _, ok := sess.(*wecasa.Session); !ok {
		h.t.Fatalf("Login returned %T, want *wecasa.Session", sess)
	}
	if err := h.c.Probe(h.t.Context(), sess); err != nil {
		h.t.Fatalf("Probe on the session Login returned: %v", err)
	}
}

// TestLogin_PasswordThenListAndFetch is the happy path on the recorded
// fixtures: browser login, cookies exported, token read, 2026 listed,
// one invoice fetched.
func TestLogin_PasswordThenListAndFetch(t *testing.T) {
	t.Parallel()
	h := newHarness(t, wecasa.Options{})
	h.use(newScript(h.cookies()))

	sess, err := h.run(t.Context())
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	h.mustWork(sess)
	h.assertAllClosed()

	launches := h.pool.launches()
	if len(launches) != 1 || launches[0].Visible {
		t.Fatalf("launches = %+v, want one headless", launches)
	}
	if !slices.Equal(launches[0].AllowedDomains, []string{wwwHost}) || !slices.Equal(launches[0].Static, []string{staticPrefix}) {
		t.Errorf("launch options = %+v, want the Info allowlist and static prefix", launches[0])
	}
	b := h.browser(0)
	if v, ok := b.typedValue(selEmail); !ok || v != h.login {
		t.Errorf("%s typed %v, want the login", selEmail, ok)
	}
	if v, ok := b.typedValue(selPassword); !ok || v != h.password {
		t.Errorf("%s typed %v, want the password", selPassword, ok)
	}
	if n := b.count("click"); n != 1 {
		t.Errorf("%d clicks, want 1 (submit)", n)
	}
	for _, o := range b.opList() {
		if o.kind == "navigate" && o.arg != loginURL {
			t.Errorf("navigated to %q, want only %s", o.arg, loginURL)
		}
		if o.kind != "close" && !o.hasDeadline {
			t.Errorf("browser %s %s ran without a deadline", o.kind, o.arg)
		}
	}
	if got := b.cookieRequests(); len(got) != 1 || !slices.Equal(got[0], []string{wwwHost}) {
		t.Errorf("cookie requests = %v, want one for [%s]", got, wwwHost)
	}
	if got := h.prompt.requests(); len(got) != 0 {
		t.Errorf("the user was prompted %d times: Wecasa has no code step", len(got))
	}
	if i, j := h.rec.index("resolve "+refPhrase), h.rec.index("launch headless"); i < 0 || j < 0 || i > j {
		t.Errorf("events = %v: credentials must be resolved before the launch", h.rec.list())
	}

	refs, err := h.c.List(t.Context(), sess, connector.Year(2026))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	assertRefs(t, refs, recorded2026)
	rc, err := h.c.Fetch(t.Context(), sess, refs[3]) // aCMmbqzTPFDb, the recorded PDF
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	_ = rc.Close()

	blob, err := sess.(connector.Persistable).Persist(t.Context())
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if strings.Contains(blob.Expose(), "FOREIGN-COOKIE-VALUE") {
		t.Error("a cookie of another domain was persisted")
	}
	h.assertNoLeak(sess, nil)
}

// TestLogin_SavedSession: a valid saved session is reused without browser
// nor secret; an expired one falls back to the browser with a clean jar;
// a rate-limited probe is returned as is.
func TestLogin_SavedSession(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, wecasa.Options{})
		blob, err := h.site.session(t).Persist(t.Context())
		if err != nil {
			t.Fatalf("Persist: %v", err)
		}
		h.env.Saved = blob
		sess, err := h.run(t.Context())
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		h.mustWork(sess)
		if n := len(h.pool.launches()); n != 0 {
			t.Errorf("%d browsers launched for a valid saved session", n)
		}
		if calls := h.res.callList(); len(calls) != 0 {
			t.Errorf("secrets resolved for a valid saved session: %v", calls)
		}
		h.assertNoLeak(sess, nil)
	})

	t.Run("expired falls back to the browser", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, wecasa.Options{})
		blob, err := h.site.session(t).Persist(t.Context())
		if err != nil {
			t.Fatalf("Persist: %v", err)
		}
		// The site moves to a new token: the saved one gets 401.
		oldToken := h.site.token
		h.site.mu.Lock()
		h.site.token = testsecrets.Canary(t, testsecrets.Token)
		h.site.page = pageWithToken(t, "token: '"+h.site.token+"'")
		h.site.mu.Unlock()
		h.env.Saved = blob
		h.use(newScript(h.cookies()))
		sess, err := h.run(t.Context())
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		h.mustWork(sess)
		if n := len(h.pool.launches()); n != 1 {
			t.Errorf("%d launches, want 1", n)
		}
		h.assertAllClosed()
		nb, err := sess.(connector.Persistable).Persist(t.Context())
		if err != nil {
			t.Fatalf("Persist: %v", err)
		}
		if strings.Contains(nb.Expose(), oldToken) {
			t.Error("the stale token survived the new login")
		}
		h.assertNoLeak(sess, nil)
	})

	t.Run("malformed blob falls back to the browser", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, wecasa.Options{})
		h.env.Saved = secret.FromString("not a blob")
		h.use(newScript(h.cookies()))
		sess, err := h.run(t.Context())
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		h.mustWork(sess)
	})

	t.Run("rate limited probe is returned without browser", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, wecasa.Options{})
		blob, err := h.site.session(t).Persist(t.Context())
		if err != nil {
			t.Fatalf("Persist: %v", err)
		}
		h.site.route(pathUser, status(429))
		h.env.Saved = blob
		_, err = h.run(t.Context())
		if !errors.Is(err, connector.ErrRateLimited) {
			t.Fatalf("Login = %v, want ErrRateLimited", err)
		}
		if n := len(h.pool.launches()); n != 0 {
			t.Errorf("%d browsers launched", n)
		}
		if n := h.site.hitsWithPrefix("GET " + pathUser); n != 1 {
			t.Errorf("probe sent %d times, want exactly 1", n)
		}
	})
}

// TestLogin_WrongPasswordAuthFailed: the form shown again after submit.
func TestLogin_WrongPasswordAuthFailed(t *testing.T) {
	t.Parallel()
	h := newHarness(t, wecasa.Options{})
	h.use(newScript(h.cookies(), afterSubmit(pgBadCreds)))
	sess, err := h.run(t.Context())
	if !errors.Is(err, connector.ErrAuthFailed) || sess != nil {
		t.Fatalf("Login = %v, %v; want ErrAuthFailed", sess, err)
	}
	if n := h.browser(0).count("cookies"); n != 0 {
		t.Errorf("cookies read %d times after a rejected login", n)
	}
	h.assertAllClosed()
	h.assertNoLeak(nil, err)
}

// TestLogin_ManualPagesNeverAutomated: a Cloudflare challenge or an
// unknown page, at entry or after submit. Non-interactive → ErrNeedsLogin,
// one browser. Interactive → the headless browser is closed, a visible
// one (same allowlist and static prefix) opens the login URL, and the
// user's login is used; nothing is typed or clicked in it.
func TestLogin_ManualPagesNeverAutomated(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mod  func(*script)
	}{
		{"challenge at entry", entry(pgCaptcha)},
		{"challenge after submit", afterSubmit(pgCaptcha)},
		{"challenge inside the form at entry", entry(pgFormChallenge)},
		{"challenge inside the form after submit", afterSubmit(pgFormChallenge)},
		{"unknown page at entry", entry(pgUnknown)},
		{"unknown page after submit", afterSubmit(pgUnknown)},
	}
	for _, tc := range cases {
		t.Run(tc.name+" non-interactive", func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, wecasa.Options{})
			h.use(newScript(h.cookies(), tc.mod))
			sess, err := h.run(t.Context())
			if !errors.Is(err, connector.ErrNeedsLogin) || sess != nil {
				t.Fatalf("Login = %v, %v; want ErrNeedsLogin", sess, err)
			}
			if n := len(h.pool.launches()); n != 1 {
				t.Errorf("%d launches, want 1", n)
			}
			h.assertAllClosed()
			h.assertNoLeak(nil, err)
		})
		t.Run(tc.name+" interactive", func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, wecasa.Options{})
			h.interactive(true)
			visible := newScript(h.cookies(), tc.mod, func(s *script) { s.userDone = pgAccount })
			h.use(newScript(h.cookies(), tc.mod), visible)
			sess, err := h.run(t.Context())
			if err != nil {
				t.Fatalf("Login: %v", err)
			}
			h.mustWork(sess)
			launches := h.pool.launches()
			if len(launches) != 2 || launches[0].Visible || !launches[1].Visible {
				t.Fatalf("launches = %+v, want headless then visible", launches)
			}
			if !slices.Equal(launches[1].AllowedDomains, []string{wwwHost}) || !slices.Equal(launches[1].Static, []string{staticPrefix}) {
				t.Errorf("visible launch options = %+v", launches[1])
			}
			if i, j := h.rec.index("b1 close"), h.rec.index("launch visible"); i < 0 || i > j {
				t.Errorf("events = %v: the headless browser must close before the visible launch", h.rec.list())
			}
			v := h.browser(1)
			if v.count("type") != 0 || v.count("click") != 0 {
				t.Errorf("the visible browser was typed into or clicked: %+v", v.opList())
			}
			h.assertAllClosed()
			h.assertNoLeak(sess, nil)
		})
	}

	t.Run("user does not finish in time", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, wecasa.Options{UserTimeout: time.Millisecond})
		h.interactive(true)
		h.use(newScript(h.cookies(), entry(pgCaptcha)), newScript(h.cookies(), entry(pgCaptcha)))
		_, err := h.run(t.Context())
		if !errors.Is(err, connector.ErrNeedsLogin) {
			t.Fatalf("Login = %v, want ErrNeedsLogin", err)
		}
		h.assertAllClosed()
	})
}

// TestLogin_SiteChangedBroken: a selector the flow needs missing, a page
// outside the allowlist, no session cookie → ErrBroken naming the piece.
func TestLogin_SiteChangedBroken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		mod   func(*script)
		piece string
	}{
		{name: "login form gone", mod: withPage(pgLogin, fakePage{url: loginURL}), piece: selForm},
		{name: "password field gone", mod: withPage(pgLogin, fakePage{url: loginURL, visible: []string{selForm, selEmail, selSubmit}}), piece: selPassword},
		{name: "submit gone", mod: withPage(pgLogin, fakePage{url: loginURL, visible: []string{selForm, selEmail, selPassword}}), piece: selSubmit},
		{name: "logout link gone", mod: withPage(pgAccount, fakePage{url: accountURL}), piece: selLogout},
		{name: "landed off the allowlist", mod: withPage(pgAccount, fakePage{url: "https://evil.test/customer-area", visible: []string{selLogout}}), piece: "allowlist"},
		{name: "landed on http", mod: withPage(pgAccount, fakePage{url: "http://www.wecasa.fr/customer-area", visible: []string{selLogout}}), piece: "https"},
		{name: "no session cookie", mod: func(s *script) { s.cookies = nil }, piece: "cookie"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, wecasa.Options{})
			h.use(newScript(h.cookies(), tt.mod))
			sess, err := h.run(t.Context())
			if !errors.Is(err, connector.ErrBroken) || sess != nil {
				t.Fatalf("Login = %v, %v; want ErrBroken", sess, err)
			}
			if !strings.Contains(err.Error(), tt.piece) {
				t.Errorf("error %q does not name %q", err, tt.piece)
			}
			h.assertAllClosed()
			h.assertNoLeak(nil, err)
		})
	}
}

// TestLogin_PageWithoutTokenNeedsLogin: the browser login worked but the
// bookings page holds no token: the session is not usable.
func TestLogin_PageWithoutTokenNeedsLogin(t *testing.T) {
	t.Parallel()
	h := newHarness(t, wecasa.Options{})
	h.site.setPage(fixture(t, "005-get-customer-area.html"))
	h.use(newScript(h.cookies()))
	sess, err := h.run(t.Context())
	if !errors.Is(err, connector.ErrNeedsLogin) || sess != nil {
		t.Fatalf("Login = %v, %v; want ErrNeedsLogin", sess, err)
	}
	h.assertAllClosed()
	h.assertNoLeak(nil, err)
}

// TestLogin_FailsEarly: missing dependencies or credentials fail before
// any launch; a cancelled context is returned as such, never ErrBroken.
func TestLogin_FailsEarly(t *testing.T) {
	t.Parallel()

	t.Run("no http client", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, wecasa.Options{})
		h.env.HTTP = nil
		if _, err := h.run(t.Context()); err == nil {
			t.Fatal("Login without HTTP succeeded")
		}
	})
	t.Run("no browser", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, wecasa.Options{})
		h.env.Browser = nil
		if _, err := h.run(t.Context()); err == nil {
			t.Fatal("Login without browser succeeded")
		}
	})
	t.Run("resolver error", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, wecasa.Options{})
		boom := errors.New("vault locked")
		h.res.err = boom
		_, err := h.run(t.Context())
		if !errors.Is(err, boom) {
			t.Fatalf("Login = %v, want the resolver error", err)
		}
		if n := len(h.pool.launches()); n != 0 {
			t.Errorf("%d launches after a resolver failure", n)
		}
	})
	t.Run("no password reference", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, wecasa.Options{})
		h.env.Credentials.Password = ""
		if _, err := h.run(t.Context()); err == nil || len(h.pool.launches()) != 0 {
			t.Fatalf("Login = %v with %d launches; want an error, no launch", err, len(h.pool.launches()))
		}
	})
	t.Run("empty secret", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, wecasa.Options{})
		h.res.vals[refLogin] = ""
		if _, err := h.run(t.Context()); err == nil {
			t.Fatal("Login with an empty login succeeded")
		}
	})
	t.Run("launch error", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, wecasa.Options{})
		h.pool.launchErr = errors.New("no chrome")
		if _, err := h.run(t.Context()); err == nil {
			t.Fatal("Login with a failing pool succeeded")
		}
	})
	t.Run("context cancelled mid-flow", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, wecasa.Options{})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		h.use(newScript(h.cookies(), func(s *script) {
			s.onOp = func(kind, _ string) {
				if kind == "click" {
					cancel()
				}
			}
		}))
		_, err := h.run(ctx)
		if !errors.Is(err, context.Canceled) || errors.Is(err, connector.ErrBroken) {
			t.Fatalf("Login = %v, want context.Canceled and not ErrBroken", err)
		}
		h.assertAllClosed()
	})
	t.Run("browser cookie read fails", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, wecasa.Options{})
		h.use(newScript(h.cookies(), func(s *script) { s.fail["cookies"] = errors.New("cdp gone") }))
		if _, err := h.run(t.Context()); err == nil {
			t.Fatal("Login succeeded without cookies")
		}
		h.assertAllClosed()
	})
}

// TestLogin_ExpiredSavedSessionCookiesNotKept: a saved session that no
// longer works is dropped from the jar before the browser login, so its
// cookies (one the browser reissues, one it does not) never reach the new
// session nor its Persist blob.
func TestLogin_ExpiredSavedSessionCookiesNotKept(t *testing.T) {
	t.Parallel()
	h := newHarness(t, wecasa.Options{})
	staleSession := testsecrets.Canary(t, testsecrets.Cookie)
	staleRemember := testsecrets.Canary(t, testsecrets.Cookie)
	// The saved session: the site's token at the time, then stale cookies
	// overwriting the session cookie and adding one the browser never
	// reissues.
	hc := h.site.client(t)
	old, err := wecasa.NewSession(t.Context(), hc, []connector.Cookie{sessionCookie(sessionKey, h.site.cookie)})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if err := hc.SetCookies(wwwHost, []httpx.Cookie{
		{Name: sessionKey, Value: staleSession, Path: "/"},
		{Name: "remember_user_token", Value: staleRemember, Path: "/"},
	}); err != nil {
		t.Fatalf("set stale cookies: %v", err)
	}
	saved, err := old.Persist(t.Context())
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	for _, v := range []string{staleSession, staleRemember} {
		if !strings.Contains(saved.Expose(), v) {
			t.Fatal("test setup: the saved blob lacks a stale cookie")
		}
	}
	// The site moves to a new token: the saved session gets 401.
	h.site.mu.Lock()
	h.site.token = testsecrets.Canary(t, testsecrets.Token)
	h.site.page = pageWithToken(t, "token: '"+h.site.token+"'")
	h.site.mu.Unlock()
	h.env.Saved = saved
	h.use(newScript(h.cookies()))

	sess, err := h.run(t.Context())
	if err != nil {
		t.Fatalf("Login after an expired saved session: %v", err)
	}
	h.mustWork(sess)
	blob, err := sess.(connector.Persistable).Persist(t.Context())
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	got := blob.Expose()
	if !strings.Contains(got, h.site.cookie) {
		t.Error("the new Persist blob lacks the cookie the browser login produced")
	}
	for name, v := range map[string]string{"stale _wecasa_session": staleSession, "stale remember_user_token": staleRemember} {
		if strings.Contains(got, v) {
			t.Errorf("%s value from the expired saved session is in the new Persist blob", name)
		}
	}
	if strings.Contains(got, `"remember_user_token"`) {
		t.Error("cookie remember_user_token from the expired saved session survived the browser login")
	}
	h.assertNoLeak(sess, err)
	for _, v := range []string{staleSession, staleRemember} {
		if strings.Contains(h.logs.String(), v) {
			t.Error("a stale cookie leaks into the logs")
		}
	}
}
