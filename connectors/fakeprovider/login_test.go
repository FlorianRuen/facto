package fakeprovider_test

// Plan J1 T21: fakeprovider login flows over connector.BrowserPool. Tests
// written first, against the T20 placeholder Login; T21 removed that
// placeholder and its ErrLoginNotImplemented sentinel.
//
// Expected API (no new exported symbol is required by these tests; the
// signature of Login is unchanged):
//
//	func (c *Connector) Login(ctx context.Context, env connector.Env) (connector.Session, error)
//
// Suggested (not asserted by value, only "every wait is bounded"):
//
//	type Options struct {
//	    ...
//	    StepTimeout time.Duration // each automated WaitVisible; default 30s
//	    UserTimeout time.Duration // visible-window wait for the user; default 10m
//	}
//
// Behaviour, in order (page contract: docs/connectors/fakeprovider.md
// "Login flow"; the e2e fake site of T22 serves the same URLs/selectors):
//
//  1. Saved session. When !env.Saved.IsZero(): Restore(env.HTTP, env.Saved)
//     then Probe. Probe ok → return that session: no Launch, no secret
//     resolved (a scheduled run needs no vault access while sessions are
//     valid, spec "Scheduled mode"). Restore or Probe failing with
//     ErrNeedsLogin → fall back to step 2. Any other Probe error (e.g.
//     ErrRateLimited) is returned as is, no browser.
//  2. Credentials. Resolve Credentials.Login and Credentials.Password
//     through env.Secrets BEFORE launching any browser; a resolver failure
//     is returned (errors.Is the resolver error) and no browser is opened.
//     Credentials.OTP is NOT resolved here (a TOTP code is time-bound).
//  3. Headless launch: env.Browser.Launch(LaunchOptions{AllowedDomains:
//     Info().AllowedDomains, Visible: false}). Every launched browser is
//     closed exactly once on every path (success, error, cancel).
//  4. Navigate("https://www.fakeprovider.test/login") once; the connector
//     never navigates to the SSO host itself (the site redirects) and never
//     POSTs: the form is submitted by Click so the hidden CSRF field
//     (input[name=csrf_token]) travels with it; it is never typed into.
//  5. WaitVisible on "#login-form, #captcha" (any CSS selector list that
//     matches those), then CurrentURL classifies the page:
//     - path /login/captcha → captcha: never automated (no Type, no Click).
//     Non-interactive → ErrNeedsLogin. Interactive → close the headless
//     browser, Launch(Visible: true) with the same allowlist, Navigate to
//     the login URL and wait (UserTimeout) for "#account" while the user
//     completes the whole login by hand: the connector types and clicks
//     nothing in the visible window.
//     - path /login → TypeSecret("#username"), TypeSecret("#password"),
//     Click("#login-submit").
//  6. After submit, WaitVisible on a list covering "#account",
//     "#login-error", "#otp", "#email-code", "#captcha", then CurrentURL:
//     - https www /account → success (step 8);
//     - /login (either host) → bad credentials → ErrAuthFailed;
//     - /login/totp → resolve Credentials.OTP (a code, never a seed: A5),
//     TypeSecret("#otp"), Click("#otp-submit"), wait for "#account" or
//     "#otp-error" (/login/totp again → ErrAuthFailed). No OTP ref:
//     interactive → Prompter; non-interactive → ErrNeedsLogin;
//     - /login/email → email code: non-interactive (env.Interactive false)
//     → ErrNeedsLogin without calling Prompt; interactive → env.Prompt
//     once with a connector-written label (CleanLabel() == Label),
//     TypeSecret("#email-code"), Click("#email-code-submit"), wait for
//     "#account". The OTP ref is never used for an email code;
//     - /login/captcha → as in step 5;
//     - anything else, a non-https URL or a host outside the allowlist →
//     ErrBroken (no Cookies call).
//  7. Every WaitVisible runs under a context with a deadline (the real
//     browser's WaitVisible polls until ctx ends). A wait, Type or Click
//     failing while ctx is still live → ErrBroken whose message names the
//     missing selector. A cancelled ctx is returned as ctx.Err() (wrapped),
//     never ErrBroken.
//  8. Success: Cookies(ctx, Info().AllowedDomains) → NewSession(env.HTTP,
//     cookies). No cookie for www.fakeprovider.test → ErrBroken.
//  9. No secret value (login, password, OTP or email code, cookie, saved
//     blob) ever appears in an error, a log record or a rendered Session.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/connectors/fakeprovider"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// Synthetic secret references (never real ones).
const (
	refLogin  = "keyring://facto/fakeprovider/login"
	refPhrase = "keyring://facto/fakeprovider/password"
	refOTP    = "keyring://facto/fakeprovider/otp"
)

// harness wires a connector, a fake site answering /api/me, and the
// scripted doubles.
type harness struct {
	t      *testing.T
	c      *fakeprovider.Connector
	env    connector.Env
	rec    *recorder
	pool   *fakePool
	res    *fakeResolver
	prompt *fakePrompter
	logs   *syncBuffer
	site   *site
	me     *meSite

	login, password, otp, emailCode, cookie string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		t:         t,
		c:         fakeprovider.New(fakeprovider.Options{}),
		rec:       &recorder{},
		logs:      &syncBuffer{},
		login:     testsecrets.Canary(t, testsecrets.Token),
		password:  testsecrets.Canary(t, testsecrets.Password),
		otp:       testsecrets.Canary(t, testsecrets.Token),
		emailCode: testsecrets.Canary(t, testsecrets.Token),
		cookie:    canaryCookie(t),
	}
	h.me = &meSite{current: h.cookie}
	h.site = newSite(t, h.me.handler)
	h.pool = &fakePool{rec: h.rec}
	h.res = &fakeResolver{rec: h.rec, vals: map[string]string{
		refLogin: h.login, refPhrase: h.password, refOTP: h.otp,
	}}
	h.prompt = &fakePrompter{rec: h.rec, answer: h.emailCode}
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

// interactive sets Env.Interactive and the prompter to the same value.
func (h *harness) interactive(v bool) {
	h.env.Interactive = v
	h.prompt.interactive = v
}

// use queues one script per expected Launch.
func (h *harness) use(scripts ...*script) { h.pool.scripts = append(h.pool.scripts, scripts...) }

// wwwCookie is the session cookie the fake site accepts.
func (h *harness) wwwCookie() connector.Cookie { return sessionCookie(h.cookie) }

func (h *harness) run(ctx context.Context) (connector.Session, error) {
	return h.c.Login(ctx, h.env)
}

// mustProbe proves sess carries the cookie the site accepts.
func (h *harness) mustProbe(sess connector.Session) {
	h.t.Helper()
	if _, ok := sess.(*fakeprovider.Session); !ok {
		h.t.Fatalf("Login returned %T, want *fakeprovider.Session", sess)
	}
	if err := h.c.Probe(h.t.Context(), sess); err != nil {
		h.t.Fatalf("Probe on the session Login returned: %v", err)
	}
}

// browser returns the i-th launched browser (0-based).
func (h *harness) browser(i int) *fakeBrowser {
	h.t.Helper()
	bs := h.pool.launched()
	if i >= len(bs) {
		h.t.Fatalf("browser #%d was never launched (%d launched)", i+1, len(bs))
	}
	return bs[i]
}

// assertAllClosed fails unless every launched browser was closed exactly once.
func (h *harness) assertAllClosed() {
	h.t.Helper()
	for i, b := range h.pool.launched() {
		if n := b.closeCount(); n != 1 {
			h.t.Errorf("browser #%d closed %d times, want exactly 1", i+1, n)
		}
	}
}

// assertNoLeak fails if any secret of the harness shows in err, the logs,
// the prompt labels or the rendered session.
func (h *harness) assertNoLeak(sess connector.Session, err error, extra ...string) {
	h.t.Helper()
	var out strings.Builder
	if err != nil {
		fmt.Fprintf(&out, "%v|%+v|%#v|%s|", err, err, err, err.Error())
	}
	if sess != nil {
		out.WriteString(rendered(sess))
	}
	out.WriteString(h.logs.String())
	for _, r := range h.prompt.requests() {
		out.WriteString(r.Label + "|" + r.CleanLabel() + "|")
	}
	s := out.String()
	for _, c := range append([]string{h.login, h.password, h.otp, h.emailCode, h.cookie}, extra...) {
		if c != "" && strings.Contains(s, c) {
			h.t.Errorf("secret canary %q rendered in error/log/label/session output", c)
		}
	}
}

// typed asserts what browser b typed into sel.
func typed(t *testing.T, b *fakeBrowser, sel, want string) {
	t.Helper()
	got, ok := b.typedValue(sel)
	if !ok {
		t.Fatalf("nothing typed into %s; ops = %v", sel, b.opList())
	}
	if got != want {
		t.Fatalf("value typed into %s is not the resolved secret", sel)
	}
}

// opIndex returns the index of the first op (kind, arg) or -1.
func opIndex(ops []op, kind, arg string) int {
	return slices.IndexFunc(ops, func(o op) bool { return o.kind == kind && o.arg == arg })
}

// clicks counts the clicks on sel.
func clicks(ops []op, sel string) int {
	n := 0
	for _, o := range ops {
		if o.kind == "click" && o.arg == sel {
			n++
		}
	}
	return n
}

// savedBlob persists a session carrying cookie value v.
func (h *harness) savedBlob(v string) secret.Secret {
	h.t.Helper()
	blob, err := h.site.session(h.t, v).Persist(h.t.Context())
	if err != nil {
		h.t.Fatalf("Persist: %v", err)
	}
	return blob
}

func TestLogin_RestoresSavedSessionWithoutBrowser(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		noBrowser bool
	}{
		{name: "pool present but unused"},
		{name: "no browser pool at all", noBrowser: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.env.Saved = h.savedBlob(h.cookie)
			if tc.noBrowser {
				h.env.Browser = nil
			}

			sess, err := h.run(t.Context())
			if err != nil {
				t.Fatalf("Login with a valid saved session: %v", err)
			}
			h.mustProbe(sess)
			if n := len(h.pool.launches()); n != 0 {
				t.Errorf("Launch called %d times, want 0 (saved session still valid)", n)
			}
			if calls := h.res.callList(); len(calls) != 0 {
				t.Errorf("secrets resolved %q, want none: a valid saved session needs no vault access", calls)
			}
			if n := len(h.prompt.requests()); n != 0 {
				t.Errorf("Prompt called %d times, want 0", n)
			}
			h.assertNoLeak(sess, err)
		})
	}
}

func TestLogin_ExpiredSavedSessionFallsBackToBrowser(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		saved func(h *harness) secret.Secret
	}{
		{name: "site answers 401 to the saved cookie", saved: func(h *harness) secret.Secret {
			return h.savedBlob(canaryCookie(h.t)) // a cookie the site no longer accepts
		}},
		{name: "malformed saved blob", saved: func(*harness) secret.Secret {
			return secret.FromString(`{"v":1,"cookies":`)
		}},
		{name: "foreign version", saved: func(*harness) secret.Secret {
			return secret.FromString(`{"v":99,"cookies":[]}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			saved := tc.saved(h)
			h.env.Saved = saved
			h.use(newScript([]connector.Cookie{h.wwwCookie()}))

			sess, err := h.run(t.Context())
			if err != nil {
				t.Fatalf("Login after an expired saved session: %v", err)
			}
			h.mustProbe(sess)
			if l := h.pool.launches(); len(l) != 1 || l[0].Visible {
				t.Fatalf("launches = %+v, want exactly one headless launch", l)
			}
			h.assertAllClosed()
			h.assertNoLeak(sess, err, saved.Expose())
		})
	}

	t.Run("rate-limited probe is returned, no browser", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.site = newSite(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "slow down", http.StatusTooManyRequests)
		})
		h.env.HTTP = h.site.client(t)
		h.env.Saved = h.savedBlob(h.cookie)
		h.use(newScript([]connector.Cookie{h.wwwCookie()}))

		_, err := h.run(t.Context())
		if !errors.Is(err, connector.ErrRateLimited) {
			t.Fatalf("Login error = %v, want ErrRateLimited", err)
		}
		if n := len(h.pool.launches()); n != 0 {
			t.Fatalf("Launch called %d times after a 429, want 0", n)
		}
	})
}

func TestLogin_PasswordWithCSRF(t *testing.T) {
	t.Parallel()

	t.Run("form flow", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.env.Credentials.OTP = refOTP // configured but not needed by this flow
		foreign := canaryCookie(t)
		evil := sessionCookie(foreign)
		evil.Name, evil.Domain = "tracker", evilHost
		h.use(newScript([]connector.Cookie{h.wwwCookie(), evil}))

		sess, err := h.run(t.Context())
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		h.mustProbe(sess)

		allowed := h.c.Info().AllowedDomains
		l := h.pool.launches()
		if len(l) != 1 {
			t.Fatalf("launches = %+v, want exactly one", l)
		}
		if l[0].Visible {
			t.Error("first launch is visible, want headless")
		}
		if !slices.Equal(l[0].AllowedDomains, allowed) {
			t.Errorf("LaunchOptions.AllowedDomains = %q, want Info().AllowedDomains %q", l[0].AllowedDomains, allowed)
		}

		b := h.browser(0)
		ops := b.opList()
		if got := b.count("navigate"); got != 1 || opIndex(ops, "navigate", loginURL) != 0 {
			t.Errorf("navigations = %v, want exactly one, first, to %s (the form submits itself: CSRF travels with it)", ops, loginURL)
		}
		typed(t, b, selUsername, h.login)
		typed(t, b, selPassword, h.password)
		if _, ok := b.typedValue(selCSRF); ok || opIndex(ops, "type", selCSRF) >= 0 {
			t.Error("the hidden CSRF field was typed into")
		}
		iU, iP, iS := opIndex(ops, "type", selUsername), opIndex(ops, "type", selPassword), opIndex(ops, "click", selSubmit)
		if iU >= iS || iP >= iS {
			t.Errorf("submit clicked before both fields were typed: ops = %v", ops)
		}
		if n := clicks(ops, selSubmit); n != 1 {
			t.Errorf("submit clicked %d times, want 1", n)
		}
		for _, o := range ops {
			if o.kind == "wait" && !o.hasDeadline {
				t.Errorf("WaitVisible(%q) ran without a deadline: the real browser would poll forever", o.arg)
			}
		}
		if req := b.cookieRequests(); len(req) != 1 || !slices.Equal(req[0], allowed) {
			t.Errorf("Cookies domains = %q, want once with Info().AllowedDomains %q", req, allowed)
		}

		// Credentials resolved before launch; OTP never (not needed).
		if iL, iR := h.rec.index("launch headless"), h.rec.index("resolve "+refPhrase); iR < 0 || iR > iL {
			t.Errorf("password resolved after the browser was launched: events = %v", h.rec.list())
		}
		if slices.Contains(h.res.callList(), refOTP) {
			t.Error("OTP reference resolved although the site never asked for a code")
		}
		if n := len(h.prompt.requests()); n != 0 {
			t.Errorf("Prompt called %d times, want 0", n)
		}

		// Only allowlisted cookies reach the session.
		blob, err := sess.(*fakeprovider.Session).Persist(t.Context())
		if err != nil {
			t.Fatalf("Persist: %v", err)
		}
		if strings.Contains(blob.Expose(), foreign) {
			t.Error("a cookie of a host outside the allowlist reached the session")
		}
		h.assertAllClosed()
		h.assertNoLeak(sess, err, foreign)
	})

	t.Run("resolver failure opens no browser", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		errVault := errors.New("synthetic vault locked")
		h.res.err = errVault
		h.use(newScript([]connector.Cookie{h.wwwCookie()}))

		_, err := h.run(t.Context())
		if !errors.Is(err, errVault) {
			t.Fatalf("Login error = %v, want the resolver error in the chain", err)
		}
		if n := len(h.pool.launches()); n != 0 {
			t.Fatalf("Launch called %d times, want 0 when credentials cannot be resolved", n)
		}
	})

	t.Run("missing credential reference opens no browser", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.env.Credentials.Password = ""
		h.use(newScript([]connector.Cookie{h.wwwCookie()}))

		if _, err := h.run(t.Context()); err == nil {
			t.Fatal("Login succeeded without a password reference")
		}
		if n := len(h.pool.launches()); n != 0 {
			t.Fatalf("Launch called %d times, want 0", n)
		}
	})
}

func TestLogin_TOTPFromOTPRef(t *testing.T) {
	t.Parallel()

	t.Run("otp ref resolves to a code typed after the password step", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.env.Credentials.OTP = refOTP
		h.use(newScript([]connector.Cookie{h.wwwCookie()}, afterSubmit(pgTOTP)))

		sess, err := h.run(t.Context())
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		h.mustProbe(sess)
		b := h.browser(0)
		typed(t, b, selOTP, h.otp) // the resolved value is typed as is: a code, never a seed (A5)
		if n := clicks(b.opList(), selOTPSubmit); n != 1 {
			t.Errorf("OTP submit clicked %d times, want 1", n)
		}
		calls := h.res.callList()
		if n := len(slices.DeleteFunc(slices.Clone(calls), func(r string) bool { return r != refOTP })); n != 1 {
			t.Errorf("OTP ref resolved %d times, want exactly 1 (calls %q)", n, calls)
		}
		if iC, iR := h.rec.index("b1 click "+selSubmit), h.rec.index("resolve "+refOTP); iR < iC {
			t.Errorf("OTP resolved before the password was submitted (codes are time-bound): events = %v", h.rec.list())
		}
		if n := len(h.prompt.requests()); n != 0 {
			t.Errorf("Prompt called %d times, want 0 with an OTP ref", n)
		}
		h.assertAllClosed()
		h.assertNoLeak(sess, err)
	})

	t.Run("no otp ref, non-interactive", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.use(newScript([]connector.Cookie{h.wwwCookie()}, afterSubmit(pgTOTP)))

		sess, err := h.run(t.Context())
		if !errors.Is(err, connector.ErrNeedsLogin) {
			t.Fatalf("Login error = %v, want ErrNeedsLogin", err)
		}
		b := h.browser(0)
		if _, ok := b.typedValue(selOTP); ok {
			t.Error("something was typed into the OTP field without a code")
		}
		if n := len(h.prompt.requests()); n != 0 {
			t.Errorf("Prompt called %d times in a non-interactive run", n)
		}
		h.assertAllClosed()
		h.assertNoLeak(sess, err)
	})

	t.Run("no otp ref, interactive prompts once", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.interactive(true)
		h.use(newScript([]connector.Cookie{h.wwwCookie()}, afterSubmit(pgTOTP)))

		sess, err := h.run(t.Context())
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		h.mustProbe(sess)
		if n := len(h.prompt.requests()); n != 1 {
			t.Fatalf("Prompt called %d times, want 1", n)
		}
		typed(t, h.browser(0), selOTP, h.emailCode)
		h.assertAllClosed()
		h.assertNoLeak(sess, err)
	})
}

func TestLogin_EmailOTPPrompts(t *testing.T) {
	t.Parallel()

	t.Run("interactive user types the emailed code", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.interactive(true)
		h.env.Credentials.OTP = refOTP // a TOTP ref is never used for an email code
		h.use(newScript([]connector.Cookie{h.wwwCookie()}, afterSubmit(pgEmail)))

		sess, err := h.run(t.Context())
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		h.mustProbe(sess)
		reqs := h.prompt.requests()
		if len(reqs) != 1 {
			t.Fatalf("Prompt called %d times, want exactly 1", len(reqs))
		}
		if l := reqs[0].Label; l == "" || reqs[0].CleanLabel() != l {
			t.Errorf("prompt label %q is empty or not clean (CleanLabel %q)", l, reqs[0].CleanLabel())
		}
		b := h.browser(0)
		typed(t, b, selEmailCode, h.emailCode)
		if n := clicks(b.opList(), selEmailSub); n != 1 {
			t.Errorf("email code submit clicked %d times, want 1", n)
		}
		if slices.Contains(h.res.callList(), refOTP) {
			t.Error("the OTP ref was resolved for an email code")
		}
		if i, j := h.rec.index("b1 click "+selSubmit), h.rec.index("prompt"); j < i {
			t.Errorf("prompted before the site asked for a code: events = %v", h.rec.list())
		}
		if n := len(h.pool.launches()); n != 1 {
			t.Errorf("launches = %d, want 1 (an email code needs no visible window)", n)
		}
		h.assertAllClosed()
		h.assertNoLeak(sess, err)
	})

	t.Run("prompt error is returned", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.interactive(true)
		h.prompt.err = fmt.Errorf("%w: synthetic: user aborted", connector.ErrNeedsLogin)
		h.use(newScript([]connector.Cookie{h.wwwCookie()}, afterSubmit(pgEmail)))

		sess, err := h.run(t.Context())
		if !errors.Is(err, connector.ErrNeedsLogin) {
			t.Fatalf("Login error = %v, want the prompter's ErrNeedsLogin", err)
		}
		if _, ok := h.browser(0).typedValue(selEmailCode); ok {
			t.Error("something was typed into the email code field after the prompt failed")
		}
		h.assertAllClosed()
		h.assertNoLeak(sess, err)
	})
}

func TestLogin_EmailOTPNonInteractiveNeedsLogin(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.interactive(false)
	h.use(newScript([]connector.Cookie{h.wwwCookie()}, afterSubmit(pgEmail)))

	sess, err := h.run(t.Context())
	if !errors.Is(err, connector.ErrNeedsLogin) {
		t.Fatalf("Login error = %v, want ErrNeedsLogin", err)
	}
	if sess != nil {
		t.Errorf("Login returned a session (%v) with an error", sess)
	}
	if n := len(h.prompt.requests()); n != 0 {
		t.Errorf("Prompt called %d times; the connector must decide on Env.Interactive", n)
	}
	b := h.browser(0)
	if _, ok := b.typedValue(selEmailCode); ok {
		t.Error("something was typed into the email code field")
	}
	if n := b.count("cookies"); n != 0 {
		t.Errorf("Cookies called %d times on a failed login", n)
	}
	if l := h.pool.launches(); len(l) != 1 || l[0].Visible {
		t.Errorf("launches = %+v, want one headless launch and no visible relaunch", l)
	}
	h.assertAllClosed()
	h.assertNoLeak(sess, err)
}

func TestLogin_SSORedirectAcrossAllowedHosts(t *testing.T) {
	t.Parallel()

	ssoEntry := func(s *script) { s.nav[loginURL] = pgSSOLogin } // www/login 302 → sso/login

	t.Run("www to sso to www", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		ssoCk := sessionCookie(canaryCookie(t))
		ssoCk.Name, ssoCk.Domain = "fp_sso", ssoHost
		h.use(newScript([]connector.Cookie{h.wwwCookie(), ssoCk}, ssoEntry))

		sess, err := h.run(t.Context())
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		h.mustProbe(sess)
		b := h.browser(0)
		ops := b.opList()
		if n := b.count("navigate"); n != 1 || opIndex(ops, "navigate", loginURL) < 0 {
			t.Errorf("navigations = %v, want only %s (the site redirects to sso, not the connector)", ops, loginURL)
		}
		typed(t, b, selUsername, h.login)
		typed(t, b, selPassword, h.password)
		h.assertAllClosed()
		h.assertNoLeak(sess, err, ssoCk.Value.Expose())
	})

	for _, tc := range []struct {
		name, url string
	}{
		{name: "lands outside the allowlist", url: "https://" + evilHost + "/account"},
		{name: "lands on plain http", url: "http://" + wwwHost + "/account"},
		{name: "lands on a parent domain", url: "https://fakeprovider.test/account"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.use(newScript([]connector.Cookie{h.wwwCookie()}, ssoEntry,
				withPage("elsewhere", fakePage{url: tc.url, visible: []string{selAccount}}),
				afterSubmit("elsewhere")))

			sess, err := h.run(t.Context())
			if !errors.Is(err, connector.ErrBroken) {
				t.Fatalf("Login error = %v, want ErrBroken", err)
			}
			if sess != nil {
				t.Errorf("Login returned a session (%v) with an error", sess)
			}
			if n := h.browser(0).count("cookies"); n != 0 {
				t.Errorf("Cookies called %d times after landing on %s", n, tc.url)
			}
			if strings.Contains(err.Error(), "?") {
				t.Errorf("error %q carries a query string", err)
			}
			h.assertAllClosed()
		})
	}
}

func TestLogin_CaptchaNeverAutomated(t *testing.T) {
	t.Parallel()

	// noAutomation fails if b typed or clicked anything at all.
	noAutomation := func(t *testing.T, name string, b *fakeBrowser) {
		t.Helper()
		for _, o := range b.opList() {
			if o.kind == "type" || o.kind == "click" {
				t.Errorf("%s browser: %s %s on a captcha flow; captcha pages are never automated", name, o.kind, o.arg)
			}
		}
	}

	t.Run("non-interactive needs login without submitting", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.use(newScript([]connector.Cookie{h.wwwCookie()}, entry(pgCaptcha)))

		sess, err := h.run(t.Context())
		if !errors.Is(err, connector.ErrNeedsLogin) {
			t.Fatalf("Login error = %v, want ErrNeedsLogin", err)
		}
		noAutomation(t, "headless", h.browser(0))
		if l := h.pool.launches(); len(l) != 1 {
			t.Errorf("launches = %+v, want one (no visible window when non-interactive)", l)
		}
		if n := len(h.prompt.requests()); n != 0 {
			t.Errorf("Prompt called %d times", n)
		}
		h.assertAllClosed()
		h.assertNoLeak(sess, err)
	})

	t.Run("captcha after submit, non-interactive", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.use(newScript([]connector.Cookie{h.wwwCookie()}, afterSubmit(pgCaptcha)))

		sess, err := h.run(t.Context())
		if !errors.Is(err, connector.ErrNeedsLogin) {
			t.Fatalf("Login error = %v, want ErrNeedsLogin", err)
		}
		for _, o := range h.browser(0).opList() {
			if (o.kind == "type" || o.kind == "click") && strings.Contains(o.arg, "captcha") {
				t.Errorf("%s %s: captcha touched", o.kind, o.arg)
			}
		}
		h.assertAllClosed()
		h.assertNoLeak(sess, err)
	})

	t.Run("interactive relaunches visible and the user completes", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.interactive(true)
		headless := newScript([]connector.Cookie{h.wwwCookie()}, entry(pgCaptcha))
		visible := newScript([]connector.Cookie{h.wwwCookie()}, entry(pgCaptcha))
		visible.userDone = pgAccount // the user solves the captcha and logs in
		h.use(headless, visible)

		sess, err := h.run(t.Context())
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		h.mustProbe(sess)

		l := h.pool.launches()
		if len(l) != 2 || l[0].Visible || !l[1].Visible {
			t.Fatalf("launches = %+v, want headless then visible", l)
		}
		if allowed := h.c.Info().AllowedDomains; !slices.Equal(l[1].AllowedDomains, allowed) {
			t.Errorf("visible LaunchOptions.AllowedDomains = %q, want %q", l[1].AllowedDomains, allowed)
		}
		if iC, iL := h.rec.index("b1 close"), h.rec.index("launch visible"); iC < 0 || iC > iL {
			t.Errorf("headless browser not closed before the visible relaunch: events = %v", h.rec.list())
		}
		noAutomation(t, "headless", h.browser(0))
		noAutomation(t, "visible", h.browser(1))
		for _, o := range h.browser(1).opList() {
			if o.kind == "wait" && !o.hasDeadline {
				t.Errorf("user wait %q has no deadline", o.arg)
			}
		}
		if n := h.browser(1).count("cookies"); n != 1 {
			t.Errorf("visible browser Cookies called %d times, want 1", n)
		}
		h.assertAllClosed()
		h.assertNoLeak(sess, err)
	})

	t.Run("interactive, user never completes", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.interactive(true)
		h.use(newScript(nil, entry(pgCaptcha)), newScript(nil, entry(pgCaptcha))) // no userDone

		sess, err := h.run(t.Context())
		if err == nil {
			t.Fatal("Login succeeded although the user never completed the captcha")
		}
		if errors.Is(err, connector.ErrBroken) {
			t.Errorf("Login error = %v: a user timeout is not a site change", err)
		}
		noAutomation(t, "visible", h.browser(1))
		h.assertAllClosed()
		h.assertNoLeak(sess, err)
	})
}

func TestLogin_BadPasswordAuthFailed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		mods []func(*script)
		otp  bool
	}{
		{name: "login form shown again with an error", mods: []func(*script){afterSubmit(pgBadCreds)}},
		{name: "sso login form shown again with an error", mods: []func(*script){
			func(s *script) { s.nav[loginURL] = pgSSOLogin },
			withPage(pgBadCreds, fakePage{url: ssoLoginURL, visible: []string{selLoginForm, selUsername, selPassword, selSubmit, selLoginError}}),
			afterSubmit(pgBadCreds),
		}},
		{name: "wrong totp code", otp: true, mods: []func(*script){
			afterSubmit(pgTOTP),
			func(s *script) {
				p := s.pages[pgTOTP]
				p.next = map[string]string{selOTPSubmit: pgTOTPErr}
				s.pages[pgTOTP] = p
			},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			if tc.otp {
				h.env.Credentials.OTP = refOTP
			}
			h.use(newScript([]connector.Cookie{h.wwwCookie()}, tc.mods...))

			sess, err := h.run(t.Context())
			if !errors.Is(err, connector.ErrAuthFailed) {
				t.Fatalf("Login error = %v, want ErrAuthFailed", err)
			}
			if errors.Is(err, connector.ErrBroken) || errors.Is(err, connector.ErrNeedsLogin) {
				t.Errorf("Login error = %v also matches another state", err)
			}
			if sess != nil {
				t.Errorf("Login returned a session (%v) with an error", sess)
			}
			b := h.browser(0)
			if n := clicks(b.opList(), selSubmit); n != 1 {
				t.Errorf("login submitted %d times, want 1 (never retry a rejected password)", n)
			}
			if n := b.count("cookies"); n != 0 {
				t.Errorf("Cookies called %d times on a rejected login", n)
			}
			h.assertAllClosed()
			h.assertNoLeak(sess, err)
		})
	}
}

func TestLogin_MissingSelectorBroken(t *testing.T) {
	t.Parallel()
	loginWithout := func(missing string) func(*script) {
		return func(s *script) {
			p := s.pages[pgLogin]
			p.visible = slices.DeleteFunc(slices.Clone(p.visible), func(v string) bool { return v == missing })
			s.pages[pgLogin] = p
		}
	}
	for _, tc := range []struct {
		name     string
		mods     []func(*script)
		noCookie bool
		wantName string // the missing piece the error must name ("" = no check)
	}{
		{name: "login page replaced", wantName: selLoginForm, mods: []func(*script){
			withPage("maintenance", fakePage{url: loginURL, visible: []string{"#maintenance"}}),
			entry("maintenance"),
		}},
		{name: "login url serves nothing", wantName: selLoginForm, mods: []func(*script){
			func(s *script) { delete(s.nav, loginURL) },
		}},
		{name: "username field missing", wantName: selUsername, mods: []func(*script){loginWithout(selUsername)}},
		{name: "password field missing", wantName: selPassword, mods: []func(*script){loginWithout(selPassword)}},
		{name: "submit button missing", wantName: selSubmit, mods: []func(*script){loginWithout(selSubmit)}},
		{name: "nothing recognisable after submit", mods: []func(*script){
			withPage("blank", fakePage{url: "https://" + wwwHost + "/account"}),
			afterSubmit("blank"),
		}},
		{name: "unknown page after submit", mods: []func(*script){
			withPage("unknown", fakePage{url: "https://" + wwwHost + "/welcome-v2", visible: []string{selAccount}}),
			afterSubmit("unknown"),
		}},
		{name: "otp field missing", wantName: selOTP, mods: []func(*script){
			afterSubmit(pgTOTP),
			withPage(pgTOTP, fakePage{url: totpURL, visible: []string{selOTPForm, selOTPSubmit}}),
		}},
		{name: "no session cookie after login", noCookie: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.env.Credentials.OTP = refOTP
			cookies := []connector.Cookie{h.wwwCookie()}
			if tc.noCookie {
				cookies = nil
			}
			h.use(newScript(cookies, tc.mods...))

			sess, err := h.run(t.Context())
			if !errors.Is(err, connector.ErrBroken) {
				t.Fatalf("Login error = %v, want ErrBroken", err)
			}
			if errors.Is(err, connector.ErrAuthFailed) || errors.Is(err, connector.ErrNeedsLogin) {
				t.Errorf("Login error = %v also matches another state", err)
			}
			if sess != nil {
				t.Errorf("Login returned a session (%v) with an error", sess)
			}
			if tc.wantName != "" && !strings.Contains(err.Error(), tc.wantName) {
				t.Errorf("Login error = %q, want it to name the missing %s", err, tc.wantName)
			}
			b := h.browser(0)
			if tc.wantName == selUsername || tc.wantName == selPassword {
				if n := clicks(b.opList(), selSubmit); n != 0 {
					t.Errorf("submit clicked although %s was missing", tc.wantName)
				}
			}
			h.assertAllClosed()
			h.assertNoLeak(sess, err)
		})
	}
}

func TestLogin_SecretsNeverRendered(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		setup func(h *harness)
	}{
		{name: "password ok", setup: func(h *harness) {
			h.use(newScript([]connector.Cookie{h.wwwCookie()}))
		}},
		{name: "bad password", setup: func(h *harness) {
			h.use(newScript(nil, afterSubmit(pgBadCreds)))
		}},
		{name: "totp ok", setup: func(h *harness) {
			h.env.Credentials.OTP = refOTP
			h.use(newScript([]connector.Cookie{h.wwwCookie()}, afterSubmit(pgTOTP)))
		}},
		{name: "wrong totp", setup: func(h *harness) {
			h.env.Credentials.OTP = refOTP
			h.use(newScript(nil, afterSubmit(pgTOTP), func(s *script) {
				p := s.pages[pgTOTP]
				p.next = map[string]string{selOTPSubmit: pgTOTPErr}
				s.pages[pgTOTP] = p
			}))
		}},
		{name: "email code ok", setup: func(h *harness) {
			h.interactive(true)
			h.use(newScript([]connector.Cookie{h.wwwCookie()}, afterSubmit(pgEmail)))
		}},
		{name: "email code non-interactive", setup: func(h *harness) {
			h.use(newScript(nil, afterSubmit(pgEmail)))
		}},
		{name: "captcha visible", setup: func(h *harness) {
			h.interactive(true)
			v := newScript([]connector.Cookie{h.wwwCookie()}, entry(pgCaptcha))
			v.userDone = pgAccount
			h.use(newScript(nil, entry(pgCaptcha)), v)
		}},
		{name: "site changed", setup: func(h *harness) {
			h.use(newScript(nil, func(s *script) { delete(s.nav, loginURL) }))
		}},
		{name: "expired saved session", setup: func(h *harness) {
			h.env.Saved = h.savedBlob(canaryCookie(h.t))
			h.use(newScript([]connector.Cookie{h.wwwCookie()}))
		}},
		{name: "valid saved session", setup: func(h *harness) {
			h.env.Saved = h.savedBlob(h.cookie)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			tc.setup(h)
			saved := h.env.Saved

			sess, err := h.run(t.Context())
			// The scenario must really run (a stub failing early would leak
			// nothing and pass vacuously).
			wantOK := map[string]bool{
				"password ok": true, "totp ok": true, "email code ok": true,
				"captcha visible": true, "expired saved session": true, "valid saved session": true,
			}[tc.name]
			if wantOK != (err == nil) {
				t.Fatalf("Login error = %v, want success %v for this scenario", err, wantOK)
			}
			if !wantOK && !errors.Is(err, connector.ErrAuthFailed) && !errors.Is(err, connector.ErrNeedsLogin) && !errors.Is(err, connector.ErrBroken) {
				t.Errorf("Login error = %v, want a connector state sentinel", err)
			}
			h.assertNoLeak(sess, err, saved.Expose())
		})
	}
}

func TestLogin_BrowserAlwaysClosed(t *testing.T) {
	t.Parallel()
	errInjected := errors.New("synthetic browser failure")
	for _, tc := range []struct {
		name        string
		setup       func(h *harness, cancel context.CancelFunc)
		wantErr     bool
		wantIs      error // optional errors.Is target
		notBroken   bool  // the error must not match ErrBroken
		wantBrowser int   // launches expected
	}{
		{name: "success", wantBrowser: 1, setup: func(h *harness, _ context.CancelFunc) {
			h.use(newScript([]connector.Cookie{h.wwwCookie()}))
		}},
		{name: "navigate fails", wantErr: true, wantIs: errInjected, wantBrowser: 1, setup: func(h *harness, _ context.CancelFunc) {
			h.use(newScript(nil, func(s *script) { s.fail["navigate"] = errInjected }))
		}},
		{name: "typing fails", wantErr: true, wantBrowser: 1, setup: func(h *harness, _ context.CancelFunc) {
			h.use(newScript(nil, func(s *script) { s.fail["type"] = errInjected }))
		}},
		{name: "click fails", wantErr: true, wantBrowser: 1, setup: func(h *harness, _ context.CancelFunc) {
			h.use(newScript(nil, func(s *script) { s.fail["click"] = errInjected }))
		}},
		{name: "current url fails", wantErr: true, wantBrowser: 1, setup: func(h *harness, _ context.CancelFunc) {
			h.use(newScript(nil, func(s *script) { s.fail["url"] = errInjected }))
		}},
		{name: "cookies fail", wantErr: true, wantBrowser: 1, setup: func(h *harness, _ context.CancelFunc) {
			h.use(newScript(nil, func(s *script) { s.fail["cookies"] = errInjected }))
		}},
		{
			name: "context cancelled mid-flow", wantErr: true, wantIs: context.Canceled, notBroken: true, wantBrowser: 1,
			setup: func(h *harness, cancel context.CancelFunc) {
				h.use(newScript(nil, func(s *script) {
					s.onOp = func(kind, sel string) {
						if kind == "click" && sel == selSubmit {
							cancel()
						}
					}
				}))
			},
		},
		{name: "bad password", wantErr: true, wantIs: connector.ErrAuthFailed, wantBrowser: 1, setup: func(h *harness, _ context.CancelFunc) {
			h.use(newScript(nil, afterSubmit(pgBadCreds)))
		}},
		{name: "email code non-interactive", wantErr: true, wantIs: connector.ErrNeedsLogin, wantBrowser: 1, setup: func(h *harness, _ context.CancelFunc) {
			h.use(newScript(nil, afterSubmit(pgEmail)))
		}},
		{name: "captcha interactive", wantBrowser: 2, setup: func(h *harness, _ context.CancelFunc) {
			h.interactive(true)
			v := newScript([]connector.Cookie{h.wwwCookie()}, entry(pgCaptcha))
			v.userDone = pgAccount
			h.use(newScript(nil, entry(pgCaptcha)), v)
		}},
		{name: "visible relaunch fails", wantErr: true, wantBrowser: 1, setup: func(h *harness, _ context.CancelFunc) {
			h.interactive(true)
			h.use(newScript(nil, entry(pgCaptcha))) // second Launch has no script: fails
		}},
		{name: "launch fails", wantErr: true, wantIs: errInjected, notBroken: true, wantBrowser: 0, setup: func(h *harness, _ context.CancelFunc) {
			h.pool.launchErr = errInjected
		}},
		{name: "no browser pool", wantErr: true, wantBrowser: 0, setup: func(h *harness, _ context.CancelFunc) {
			h.env.Browser = nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			tc.setup(h, cancel)

			sess, err := h.run(ctx)
			if tc.wantErr != (err != nil) {
				t.Fatalf("Login error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("Login error = %v, want errors.Is %v", err, tc.wantIs)
			}
			if tc.notBroken && errors.Is(err, connector.ErrBroken) {
				t.Errorf("Login error = %v must not be classified as a site change", err)
			}
			if err != nil && sess != nil {
				t.Errorf("Login returned a session with an error")
			}
			if n := len(h.pool.launched()); n != tc.wantBrowser {
				t.Errorf("%d browsers launched, want %d", n, tc.wantBrowser)
			}
			h.assertAllClosed()
			h.assertNoLeak(sess, err)
		})
	}
}
