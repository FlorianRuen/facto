package fakeprovider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/secret"
)

// Login flow contract (docs/connectors/fakeprovider.md "Login flow").
const (
	loginURL = "https://" + HostWWW + "/login"

	pathAccount = "/account"
	pathLogin   = "/login"
	pathTOTP    = "/login/totp"
	pathEmail   = "/login/email"
	pathCaptcha = "/login/captcha"

	selLoginForm  = "#login-form"
	selUsername   = "#username"
	selPassword   = "#password"
	selSubmit     = "#login-submit"
	selLoginError = "#login-error"
	selOTP        = "#otp"
	selOTPSubmit  = "#otp-submit"
	selOTPError   = "#otp-error"
	selEmailCode  = "#email-code"
	selEmailSub   = "#email-code-submit"
	selEmailError = "#email-code-error"
	selCaptcha    = "#captcha"
	selAccount    = "#account"
)

// Selector lists waited on before classifying a page with CurrentURL.
var (
	waitEntry       = strings.Join([]string{selLoginForm, selCaptcha}, ", ")
	waitAfterSubmit = strings.Join([]string{selAccount, selLoginError, selOTP, selEmailCode, selCaptcha}, ", ")
	waitAfterOTP    = strings.Join([]string{selAccount, selOTPError, selCaptcha}, ", ")
	waitAfterEmail  = strings.Join([]string{selAccount, selEmailError, selCaptcha}, ", ")
)

// page is a classified login-flow page.
type page int

const (
	pageAccount page = iota + 1
	pageLogin
	pageTOTP
	pageEmail
	pageCaptcha
)

// maxPathInError caps the supplier path an ErrBroken message quotes.
const maxPathInError = 64

// Prompt labels, written by the connector (never taken from the site).
const (
	labelTOTP  = "Fake Provider: authenticator app code"
	labelEmail = "Fake Provider: code sent by email"
)

// Login opens a session. A saved session (Env.Saved) that still passes
// Probe is reused without any browser nor secret. Otherwise the login and
// password references are resolved, then a headless browser restricted to
// Info().AllowedDomains walks the login pages (docs/connectors/fakeprovider.md
// "Login flow"). Captcha pages are never automated: an interactive run
// relaunches a visible browser for the user, a non-interactive one fails
// with connector.ErrNeedsLogin. Every launched browser is closed before
// Login returns.
func (c *Connector) Login(ctx context.Context, env connector.Env) (connector.Session, error) {
	if env.HTTP == nil {
		return nil, errors.New("fakeprovider: login: no http client")
	}
	log := env.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if !env.Saved.IsZero() {
		sess, err := c.restore(ctx, env)
		if err == nil {
			log.DebugContext(ctx, "fakeprovider: saved session reused")
			return sess, nil
		}
		if !errors.Is(err, connector.ErrNeedsLogin) || ctx.Err() != nil {
			return nil, err
		}
		log.InfoContext(ctx, "fakeprovider: saved session no longer valid, logging in")
		// Restore injected the stale cookies into env.HTTP's jar: drop them
		// so the new session carries only what the browser login yields.
		if err := clearJar(env.HTTP); err != nil {
			return nil, err
		}
	}
	if env.Browser == nil {
		return nil, errors.New("fakeprovider: login: no browser pool")
	}
	user, err := resolve(ctx, env.Secrets, "login", env.Credentials.Login)
	if err != nil {
		return nil, err
	}
	defer user.Wipe()
	pw, err := resolve(ctx, env.Secrets, "password", env.Credentials.Password)
	if err != nil {
		return nil, err
	}
	defer pw.Wipe()

	f := &flow{c: c, env: env, log: log}
	defer f.close()
	sess, err := f.run(ctx, user, pw)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// restore rebuilds env.Saved into env.HTTP's jar and probes it.
func (c *Connector) restore(ctx context.Context, env connector.Env) (*Session, error) {
	sess, err := Restore(env.HTTP, env.Saved)
	if err != nil {
		return nil, fmt.Errorf("fakeprovider: login: %w", err)
	}
	if err := c.Probe(ctx, sess); err != nil {
		return nil, fmt.Errorf("fakeprovider: login: saved session: %w", err)
	}
	return sess, nil
}

// clearJar deletes every cookie hc's jar holds for the allowlisted hosts.
// Restore only injects cookies scoped to "/", which Cookies lists; a cookie
// set again with an Expires in the past is deleted by the jar.
func clearJar(hc *httpx.Client) error {
	for _, host := range allowedHosts() {
		cs, err := hc.Cookies(host)
		if err != nil {
			return fmt.Errorf("fakeprovider: login: clear saved cookies: %w", err)
		}
		if len(cs) == 0 {
			continue
		}
		del := make([]httpx.Cookie, 0, len(cs))
		for _, c := range cs {
			del = append(del, httpx.Cookie{Name: c.Name, Value: "deleted", Path: "/", Expires: time.Unix(1, 0).UTC()})
		}
		if err := hc.SetCookies(host, del); err != nil {
			return fmt.Errorf("fakeprovider: login: clear saved cookies: %w", err)
		}
	}
	return nil
}

// resolve resolves one credential reference. Errors name the field, never
// the reference nor a value.
func resolve(ctx context.Context, r connector.SecretResolver, field, ref string) (secret.Secret, error) {
	if ref == "" {
		return secret.Secret{}, fmt.Errorf("fakeprovider: login: no %s reference configured", field)
	}
	if r == nil {
		return secret.Secret{}, errors.New("fakeprovider: login: no secret resolver")
	}
	s, err := r.Resolve(ctx, ref)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("fakeprovider: login: resolve %s: %w", field, err)
	}
	if s.IsZero() {
		return secret.Secret{}, fmt.Errorf("fakeprovider: login: %s reference resolved to an empty value", field)
	}
	return s, nil
}

// flow is one browser login. It owns at most one open browser at a time.
type flow struct {
	c   *Connector
	env connector.Env
	log *slog.Logger
	b   connector.Browser
}

// launch opens a browser restricted to Info().AllowedDomains.
func (f *flow) launch(ctx context.Context, visible bool) error {
	b, err := f.env.Browser.Launch(ctx, connector.LaunchOptions{
		AllowedDomains: f.c.Info().AllowedDomains,
		Visible:        visible,
	})
	if err != nil {
		if b != nil {
			// A pool may hand back a half-started browser with its error.
			f.b = b
			f.close()
		}
		return fmt.Errorf("fakeprovider: login: launch browser: %w", err)
	}
	f.b = b
	return nil
}

// close closes the open browser, if any, exactly once.
func (f *flow) close() {
	if f.b == nil {
		return
	}
	b := f.b
	f.b = nil
	if err := b.Close(); err != nil {
		f.log.Warn("fakeprovider: close browser", slog.String("error", logx.Clean(err.Error())))
	}
}

// run drives the headless browser from the login URL to the account page.
func (f *flow) run(ctx context.Context, user, pw secret.Secret) (*Session, error) {
	if err := f.launch(ctx, false); err != nil {
		return nil, err
	}
	if err := f.navigate(ctx); err != nil {
		return nil, err
	}
	p, err := f.waitPage(ctx, waitEntry)
	if err != nil {
		return nil, err
	}
	if p == pageCaptcha {
		return f.captcha(ctx)
	}
	if p != pageLogin {
		return nil, fmt.Errorf("%w: fakeprovider: login: %s did not show the login form", connector.ErrBroken, pathLogin)
	}

	for _, step := range []struct {
		sel string
		val secret.Secret
	}{{selUsername, user}, {selPassword, pw}} {
		if err := f.typeSecret(ctx, step.sel, step.val); err != nil {
			return nil, err
		}
	}
	if err := f.click(ctx, selSubmit); err != nil {
		return nil, err
	}
	p, err = f.waitPage(ctx, waitAfterSubmit)
	if err != nil {
		return nil, err
	}
	switch p {
	case pageAccount:
		return f.session(ctx)
	case pageLogin:
		return nil, fmt.Errorf("%w: fakeprovider: login: the site rejected the credentials", connector.ErrAuthFailed)
	case pageTOTP:
		return f.totp(ctx)
	case pageEmail:
		return f.email(ctx)
	case pageCaptcha:
		return f.captcha(ctx)
	}
	return nil, fmt.Errorf("%w: fakeprovider: login: unexpected page after submit", connector.ErrBroken)
}

// totp types an authenticator code: the otp reference (a code, never a
// seed: plan J1 A5), resolved only now since codes are time-bound, else a
// prompt when interactive.
func (f *flow) totp(ctx context.Context) (*Session, error) {
	var code secret.Secret
	switch {
	case f.env.Credentials.OTP != "":
		s, err := resolve(ctx, f.env.Secrets, "otp", f.env.Credentials.OTP)
		if err != nil {
			return nil, err
		}
		code = s
	case f.env.Interactive:
		s, err := f.prompt(ctx, labelTOTP)
		if err != nil {
			return nil, err
		}
		code = s
	default:
		return nil, fmt.Errorf("%w: fakeprovider: login: the site asks for an authenticator code and no otp reference is configured", connector.ErrNeedsLogin)
	}
	defer code.Wipe()
	return f.submitCode(ctx, selOTP, selOTPSubmit, code, waitAfterOTP, pageTOTP)
}

// email types the code the site emailed: only an interactive user has it.
// The otp reference is never used here.
func (f *flow) email(ctx context.Context) (*Session, error) {
	if !f.env.Interactive {
		return nil, fmt.Errorf("%w: fakeprovider: login: the site emailed a code, an interactive login is needed", connector.ErrNeedsLogin)
	}
	code, err := f.prompt(ctx, labelEmail)
	if err != nil {
		return nil, err
	}
	defer code.Wipe()
	return f.submitCode(ctx, selEmailCode, selEmailSub, code, waitAfterEmail, pageEmail)
}

// prompt asks the user once for a code.
func (f *flow) prompt(ctx context.Context, label string) (secret.Secret, error) {
	if f.env.Prompt == nil {
		return secret.Secret{}, fmt.Errorf("%w: fakeprovider: login: no prompter to ask for a code", connector.ErrNeedsLogin)
	}
	s, err := f.env.Prompt.Prompt(ctx, connector.PromptRequest{Label: label})
	if err != nil {
		return secret.Secret{}, fmt.Errorf("fakeprovider: login: prompt: %w", err)
	}
	if s.IsZero() {
		return secret.Secret{}, fmt.Errorf("%w: fakeprovider: login: empty code", connector.ErrNeedsLogin)
	}
	return s, nil
}

// submitCode types code into field, clicks submit and classifies the next
// page: the account page succeeds, the same code page again means the code
// was rejected.
func (f *flow) submitCode(ctx context.Context, field, submit string, code secret.Secret, wait string, again page) (*Session, error) {
	if err := f.typeSecret(ctx, field, code); err != nil {
		return nil, err
	}
	if err := f.click(ctx, submit); err != nil {
		return nil, err
	}
	p, err := f.waitPage(ctx, wait)
	if err != nil {
		return nil, err
	}
	switch p {
	case pageAccount:
		return f.session(ctx)
	case again:
		return nil, fmt.Errorf("%w: fakeprovider: login: the site rejected the code", connector.ErrAuthFailed)
	case pageCaptcha:
		return f.captcha(ctx)
	case pageLogin, pageTOTP, pageEmail:
	}
	return nil, fmt.Errorf("%w: fakeprovider: login: unexpected page after the code", connector.ErrBroken)
}

// captcha never automates the captcha. Non-interactive: ErrNeedsLogin.
// Interactive: the headless browser is closed, a visible one (same
// allowlist) opens the login URL and the user completes the whole login by
// hand within UserTimeout; the connector types and clicks nothing.
func (f *flow) captcha(ctx context.Context) (*Session, error) {
	if !f.env.Interactive {
		return nil, fmt.Errorf("%w: fakeprovider: login: the site shows a captcha, an interactive login is needed", connector.ErrNeedsLogin)
	}
	f.close()
	if err := f.launch(ctx, true); err != nil {
		return nil, err
	}
	if err := f.navigate(ctx); err != nil {
		return nil, err
	}
	f.log.InfoContext(ctx, "fakeprovider: captcha shown, complete the login in the browser window")
	wctx, cancel := context.WithTimeout(ctx, f.c.opts.UserTimeout)
	defer cancel()
	if err := f.b.WaitVisible(wctx, selAccount); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, fmt.Errorf("fakeprovider: login: wait for the user: %w", cerr)
		}
		return nil, fmt.Errorf("%w: fakeprovider: login: the login was not completed in the browser window within %s", connector.ErrNeedsLogin, f.c.opts.UserTimeout)
	}
	p, err := f.classify(ctx)
	if err != nil {
		return nil, err
	}
	if p != pageAccount {
		return nil, fmt.Errorf("%w: fakeprovider: login: unexpected page after the manual login", connector.ErrBroken)
	}
	return f.session(ctx)
}

// session exports the allowlisted cookies into env.HTTP's jar.
func (f *flow) session(ctx context.Context) (*Session, error) {
	sctx, cancel := context.WithTimeout(ctx, f.c.opts.StepTimeout)
	defer cancel()
	cookies, err := f.b.Cookies(sctx, f.c.Info().AllowedDomains)
	if err != nil {
		return nil, opError(ctx, "read cookies", err)
	}
	hasWWW := false
	for _, ck := range cookies {
		if h, ok := allowedHost(ck.Domain); ok && h == HostWWW {
			hasWWW = true
			break
		}
	}
	if !hasWWW {
		return nil, fmt.Errorf("%w: fakeprovider: login: no session cookie for %s", connector.ErrBroken, HostWWW)
	}
	sess, err := NewSession(f.env.HTTP, cookies)
	if err != nil {
		return nil, fmt.Errorf("%w: fakeprovider: login: %w", connector.ErrBroken, err)
	}
	f.log.InfoContext(ctx, "fakeprovider: logged in")
	return sess, nil
}

// navigate opens the login URL, the only URL the connector ever navigates
// to: the site redirects to the SSO host by itself.
func (f *flow) navigate(ctx context.Context) error {
	sctx, cancel := context.WithTimeout(ctx, f.c.opts.StepTimeout)
	defer cancel()
	if err := f.b.Navigate(sctx, loginURL); err != nil {
		return opError(ctx, "open "+pathLogin, err)
	}
	return nil
}

// waitPage waits for any selector of the list sel, then classifies the
// page by its URL.
func (f *flow) waitPage(ctx context.Context, sel string) (page, error) {
	sctx, cancel := context.WithTimeout(ctx, f.c.opts.StepTimeout)
	defer cancel()
	if err := f.b.WaitVisible(sctx, sel); err != nil {
		return 0, stepError(ctx, "wait for "+sel, err)
	}
	return f.classify(ctx)
}

func (f *flow) typeSecret(ctx context.Context, sel string, v secret.Secret) error {
	sctx, cancel := context.WithTimeout(ctx, f.c.opts.StepTimeout)
	defer cancel()
	if err := f.b.TypeSecret(sctx, sel, v); err != nil {
		return stepError(ctx, "type into "+sel, err)
	}
	return nil
}

func (f *flow) click(ctx context.Context, sel string) error {
	sctx, cancel := context.WithTimeout(ctx, f.c.opts.StepTimeout)
	defer cancel()
	if err := f.b.Click(sctx, sel); err != nil {
		return stepError(ctx, "click "+sel, err)
	}
	return nil
}

// classify maps the current URL to a page. A non-https URL, a host outside
// the allowlist or an unknown path wraps connector.ErrBroken. Errors never
// carry the query.
func (f *flow) classify(ctx context.Context) (page, error) {
	sctx, cancel := context.WithTimeout(ctx, f.c.opts.StepTimeout)
	defer cancel()
	raw, err := f.b.CurrentURL(sctx)
	if err != nil {
		return 0, opError(ctx, "read the current url", err)
	}
	return classifyURL(raw)
}

// classifyURL is the pure part of classify.
func classifyURL(raw string) (page, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: fakeprovider: login: unparsable page url", connector.ErrBroken)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return 0, fmt.Errorf("%w: fakeprovider: login: landed on a non-https page", connector.ErrBroken)
	}
	if p := u.Port(); p != "" && p != "443" {
		return 0, fmt.Errorf("%w: fakeprovider: login: landed on an unexpected port", connector.ErrBroken)
	}
	host, ok := allowedHost(u.Hostname())
	if !ok || strings.HasPrefix(u.Hostname(), ".") {
		return 0, fmt.Errorf("%w: fakeprovider: login: landed on a host outside the allowlist", connector.ErrBroken)
	}
	path := strings.TrimSuffix(u.Path, "/")
	switch {
	case path == pathLogin:
		return pageLogin, nil
	case host != HostWWW:
	case path == pathAccount:
		return pageAccount, nil
	case path == pathTOTP:
		return pageTOTP, nil
	case path == pathEmail:
		return pageEmail, nil
	case path == pathCaptcha:
		return pageCaptcha, nil
	}
	return 0, fmt.Errorf("%w: fakeprovider: login: unexpected page %s%s", connector.ErrBroken, host, quotePath(u))
}

// quotePath renders u's path for an error message: percent-escaped (no raw
// control byte or line break), cleaned of token-like content, capped on a
// rune boundary. Never the query.
func quotePath(u *url.URL) string {
	p := logx.Clean(u.EscapedPath())
	if len(p) <= maxPathInError {
		return p
	}
	cut := maxPathInError
	for cut > 0 && !utf8.RuneStart(p[cut]) {
		cut--
	}
	return p[:cut] + "..."
}

// stepError classifies a wait, type or click failure: the run's context
// ended → that context error (never ErrBroken); otherwise the page lacks
// what the step needs → ErrBroken naming the step and its selector.
func stepError(ctx context.Context, step string, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("fakeprovider: login: %s: %w", step, cerr)
	}
	// The browser error is rendered, not wrapped: a step timeout carries
	// context.DeadlineExceeded, which must not read as the run's deadline.
	return fmt.Errorf("%w: fakeprovider: login: %s: %s", connector.ErrBroken, step, logx.Clean(err.Error()))
}

// opError wraps a navigate, url or cookies failure, unclassified unless
// the run's context ended.
func opError(ctx context.Context, op string, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("fakeprovider: login: %s: %w", op, cerr)
	}
	return fmt.Errorf("fakeprovider: login: %s: %w", op, err)
}
