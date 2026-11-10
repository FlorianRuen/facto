package wecasa

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
	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/secret"
)

// Login pages and selectors (docs/connectors/wecasa.md "Login").
const (
	pathLogin   = "/customer-area/login"
	pathAccount = "/customer-area"
	loginURL    = "https://" + Host + pathLogin

	selForm     = "#new_user"
	selEmail    = "#user_email"
	selPassword = "#user_password"
	selSubmit   = "input[name=commit]"
	selLogout   = `a[href="/customer-area/logout"]`
)

// selChallenge matches the Cloudflare challenge page markers (served at
// the requested URL in place of the page). Never automated.
var selChallenge = strings.Join([]string{
	"#challenge-stage", "#challenge-form", "#challenge-running",
	"#cf-challenge-running", ".cf-turnstile", `iframe[src*="challenges.cloudflare.com"]`,
}, ", ")

// Selector lists waited on before classifying a page by its URL.
var (
	waitEntry       = selForm + ", " + selLogout + ", " + selChallenge // the login URL (or an open session)
	waitAfterSubmit = selLogout + ", " + selChallenge                  // after the form is sent
)

// probeTimeout bounds a check of an element on an already loaded page.
const probeTimeout = 2 * time.Second

// maxPathInError caps the supplier path an error message quotes.
const maxPathInError = 64

// page is a classified login-flow page.
type page int

const (
	pageAccount page = iota + 1 // /customer-area with the logout link
	pageLogin                   // the login form
	pageManual                  // a challenge or an unknown page: the user's job
)

// Login opens a session. A saved session (Env.Saved) that still passes
// Probe is reused without any browser nor secret. Otherwise the login and
// password references are resolved, then a headless browser restricted to
// Info().AllowedDomains and Info().BrowserStatic fills the login form. A
// challenge or an unknown page is never automated: an interactive run
// relaunches a visible browser for the user, a non-interactive one fails
// with connector.ErrNeedsLogin. Once logged in, the www.wecasa.fr cookies
// go into env.HTTP's jar and the API token is read from the bookings page.
// Every launched browser is closed before Login returns.
func (c *Connector) Login(ctx context.Context, env connector.Env) (connector.Session, error) {
	if env.HTTP == nil {
		return nil, errors.New("wecasa: login: no http client")
	}
	log := env.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if !env.Saved.IsZero() {
		sess, err := c.restore(ctx, env)
		if err == nil {
			log.DebugContext(ctx, "wecasa: saved session reused")
			return sess, nil
		}
		if !errors.Is(err, connector.ErrNeedsLogin) || ctx.Err() != nil {
			return nil, err
		}
		log.InfoContext(ctx, "wecasa: saved session no longer valid, logging in")
		// Restore injected the stale cookies into env.HTTP's jar: drop them
		// so the new session carries only what the browser login yields.
		if err := clearJar(env.HTTP); err != nil {
			return nil, err
		}
	}
	if env.Browser == nil {
		return nil, errors.New("wecasa: login: no browser pool")
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
		// Never a typed nil *Session inside a non-nil connector.Session.
		return nil, err
	}
	return sess, nil
}

// restore rebuilds env.Saved into env.HTTP's jar and probes it.
func (c *Connector) restore(ctx context.Context, env connector.Env) (*Session, error) {
	sess, err := Restore(env.HTTP, env.Saved)
	if err != nil {
		return nil, fmt.Errorf("wecasa: login: %w", err)
	}
	if err := c.Probe(ctx, sess); err != nil {
		return nil, fmt.Errorf("wecasa: login: saved session: %w", err)
	}
	return sess, nil
}

// resolve resolves one credential reference. Errors name the field, never
// the reference nor a value.
func resolve(ctx context.Context, r connector.SecretResolver, field, ref string) (secret.Secret, error) {
	if ref == "" {
		return secret.Secret{}, fmt.Errorf("wecasa: login: no %s reference configured", field)
	}
	if r == nil {
		return secret.Secret{}, errors.New("wecasa: login: no secret resolver")
	}
	s, err := r.Resolve(ctx, ref)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("wecasa: login: resolve %s: %w", field, err)
	}
	if s.IsZero() {
		return secret.Secret{}, fmt.Errorf("wecasa: login: %s reference resolved to an empty value", field)
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

// launch opens a browser restricted to the connector's allowlists.
func (f *flow) launch(ctx context.Context, visible bool) error {
	info := f.c.Info()
	b, err := f.env.Browser.Launch(ctx, connector.LaunchOptions{
		AllowedDomains: info.AllowedDomains,
		Static:         info.BrowserStatic,
		Visible:        visible,
	})
	if err != nil {
		if b != nil {
			// A pool may hand back a half-started browser with its error.
			f.b = b
			f.close()
		}
		return fmt.Errorf("wecasa: login: launch browser: %w", err)
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
		f.log.Warn("wecasa: close browser", slog.String("error", logx.Clean(err.Error())))
	}
}

// run drives the headless browser from the login URL to the customer area.
func (f *flow) run(ctx context.Context, user, pw secret.Secret) (*Session, error) {
	if err := f.launch(ctx, false); err != nil {
		return nil, err
	}
	if err := f.navigate(ctx); err != nil {
		return nil, err
	}
	p, err := f.pageAfter(ctx, waitEntry, selForm)
	if err != nil {
		return nil, err
	}
	switch p {
	case pageAccount:
		return f.session(ctx)
	case pageManual:
		return f.manual(ctx)
	case pageLogin:
	}
	for _, step := range []struct {
		sel string
		val secret.Secret
	}{{selEmail, user}, {selPassword, pw}} {
		if err := f.typeSecret(ctx, step.sel, step.val); err != nil {
			return nil, err
		}
	}
	// Clicking submits the form with the Rails CSRF field the page filled.
	if err := f.click(ctx, selSubmit); err != nil {
		return nil, err
	}
	// The form stays on screen until the browser navigates: wait for the
	// logout link or a challenge, classify only when neither comes.
	p, err = f.pageAfter(ctx, waitAfterSubmit, selForm)
	if err != nil {
		return nil, err
	}
	switch p {
	case pageAccount:
		return f.session(ctx)
	case pageLogin:
		return nil, fmt.Errorf("%w: wecasa: login: the site rejected the credentials", connector.ErrAuthFailed)
	case pageManual:
	}
	return f.manual(ctx)
}

// pageAfter waits for sel (bounded by StepTimeout), then classifies the
// page by its URL:
//   - the customer area with the logout link: pageAccount; without it:
//     ErrBroken naming the link;
//   - the login URL showing a challenge (even inside the form): pageManual;
//     the form alone: pageLogin;
//     neither: ErrBroken naming missing;
//   - any other page of the site: pageManual.
//
// A cancelled run context is returned as such, never ErrBroken.
func (f *flow) pageAfter(ctx context.Context, sel, missing string) (page, error) {
	sctx, cancel := context.WithTimeout(ctx, f.c.opts.StepTimeout)
	waitErr := f.b.WaitVisible(sctx, sel)
	cancel()
	if cerr := ctx.Err(); cerr != nil {
		return 0, fmt.Errorf("wecasa: login: wait for the page: %w", cerr)
	}
	path, err := f.classify(ctx)
	if err != nil {
		return 0, err
	}
	switch path {
	case pathAccount:
		if waitErr == nil || f.visibleNow(ctx, selLogout) {
			return pageAccount, nil
		}
		return 0, stepError(ctx, "wait for "+selLogout, errNotShown)
	case pathLogin:
		// A challenge first: a managed challenge can sit inside the form,
		// and a failed one shows the form again (not a wrong password).
		if f.visibleNow(ctx, selChallenge) {
			return pageManual, nil
		}
		if f.visibleNow(ctx, selForm) {
			return pageLogin, nil
		}
		return 0, stepError(ctx, "wait for "+missing, errNotShown)
	}
	return pageManual, nil
}

// errNotShown is the cause of a known page lacking an element.
var errNotShown = errors.New("element not shown")

// visibleNow reports whether sel is visible on the loaded page, polling
// for at most probeTimeout.
func (f *flow) visibleNow(ctx context.Context, sel string) bool {
	sctx, cancel := context.WithTimeout(ctx, min(probeTimeout, f.c.opts.StepTimeout))
	defer cancel()
	return f.b.WaitVisible(sctx, sel) == nil
}

// manual never automates a challenge or an unknown page.
// Non-interactive: ErrNeedsLogin. Interactive: the headless browser is
// closed, a visible one (same allowlists) opens the login URL and the user
// completes the whole login by hand within UserTimeout; the connector
// types and clicks nothing.
func (f *flow) manual(ctx context.Context) (*Session, error) {
	if !f.env.Interactive {
		return nil, fmt.Errorf("%w: wecasa: login: the site shows a challenge or an unexpected page, an interactive login is needed", connector.ErrNeedsLogin)
	}
	f.close()
	if err := f.launch(ctx, true); err != nil {
		return nil, err
	}
	if err := f.navigate(ctx); err != nil {
		return nil, err
	}
	f.log.InfoContext(ctx, "wecasa: complete the login in the browser window")
	wctx, cancel := context.WithTimeout(ctx, f.c.opts.UserTimeout)
	defer cancel()
	if err := f.b.WaitVisible(wctx, selLogout); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, fmt.Errorf("wecasa: login: wait for the user: %w", cerr)
		}
		return nil, fmt.Errorf("%w: wecasa: login: the login was not completed in the browser window within %s", connector.ErrNeedsLogin, f.c.opts.UserTimeout)
	}
	path, err := f.classify(ctx)
	if err != nil {
		return nil, err
	}
	if path != pathAccount {
		return nil, fmt.Errorf("%w: wecasa: login: unexpected page after the manual login", connector.ErrBroken)
	}
	return f.session(ctx)
}

// session exports the www.wecasa.fr cookies into env.HTTP's jar and reads
// the API token over httpx.
func (f *flow) session(ctx context.Context) (*Session, error) {
	sctx, cancel := context.WithTimeout(ctx, f.c.opts.StepTimeout)
	defer cancel()
	cookies, err := f.b.Cookies(sctx, f.c.Info().AllowedDomains)
	if err != nil {
		return nil, opError(ctx, "read cookies", err)
	}
	has := false
	for _, ck := range cookies {
		if isHost(ck.Domain) {
			has = true
			break
		}
	}
	if !has {
		return nil, fmt.Errorf("%w: wecasa: login: no session cookie for %s", connector.ErrBroken, Host)
	}
	if err := injectCookies(f.env.HTTP, cookies); err != nil {
		return nil, fmt.Errorf("%w: wecasa: login: %w", connector.ErrBroken, err)
	}
	tok, err := readToken(ctx, f.env.HTTP)
	if err != nil {
		return nil, fmt.Errorf("wecasa: login: read the api token: %w", err)
	}
	f.log.InfoContext(ctx, "wecasa: logged in")
	return &Session{hc: f.env.HTTP, token: tok}, nil
}

// navigate opens the login URL, the only URL the connector navigates to.
func (f *flow) navigate(ctx context.Context) error {
	sctx, cancel := context.WithTimeout(ctx, f.c.opts.StepTimeout)
	defer cancel()
	if err := f.b.Navigate(sctx, loginURL); err != nil {
		return opError(ctx, "open "+pathLogin, err)
	}
	return nil
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

// classify returns the path of the current page, trailing slash dropped.
// A non-https URL, a port other than 443 or a host other than
// www.wecasa.fr wraps connector.ErrBroken. Errors never carry the query.
func (f *flow) classify(ctx context.Context) (string, error) {
	sctx, cancel := context.WithTimeout(ctx, f.c.opts.StepTimeout)
	defer cancel()
	raw, err := f.b.CurrentURL(sctx)
	if err != nil {
		return "", opError(ctx, "read the current url", err)
	}
	return classifyURL(raw)
}

// classifyURL is the pure part of classify.
func classifyURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: wecasa: login: unparsable page url", connector.ErrBroken)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("%w: wecasa: login: landed on a non-https page", connector.ErrBroken)
	}
	if p := u.Port(); p != "" && p != "443" {
		return "", fmt.Errorf("%w: wecasa: login: landed on an unexpected port", connector.ErrBroken)
	}
	if !strings.EqualFold(u.Hostname(), Host) {
		return "", fmt.Errorf("%w: wecasa: login: landed on a host outside the allowlist", connector.ErrBroken)
	}
	path := strings.TrimSuffix(u.Path, "/")
	switch path {
	case pathLogin, pathAccount:
		return path, nil
	}
	return quotePath(u), nil
}

// quotePath renders u's path for an error or a log: percent-escaped,
// cleaned of token-like content, capped on a rune boundary. Never the
// query.
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
		return fmt.Errorf("wecasa: login: %s: %w", step, cerr)
	}
	// The browser error is rendered, not wrapped: a step timeout carries
	// context.DeadlineExceeded, which must not read as the run's deadline.
	return fmt.Errorf("%w: wecasa: login: %s: %s", connector.ErrBroken, step, logx.Clean(err.Error()))
}

// opError wraps a navigate, url or cookies failure, unclassified unless
// the run's context ended.
func opError(ctx context.Context, op string, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("wecasa: login: %s: %w", op, cerr)
	}
	return fmt.Errorf("wecasa: login: %s: %w", op, err)
}
