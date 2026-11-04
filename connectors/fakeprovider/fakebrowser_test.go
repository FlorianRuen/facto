package fakeprovider_test

// Scripted test doubles for plan J1 T21: a connector.BrowserPool handing out
// fake connector.Browser values that walk a small page graph (no real
// browser, no CDP), a SecretResolver and a Prompter. Every call is recorded
// in one ordered event log shared by all doubles, so tests can assert
// ordering (credentials resolved before launch, headless browser closed
// before the visible relaunch, OTP resolved only after the password step).
//
// The page graph models the fake site contract written down in
// docs/connectors/fakeprovider.md "Login flow"; the e2e fake site (T22)
// serves the same URLs and selectors.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/secret"
)

// Login flow contract (docs/connectors/fakeprovider.md "Login flow").
const (
	loginURL    = "https://www.fakeprovider.test/login"
	ssoLoginURL = "https://sso.fakeprovider.test/login"
	accountURL  = "https://www.fakeprovider.test/account"
	totpURL     = "https://www.fakeprovider.test/login/totp"
	emailURL    = "https://www.fakeprovider.test/login/email"
	captchaURL  = "https://www.fakeprovider.test/login/captcha"

	selLoginForm  = "#login-form"
	selUsername   = "#username"
	selPassword   = "#password"
	selSubmit     = "#login-submit"
	selCSRF       = "input[name=csrf_token]" // hidden: never visible, never typed into
	selLoginError = "#login-error"
	selOTPForm    = "#otp-form"
	selOTP        = "#otp"
	selOTPSubmit  = "#otp-submit"
	selOTPError   = "#otp-error"
	selEmailForm  = "#email-code-form"
	selEmailCode  = "#email-code"
	selEmailSub   = "#email-code-submit"
	selCaptcha    = "#captcha"
	selAccount    = "#account"
)

// Page keys of the default graph.
const (
	pgLogin    = "login"
	pgSSOLogin = "sso-login"
	pgAccount  = "account"
	pgBadCreds = "bad-credentials"
	pgTOTP     = "totp"
	pgTOTPErr  = "totp-error"
	pgEmail    = "email"
	pgCaptcha  = "captcha"
)

// errFakeNotVisible mirrors internal/browser: a wait that never sees the
// element ends with the context deadline. It names no selector, so tests
// prove the connector names the missing piece itself.
var errFakeNotVisible = fmt.Errorf("fake browser: element not visible: %w", context.DeadlineExceeded)

// fakePage is one page of the scripted site.
type fakePage struct {
	url     string
	visible []string          // selectors present and visible
	next    map[string]string // Click(selector) -> next page key
}

// script drives one launched browser.
type script struct {
	pages map[string]fakePage
	nav   map[string]string // Navigate(url) -> page key (models server redirects)
	// userDone: in a visible browser, a WaitVisible that does not match
	// moves to this page first (the user completed the login by hand).
	userDone string
	cookies  []connector.Cookie
	// fail injects an error for an operation kind: "navigate", "wait",
	// "type", "click", "url", "cookies".
	fail map[string]error
	// onOp runs at the start of every operation (e.g. to cancel ctx).
	onOp func(kind, sel string)
}

// defaultPages is the full page graph; a script edits its own copy.
func defaultPages() map[string]fakePage {
	login := []string{selLoginForm, selUsername, selPassword, selSubmit}
	return map[string]fakePage{
		pgLogin:    {url: loginURL, visible: login, next: map[string]string{selSubmit: pgAccount}},
		pgSSOLogin: {url: ssoLoginURL, visible: login, next: map[string]string{selSubmit: pgAccount}},
		pgAccount:  {url: accountURL, visible: []string{selAccount}},
		pgBadCreds: {url: loginURL, visible: append(slices.Clone(login), selLoginError), next: map[string]string{selSubmit: pgBadCreds}},
		pgTOTP:     {url: totpURL, visible: []string{selOTPForm, selOTP, selOTPSubmit}, next: map[string]string{selOTPSubmit: pgAccount}},
		pgTOTPErr:  {url: totpURL, visible: []string{selOTPForm, selOTP, selOTPSubmit, selOTPError}, next: map[string]string{selOTPSubmit: pgTOTPErr}},
		pgEmail:    {url: emailURL, visible: []string{selEmailForm, selEmailCode, selEmailSub}, next: map[string]string{selEmailSub: pgAccount}},
		pgCaptcha:  {url: captchaURL, visible: []string{selCaptcha}},
	}
}

// newScript returns the password flow (login -> account) handing out
// cookies; mods edit it.
func newScript(cookies []connector.Cookie, mods ...func(*script)) *script {
	s := &script{
		pages:   defaultPages(),
		nav:     map[string]string{loginURL: pgLogin},
		cookies: cookies,
		fail:    map[string]error{},
	}
	for _, m := range mods {
		m(s)
	}
	return s
}

// afterSubmit makes the login form's submit land on page key.
func afterSubmit(key string) func(*script) {
	return func(s *script) {
		p := s.pages[pgLogin]
		p.next = map[string]string{selSubmit: key}
		s.pages[pgLogin] = p
		p = s.pages[pgSSOLogin]
		p.next = map[string]string{selSubmit: key}
		s.pages[pgSSOLogin] = p
	}
}

// entry makes Navigate(loginURL) land on page key.
func entry(key string) func(*script) {
	return func(s *script) { s.nav[loginURL] = key }
}

// withPage adds or replaces a page.
func withPage(key string, p fakePage) func(*script) {
	return func(s *script) { s.pages[key] = p }
}

// recorder is the ordered event log shared by every double of a test.
type recorder struct {
	mu sync.Mutex
	ev []string
}

func (r *recorder) add(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ev = append(r.ev, fmt.Sprintf(format, args...))
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.ev)
}

// index returns the position of the first event equal to e, or -1.
func (r *recorder) index(e string) int {
	return slices.Index(r.list(), e)
}

// op is one recorded browser call.
type op struct {
	kind        string // navigate, wait, type, click, url, cookies, close
	arg         string // url or selector
	hasDeadline bool   // ctx carried a deadline (waits must be bounded)
}

// fakeBrowser implements connector.Browser over a script.
type fakeBrowser struct {
	n       int // 1-based launch index
	sc      *script
	rec     *recorder
	visible bool // launched with LaunchOptions.Visible

	mu        sync.Mutex
	cur       string
	ops       []op
	typed     map[string]string
	cookieReq [][]string
	closes    int
	userMoved bool
}

var _ connector.Browser = (*fakeBrowser)(nil)

// begin records the operation and returns the error it must fail with.
func (b *fakeBrowser) begin(ctx context.Context, kind, arg string) error {
	if b.sc.onOp != nil {
		b.sc.onOp(kind, arg)
	}
	_, dl := ctx.Deadline()
	b.mu.Lock()
	b.ops = append(b.ops, op{kind: kind, arg: arg, hasDeadline: dl})
	closed := b.closes > 0
	b.mu.Unlock()
	b.rec.add("b%d %s %s", b.n, kind, arg)
	if closed {
		return errors.New("fake browser: used after Close")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return b.sc.fail[kind]
}

// visibleLocked reports whether any selector of the comma-separated list
// sel is visible on the current page.
func (b *fakeBrowser) visibleLocked(sel string) bool {
	p, ok := b.sc.pages[b.cur]
	if !ok {
		return false
	}
	for part := range strings.SplitSeq(sel, ",") {
		if slices.Contains(p.visible, strings.TrimSpace(part)) {
			return true
		}
	}
	return false
}

func (b *fakeBrowser) Navigate(ctx context.Context, url string) error {
	if err := b.begin(ctx, "navigate", url); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cur = b.sc.nav[url] // unknown URL: blank page, nothing visible
	return nil
}

func (b *fakeBrowser) WaitVisible(ctx context.Context, selector string) error {
	if err := b.begin(ctx, "wait", selector); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.visibleLocked(selector) {
		return nil
	}
	if b.visible && b.sc.userDone != "" && !b.userMoved {
		b.userMoved = true
		b.cur = b.sc.userDone
		if b.visibleLocked(selector) {
			return nil
		}
	}
	return errFakeNotVisible
}

func (b *fakeBrowser) TypeSecret(ctx context.Context, selector string, value secret.Secret) error {
	if err := b.begin(ctx, "type", selector); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if strings.Contains(selector, ",") || !b.visibleLocked(selector) {
		return errors.New("fake browser: element not visible")
	}
	if b.typed == nil {
		b.typed = map[string]string{}
	}
	b.typed[selector] = value.Expose()
	return nil
}

func (b *fakeBrowser) Click(ctx context.Context, selector string) error {
	if err := b.begin(ctx, "click", selector); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if strings.Contains(selector, ",") || !b.visibleLocked(selector) {
		return errors.New("fake browser: element not visible")
	}
	if next, ok := b.sc.pages[b.cur].next[selector]; ok {
		b.cur = next
	}
	return nil
}

func (b *fakeBrowser) CurrentURL(ctx context.Context) (string, error) {
	if err := b.begin(ctx, "url", ""); err != nil {
		return "", err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if p, ok := b.sc.pages[b.cur]; ok {
		return p.url, nil
	}
	return "about:blank", nil
}

func (b *fakeBrowser) Cookies(ctx context.Context, domains []string) ([]connector.Cookie, error) {
	if err := b.begin(ctx, "cookies", strings.Join(domains, " ")); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cookieReq = append(b.cookieReq, slices.Clone(domains))
	var out []connector.Cookie
	for _, c := range b.sc.cookies {
		d := strings.ToLower(strings.TrimPrefix(c.Domain, "."))
		if slices.Contains(domains, d) {
			out = append(out, c)
		}
	}
	return out, nil
}

func (b *fakeBrowser) Close() error {
	b.mu.Lock()
	b.closes++
	b.mu.Unlock()
	b.rec.add("b%d close", b.n)
	return nil
}

// count returns how many operations of kind were attempted.
func (b *fakeBrowser) count(kind string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, o := range b.ops {
		if o.kind == kind {
			n++
		}
	}
	return n
}

// opList returns a copy of the recorded operations.
func (b *fakeBrowser) opList() []op {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.ops)
}

// typedValue returns what was typed into selector and whether it was.
func (b *fakeBrowser) typedValue(sel string) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.typed[sel]
	return v, ok
}

func (b *fakeBrowser) closeCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closes
}

func (b *fakeBrowser) cookieRequests() [][]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.cookieReq)
}

// fakePool implements connector.BrowserPool: the i-th Launch gets scripts[i].
type fakePool struct {
	rec       *recorder
	launchErr error

	mu       sync.Mutex
	scripts  []*script
	opts     []connector.LaunchOptions
	browsers []*fakeBrowser
}

var _ connector.BrowserPool = (*fakePool)(nil)

func (p *fakePool) Launch(ctx context.Context, opts connector.LaunchOptions) (connector.Browser, error) {
	mode := "headless"
	if opts.Visible {
		mode = "visible"
	}
	p.rec.add("launch %s", mode)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.opts = append(p.opts, connector.LaunchOptions{AllowedDomains: slices.Clone(opts.AllowedDomains), Visible: opts.Visible})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.launchErr != nil {
		return nil, p.launchErr
	}
	i := len(p.browsers)
	if i >= len(p.scripts) {
		return nil, fmt.Errorf("fake pool: unexpected launch #%d", i+1)
	}
	b := &fakeBrowser{n: i + 1, sc: p.scripts[i], rec: p.rec, visible: opts.Visible}
	p.browsers = append(p.browsers, b)
	return b, nil
}

func (p *fakePool) launches() []connector.LaunchOptions {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.opts)
}

func (p *fakePool) launched() []*fakeBrowser {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.browsers)
}

// fakeResolver implements connector.SecretResolver over a ref -> value map.
type fakeResolver struct {
	rec  *recorder
	vals map[string]string
	err  error

	mu    sync.Mutex
	calls []string
}

func (r *fakeResolver) Resolve(ctx context.Context, ref string) (secret.Secret, error) {
	r.rec.add("resolve %s", ref)
	r.mu.Lock()
	r.calls = append(r.calls, ref)
	r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return secret.Secret{}, err
	}
	if r.err != nil {
		return secret.Secret{}, r.err
	}
	v, ok := r.vals[ref]
	if !ok {
		return secret.Secret{}, errors.New("fake resolver: unknown reference")
	}
	return secret.FromString(v), nil
}

func (r *fakeResolver) callList() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

// fakePrompter implements connector.Prompter. A non-interactive one fails
// with ErrNeedsLogin, like the core's.
type fakePrompter struct {
	rec         *recorder
	interactive bool
	answer      string
	err         error

	mu   sync.Mutex
	reqs []connector.PromptRequest
}

func (p *fakePrompter) Prompt(ctx context.Context, req connector.PromptRequest) (secret.Secret, error) {
	p.rec.add("prompt")
	p.mu.Lock()
	p.reqs = append(p.reqs, req)
	p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return secret.Secret{}, err
	}
	if !p.interactive {
		return secret.Secret{}, fmt.Errorf("%w: fake prompter is not interactive", connector.ErrNeedsLogin)
	}
	if p.err != nil {
		return secret.Secret{}, p.err
	}
	return secret.FromString(p.answer), nil
}

func (p *fakePrompter) Interactive() bool { return p.interactive }

func (p *fakePrompter) requests() []connector.PromptRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.reqs)
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
