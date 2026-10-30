package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/secret"
)

// Page errors, errors.Is targets. None of them ever quotes a URL, a
// selector, a value or a CDP error text.
var (
	// ErrURLRefused: Navigate refused the URL before any CDP call: not
	// parsable, not https, userinfo, IP literal, port other than 443, or
	// host outside the page allowlist (same matcher as httpx).
	ErrURLRefused = errors.New("browser: url refused")
	// ErrTypeRefused: TypeSecret's pre-typing check failed (focus not on the
	// expected input of the main frame, focus in an iframe, main frame origin
	// not https or not allowlisted), or the secret is empty. Nothing was
	// typed.
	ErrTypeRefused = errors.New("browser: secret typing refused")
	// ErrNotVisible: Click or TypeSecret found no visible element.
	ErrNotVisible = errors.New("browser: element not visible")
	// ErrNavigation: Page.navigate answered an errorText (never quoted).
	ErrNavigation = errors.New("browser: navigation failed")
	// errPageScript: a page function threw or answered an unexpected
	// shape. Unexported: callers see it wrapped, never quoted.
	errPageScript = errors.New("browser: page script failed")
	// errFrameChanged: the main frame committed a new document (loaderId)
	// or URL while a page function ran: its answer is not trusted.
	errFrameChanged = errors.New("browser: main frame changed during the check")
)

// Timeouts and pauses of the page.
const (
	// defaultPollInterval is the pause between two WaitVisible polls when
	// PageOptions.PollWait is nil.
	defaultPollInterval = 100 * time.Millisecond
	// disposeTimeout bounds Target.disposeBrowserContext, run without the
	// caller's context (Close) or after it failed (NewPage cleanup).
	disposeTimeout = 5 * time.Second
	// maxCookieExpiry caps a cookie expiry (9999-12-31T23:59:59Z) so a
	// hostile value cannot overflow the conversion to time.Time.
	maxCookieExpiry = 253402300799
)

// documentExpression is the only Runtime.evaluate expression: the main
// frame's document, whose objectId the page functions run on.
const documentExpression = "document"

// isolatedWorldName names the isolated world the page functions run in
// (Page.createIsolatedWorld): the page's own scripts share the DOM but not
// the JavaScript objects, so they cannot redefine document.activeElement,
// querySelector or location for facto.
const isolatedWorldName = "facto"

// visibleHelper is shared by the page functions. It is a constant: no
// selector or other input is ever concatenated into page JavaScript.
const visibleHelper = `const visible = (el) => {
  if (!el || !el.isConnected) return false;
  const r = el.getBoundingClientRect();
  if (!(r.width > 0 && r.height > 0)) return false;
  const s = el.ownerDocument.defaultView.getComputedStyle(el);
  if (s.display === "none" || s.visibility === "hidden" || s.visibility === "collapse") return false;
  return !(parseFloat(s.opacity) <= 0);
};`

// Page functions, run with Runtime.callFunctionOn on the document object
// (this), the selector passed only as arguments[0].value.
const (
	// jsVisible: function(sel) -> bool.
	jsVisible = "function(sel) {\n" + visibleHelper + `
  return visible(this.querySelector(sel));
}`
	// jsCenter: function(sel) -> {x, y} | null, in viewport coordinates
	// after scrolling the element into view.
	jsCenter = "function(sel) {\n" + visibleHelper + `
  const el = this.querySelector(sel);
  if (!visible(el)) return null;
  el.scrollIntoView({block: "center", inline: "center"});
  const r = el.getBoundingClientRect();
  return {x: r.left + r.width / 2, y: r.top + r.height / 2};
}`
	// jsFocus: function(sel) -> bool.
	jsFocus = "function(sel) {\n" + visibleHelper + `
  const el = this.querySelector(sel);
  if (!visible(el)) return false;
  el.focus({preventScroll: false});
  return true;
}`
	// jsActiveCheck: function(sel) -> {matches, activeTag, origin}.
	jsActiveCheck = `function(sel) {
  const el = this.querySelector(sel);
  const a = this.activeElement;
  const tag = a ? String(a.tagName) : "";
  const framed = tag === "IFRAME" || tag === "FRAME";
  return {matches: !!el && a === el && !framed, activeTag: tag, origin: String(this.defaultView.location.origin)};
}`
)

// PageOptions configures NewPage.
type PageOptions struct {
	// AllowedDomains is the connector's Info().AllowedDomains, parsed with
	// httpx.ParseAllowlist plus the flag rules (no IP literal, no loopback
	// name); refused with ErrInvalidDomain.
	AllowedDomains []string
	// Log receives operation outcomes, never a URL, selector or value. Nil
	// discards.
	Log *slog.Logger
	// PollWait pauses between two WaitVisible polls and returns ctx's error
	// when ctx ends. Nil: a 100 ms timer bounded by ctx.
	PollWait func(ctx context.Context) error
}

// Page is one login page in a fresh browser context (ADR 0008 "Cookies in
// memory"). It implements connector.Browser. Close disposes the context;
// it does not close the Client, which the pool owns.
type Page struct {
	c     *Client
	allow httpx.Allowlist
	log   *slog.Logger
	wait  func(ctx context.Context) error

	contextID string
	targetID  string
	sessionID string

	// bg is the context of the enforcement calls (fetch.go); cancel ends
	// it when the page stops.
	bg     context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// subsMu guards the enforcement bookkeeping (fetch.go): the watched
	// sessions, the running handler goroutines and stopped.
	subsMu      sync.Mutex
	sessions    map[string]*watched
	running     int
	subsChanged chan struct{} // closed and replaced on each change
	stopped     bool

	blockedMu sync.Mutex
	blocked   map[string]int

	// worldMu guards world, the isolated world of one document.
	worldMu sync.Mutex
	world   *isolatedWorld

	closeOnce sync.Once
}

// isolatedWorld is the cached isolated world of one main frame document
// (frame id + loaderId) and its document object.
type isolatedWorld struct {
	frameID, loaderID string
	contextID         int64
	docObjectID       string
}

var _ connector.Browser = (*Page)(nil)

// NewPage opens the login page over c (ADR 0008 "Cookies in memory",
// "Downloads and permissions", "In-browser allowlist"), in this order:
//  1. Target.createBrowserContext (browser session);
//  2. Browser.setDownloadBehavior deny for that context;
//  3. Target.createTarget at about:blank in that context;
//  4. Target.attachToTarget with flatten;
//  5. page-session setup (Page.enable);
//  6. the in-browser allowlist (fetch.go): fail-closed subscriptions to
//     Fetch.requestPaused and Target.attachedToTarget, Fetch.enable on
//     every URL of the page session, then Target.setAutoAttach (paused
//     until enforced) on the page and browser sessions.
//
// It never navigates. An invalid allowlist is refused before any CDP call.
// A failure after step 1 disposes the context.
func NewPage(ctx context.Context, c *Client, opts PageOptions) (*Page, error) {
	domains, err := normalizeDomains(opts.AllowedDomains)
	if err != nil {
		return nil, err
	}
	allow, err := httpx.ParseAllowlist(domains)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidDomain, err)
	}
	p := &Page{
		c: c, allow: allow, log: opts.Log, wait: opts.PollWait, blocked: map[string]int{},
		sessions: map[string]*watched{}, subsChanged: make(chan struct{}),
	}
	p.bg, p.cancel = context.WithCancel(context.WithoutCancel(ctx))
	if p.log == nil {
		p.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if p.wait == nil {
		p.wait = timerWait
	}

	var created struct {
		BrowserContextID string `json:"browserContextId"`
	}
	if err := p.call(ctx, "", "Target.createBrowserContext", map[string]any{"disposeOnDetach": true}, &created); err != nil {
		p.cancel()
		return nil, fmt.Errorf("new page: create browser context: %w", err)
	}
	if created.BrowserContextID == "" {
		p.cancel()
		return nil, fmt.Errorf("new page: create browser context: %w", errPageScript)
	}
	p.contextID = created.BrowserContextID

	if err := p.setup(ctx); err != nil {
		p.dispose(ctx)
		return nil, err
	}
	p.log.Debug("browser: login page ready")
	return p, nil
}

// setup runs NewPage steps 2 to 6.
func (p *Page) setup(ctx context.Context) error {
	if err := p.call(ctx, "", "Browser.setDownloadBehavior", map[string]any{
		"behavior": "deny", "browserContextId": p.contextID,
	}, nil); err != nil {
		return fmt.Errorf("new page: deny downloads: %w", err)
	}
	var target struct {
		TargetID string `json:"targetId"`
	}
	if err := p.call(ctx, "", "Target.createTarget", map[string]any{
		"url": "about:blank", "browserContextId": p.contextID,
	}, &target); err != nil {
		return fmt.Errorf("new page: create target: %w", err)
	}
	if target.TargetID == "" {
		return fmt.Errorf("new page: create target: %w", errPageScript)
	}
	p.targetID = target.TargetID
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := p.call(ctx, "", "Target.attachToTarget", map[string]any{
		"targetId": p.targetID, "flatten": true,
	}, &attached); err != nil {
		return fmt.Errorf("new page: attach to target: %w", err)
	}
	if attached.SessionID == "" {
		return fmt.Errorf("new page: attach to target: %w", errPageScript)
	}
	p.sessionID = attached.SessionID
	if err := p.call(ctx, p.sessionID, "Page.enable", nil, nil); err != nil {
		return fmt.Errorf("new page: enable page domain: %w", err)
	}
	p.watch("", rootParent, false, true)
	p.watch(p.sessionID, rootParent, true, true)
	if err := p.call(ctx, p.sessionID, "Fetch.enable", fetchEnableParams, nil); err != nil {
		return fmt.Errorf("new page: enable fetch: %w", err)
	}
	if err := p.call(ctx, p.sessionID, "Target.setAutoAttach", autoAttachParams, nil); err != nil {
		return fmt.Errorf("new page: auto attach: %w", err)
	}
	if err := p.call(ctx, "", "Target.setAutoAttach", autoAttachParams, nil); err != nil {
		return fmt.Errorf("new page: auto attach pop-ups: %w", err)
	}
	return nil
}

// timerWait is the default PollWait.
func timerWait(ctx context.Context) error {
	t := time.NewTimer(defaultPollInterval)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err() //nolint:wrapcheck // callers wrap; errors.Is must see ctx.Err
	}
}

// call runs method and decodes its result into out (when non-nil).
func (p *Page) call(ctx context.Context, session, method string, params, out any) error {
	raw, err := p.c.Call(ctx, session, method, params)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if json.Unmarshal(raw, out) != nil {
		// Never quote the result nor the decoder error.
		return fmt.Errorf("%w: unexpected %s result", errPageScript, method)
	}
	return nil
}

// Navigate checks rawURL (https, no userinfo, no IP literal, port 443 only,
// allowlisted host) and sends Page.navigate. It returns when the browser
// answers, without waiting for the load (WaitVisible does that).
func (p *Page) Navigate(ctx context.Context, rawURL string) error {
	if err := p.checkURL(rawURL); err != nil {
		p.log.Debug("browser: navigation refused")
		return err
	}
	var res struct {
		ErrorText string `json:"errorText"`
	}
	if err := p.call(ctx, p.sessionID, "Page.navigate", map[string]any{"url": rawURL}, &res); err != nil {
		return fmt.Errorf("navigate: %w", err)
	}
	if res.ErrorText != "" {
		p.log.Debug("browser: navigation failed")
		return ErrNavigation
	}
	return nil
}

// checkURL applies the Navigate rules. The error never quotes the URL.
func (p *Page) checkURL(raw string) error {
	if hasUnsafeChar(raw) {
		return fmt.Errorf("%w: control character, space or backslash", ErrURLRefused)
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return fmt.Errorf("%w: not parsable", ErrURLRefused)
	case u.Scheme != "https" || u.Opaque != "" || u.Host == "":
		return fmt.Errorf("%w: not an absolute https url", ErrURLRefused)
	case u.User != nil:
		return fmt.Errorf("%w: userinfo", ErrURLRefused)
	case strings.Contains(u.Host, "%"):
		return fmt.Errorf("%w: escaped host", ErrURLRefused)
	}
	if port := u.Port(); port != "" && port != defaultHTTPSPort {
		return fmt.Errorf("%w: port other than 443", ErrURLRefused)
	}
	host := u.Hostname()
	if _, err := netip.ParseAddr(host); err == nil || strings.HasPrefix(u.Host, "[") {
		return fmt.Errorf("%w: ip literal", ErrURLRefused)
	}
	if !p.allow.Allows(host) {
		return fmt.Errorf("%w: host not allowlisted", ErrURLRefused)
	}
	return nil
}

// defaultHTTPSPort is the only port a page URL may name.
const defaultHTTPSPort = "443"

// frameState is the main frame as the browser reports it.
type frameState struct {
	ID       string `json:"id"`
	LoaderID string `json:"loaderId"`
	URL      string `json:"url"`
}

// mainFrame reads the main frame's id, loaderId and URL from the browser
// (Page.getFrameTree). They are the browser's truth: no page script can
// change what it reports.
func (p *Page) mainFrame(ctx context.Context) (frameState, error) {
	var tree struct {
		FrameTree struct {
			Frame frameState `json:"frame"`
		} `json:"frameTree"`
	}
	if err := p.call(ctx, p.sessionID, "Page.getFrameTree", nil, &tree); err != nil {
		return frameState{}, err
	}
	if tree.FrameTree.Frame.ID == "" {
		return frameState{}, fmt.Errorf("%w: no main frame", errPageScript)
	}
	return tree.FrameTree.Frame, nil
}

// remoteValue is the part of a Runtime.callFunctionOn answer the page reads.
type remoteValue struct {
	Result struct {
		Value json.RawMessage `json:"value"`
	} `json:"result"`
	ExceptionDetails json.RawMessage `json:"exceptionDetails"`
}

// run calls the constant page function decl with sel as arguments[0].value
// on the main frame's document, in the isolated world of that document
// (cached per frame id + loaderId), and decodes its by-value result into
// out. It reads the main frame before and after the function: a different
// frame id, loaderId or URL afterwards means a navigation committed
// mid-check and gives errFrameChanged. It returns the main frame state
// read before the function ran.
func (p *Page) run(ctx context.Context, decl, sel string, out any) (frameState, error) {
	before, err := p.mainFrame(ctx)
	if err != nil {
		return frameState{}, err
	}
	rv, err := p.callInWorld(ctx, before, decl, sel)
	if err != nil {
		return frameState{}, err
	}
	after, err := p.mainFrame(ctx)
	if err != nil {
		return frameState{}, err
	}
	if after != before {
		return frameState{}, errFrameChanged
	}
	if rv.ExceptionDetails != nil {
		return frameState{}, fmt.Errorf("%w: exception", errPageScript)
	}
	if json.Unmarshal(rv.Result.Value, out) != nil {
		return frameState{}, fmt.Errorf("%w: unexpected value", errPageScript)
	}
	return before, nil
}

// callInWorld runs decl on the document of fr's isolated world. A CDP
// error in a cached world (its context was destroyed) drops it and retries
// once in a fresh one.
func (p *Page) callInWorld(ctx context.Context, fr frameState, decl, sel string) (remoteValue, error) {
	for {
		w, cached, err := p.isolatedWorld(ctx, fr)
		if err != nil {
			return remoteValue{}, err
		}
		var rv remoteValue
		err = p.call(ctx, p.sessionID, "Runtime.callFunctionOn", map[string]any{
			"functionDeclaration": decl,
			"objectId":            w.docObjectID,
			"arguments":           []map[string]any{{"value": sel}},
			"returnByValue":       true,
			"awaitPromise":        false,
		}, &rv)
		if err == nil {
			return rv, nil
		}
		p.dropWorld(w)
		if !cached || !errors.Is(err, ErrCDP) {
			return remoteValue{}, err
		}
	}
}

// isolatedWorld returns the isolated world of fr's document, creating it
// (and reading its document object) when the cache holds another one.
// cached reports a cache hit.
func (p *Page) isolatedWorld(ctx context.Context, fr frameState) (w *isolatedWorld, cached bool, err error) {
	p.worldMu.Lock()
	w = p.world
	p.worldMu.Unlock()
	if w != nil && w.frameID == fr.ID && w.loaderID == fr.LoaderID {
		return w, true, nil
	}
	var world struct {
		ExecutionContextID int64 `json:"executionContextId"`
	}
	if err := p.call(ctx, p.sessionID, "Page.createIsolatedWorld", map[string]any{
		"frameId": fr.ID, "worldName": isolatedWorldName, "grantUniveralAccess": false,
	}, &world); err != nil {
		return nil, false, err
	}
	if world.ExecutionContextID == 0 {
		return nil, false, fmt.Errorf("%w: no isolated world", errPageScript)
	}
	var doc struct {
		Result struct {
			ObjectID string `json:"objectId"`
		} `json:"result"`
		ExceptionDetails json.RawMessage `json:"exceptionDetails"`
	}
	if err := p.call(ctx, p.sessionID, "Runtime.evaluate", map[string]any{
		"expression": documentExpression, "contextId": world.ExecutionContextID, "returnByValue": false,
	}, &doc); err != nil {
		return nil, false, err
	}
	if doc.ExceptionDetails != nil || doc.Result.ObjectID == "" {
		return nil, false, fmt.Errorf("%w: no document", errPageScript)
	}
	w = &isolatedWorld{frameID: fr.ID, loaderID: fr.LoaderID, contextID: world.ExecutionContextID, docObjectID: doc.Result.ObjectID}
	p.worldMu.Lock()
	p.world = w
	p.worldMu.Unlock()
	return w, false, nil
}

// dropWorld forgets w when it is still the cached world.
func (p *Page) dropWorld(w *isolatedWorld) {
	p.worldMu.Lock()
	if p.world == w {
		p.world = nil
	}
	p.worldMu.Unlock()
}

// WaitVisible polls until the element matching selector is visible, with
// PollWait between polls, or until ctx ends (the error wraps ctx.Err()).
func (p *Page) WaitVisible(ctx context.Context, selector string) error {
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("wait visible: %w", err)
		}
		var visible bool
		// A document committed mid-poll is not an error: poll again.
		if _, err := p.run(ctx, jsVisible, selector, &visible); err != nil && !errors.Is(err, errFrameChanged) {
			return fmt.Errorf("wait visible: %w", err)
		}
		if visible {
			return nil
		}
		if err := p.wait(ctx); err != nil {
			return fmt.Errorf("wait visible: %w", err)
		}
	}
}

// Click presses and releases the left button at the centre of the visible
// element matching selector. It does not wait.
func (p *Page) Click(ctx context.Context, selector string) error {
	var center *struct {
		X float64 `json:"x"`
		Y float64 `json:"y"`
	}
	if _, err := p.run(ctx, jsCenter, selector, &center); err != nil {
		return fmt.Errorf("click: %w", err)
	}
	if center == nil {
		return fmt.Errorf("click: %w", ErrNotVisible)
	}
	for _, typ := range []string{"mousePressed", "mouseReleased"} {
		if err := p.call(ctx, p.sessionID, "Input.dispatchMouseEvent", map[string]any{
			"type": typ, "x": center.X, "y": center.Y, "button": "left", "clickCount": 1,
		}, nil); err != nil {
			return fmt.Errorf("click: %w", err)
		}
	}
	return nil
}

// activeCheck is jsActiveCheck's result.
type activeCheck struct {
	Matches   bool   `json:"matches"`
	ActiveTag string `json:"activeTag"`
	Origin    string `json:"origin"` // spoofable from the page: never trusted, the frame tree URL is checked
}

// TypeSecret focuses the visible element matching selector, checks just
// before typing that the focus is on it in the main frame (page function in
// an isolated world) and that the main frame URL, read from the browser, is
// https and allowlisted (ADR 0008 "Secret typing"), then types value with
// one Input.insertText. It checks both again after typing: a change gives
// ErrTypeRefused ("focus or origin changed while typing"); the value may
// then have reached the page and the login must not go on. The value is
// exposed only in the insertText request, whose encoded buffer the client
// clears once sent; it never reaches a log or an error. The caller's secret
// is not wiped.
func (p *Page) TypeSecret(ctx context.Context, selector string, value secret.Secret) error {
	if value.IsZero() {
		return fmt.Errorf("type secret: %w: empty secret", ErrTypeRefused)
	}
	var focused bool
	if _, err := p.run(ctx, jsFocus, selector, &focused); err != nil {
		return fmt.Errorf("type secret: %w", err)
	}
	if !focused {
		return fmt.Errorf("type secret: %w", ErrNotVisible)
	}
	loaderID, reason, err := p.typingTarget(ctx, selector, "")
	if err != nil {
		return fmt.Errorf("type secret: %w", err)
	}
	if reason != "" {
		p.log.Debug("browser: secret typing refused", "reason", reason)
		return fmt.Errorf("type secret: %w: %s", ErrTypeRefused, reason)
	}
	// Best effort only: json.Marshal also leaves the encoded value in its
	// pooled internal buffer, and the exposed string cannot be wiped.
	if err := p.call(ctx, p.sessionID, "Input.insertText", insertText{Text: value.Expose()}, nil); err != nil {
		return fmt.Errorf("type secret: %w", err)
	}
	_, reason, err = p.typingTarget(ctx, selector, loaderID)
	if err != nil {
		return fmt.Errorf("type secret: after typing: %w", err)
	}
	if reason != "" {
		p.log.Debug("browser: focus or origin changed while typing", "reason", reason)
		return fmt.Errorf("type secret: %w: focus or origin changed while typing", ErrTypeRefused)
	}
	return nil
}

// typingTarget runs jsActiveCheck and returns the main frame loaderId and
// why typing into selector is refused ("" when allowed): a navigation
// committed during the check, the document is not wantLoader (when not
// empty), the focus is not on the input in the main frame, or the main
// frame URL reported by the browser is not https or not allowlisted. The
// origin in the script's answer is not trusted.
func (p *Page) typingTarget(ctx context.Context, selector, wantLoader string) (loaderID, reason string, err error) {
	var chk activeCheck
	fr, err := p.run(ctx, jsActiveCheck, selector, &chk)
	switch {
	case errors.Is(err, errFrameChanged):
		return "", "the page navigated during the check", nil
	case err != nil:
		return "", "", err
	case wantLoader != "" && fr.LoaderID != wantLoader:
		return "", "the page loaded a new document", nil
	case !chk.Matches:
		return "", "focus is not on the expected input of the main frame", nil
	case p.checkURL(fr.URL) != nil:
		return "", "page url is not https or not allowlisted", nil
	}
	return fr.LoaderID, "", nil
}

// insertText is the Input.insertText params.
type insertText struct {
	Text string `json:"text"`
}

// CurrentURL returns the page target's URL.
func (p *Page) CurrentURL(ctx context.Context) (string, error) {
	var info struct {
		TargetInfo struct {
			URL string `json:"url"`
		} `json:"targetInfo"`
	}
	if err := p.call(ctx, "", "Target.getTargetInfo", map[string]any{"targetId": p.targetID}, &info); err != nil {
		return "", fmt.Errorf("current url: %w", err)
	}
	return info.TargetInfo.URL, nil
}

// cdpCookie is one cookie as Storage.getCookies returns it.
type cdpCookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires"`
	HTTPOnly bool    `json:"httpOnly"`
	Secure   bool    `json:"secure"`
	Session  bool    `json:"session"`
}

// Cookies returns the login context's cookies whose domain (leading dot
// ignored) the page allowlist allows and, when domains is not empty, that
// domains (same pattern rules, refused with ErrInvalidDomain) allows too:
// domains narrows, never widens. Values are secret.Secret.
func (p *Page) Cookies(ctx context.Context, domains []string) ([]connector.Cookie, error) {
	var want *httpx.Allowlist
	if len(domains) > 0 {
		a, err := httpx.ParseAllowlist(domains)
		if err != nil {
			return nil, fmt.Errorf("cookies: %w: %w", ErrInvalidDomain, err)
		}
		want = &a
	}
	raw, err := p.c.Call(ctx, "", "Storage.getCookies", map[string]any{"browserContextId": p.contextID})
	if err != nil {
		return nil, fmt.Errorf("cookies: %w", err)
	}
	// The answer holds every cookie value: cleared once decoded. Best effort
	// only: the decoded strings, and copies made while reading the frame,
	// cannot be wiped.
	defer clear(raw)
	var res struct {
		Cookies []cdpCookie `json:"cookies"`
	}
	if json.Unmarshal(raw, &res) != nil {
		return nil, fmt.Errorf("cookies: %w: unexpected result", errPageScript)
	}
	var out []connector.Cookie
	for _, c := range res.Cookies {
		host := strings.TrimPrefix(c.Domain, ".")
		if host == "" || !p.allow.Allows(host) || (want != nil && !want.Allows(host)) {
			continue
		}
		out = append(out, connector.Cookie{
			Name:     c.Name,
			Value:    secret.FromString(c.Value),
			Domain:   c.Domain,
			Path:     c.Path,
			Expires:  cookieExpiry(c.Expires, c.Session),
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
		})
	}
	return out, nil
}

// cookieExpiry converts a CDP expiry (seconds since the epoch) to UTC; a
// session cookie or a non-positive expiry gives the zero time.
func cookieExpiry(expires float64, session bool) time.Time {
	if session || !(expires > 0) {
		return time.Time{}
	}
	expires = min(expires, maxCookieExpiry)
	sec, frac := math.Modf(expires)
	return time.Unix(int64(sec), int64(frac*float64(time.Second))).UTC()
}

// Close disposes the login context once (its targets and cookies go with
// it). Later calls return nil. It does not close the Client.
func (p *Page) Close() error {
	var err error
	p.closeOnce.Do(func() {
		p.stop()
		ctx, cancel := context.WithTimeout(context.Background(), disposeTimeout)
		defer cancel()
		if _, e := p.c.Call(ctx, "", "Target.disposeBrowserContext", map[string]any{"browserContextId": p.contextID}); e != nil {
			err = fmt.Errorf("close page: %w", e)
		}
	})
	return err
}

// dispose is NewPage's cleanup: bounded, and run even when ctx has ended.
func (p *Page) dispose(ctx context.Context) {
	p.stop()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), disposeTimeout)
	defer cancel()
	_, _ = p.c.Call(ctx, "", "Target.disposeBrowserContext", map[string]any{"browserContextId": p.contextID})
	p.closeOnce.Do(func() {})
}
