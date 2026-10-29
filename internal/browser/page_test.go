// Tests for J1 task T8 (feat(browser): page operations and secret typing),
// ADR 0008 "Hardening" (secret typing, cookies in memory, downloads) and
// "Tests required" (T8, plus TestBrowser_DownloadsDenied listed under T10).
// The browser is the in-memory scripted peer of fakecdp_test.go: these tests
// build and run on every OS. No real Chrome, no network.
//
// Expected API of package internal/browser (written before the
// implementation; the tests below are the contract):
//
//	// page.go (all OSes)
//	var (
//		// ErrURLRefused: Navigate refused the URL before any CDP call: not
//		// parsable, not https, userinfo, IP literal, port other than 443,
//		// or host outside the page allowlist (same matcher as httpx).
//		ErrURLRefused = errors.New("browser: url refused")
//		// ErrTypeRefused: TypeSecret's pre-typing check failed (focus not on
//		// the expected input of the main frame, focus in an iframe, main
//		// frame origin not https or not allowlisted), or the secret is
//		// empty. Nothing was typed.
//		ErrTypeRefused = errors.New("browser: secret typing refused")
//		// ErrNotVisible: Click or TypeSecret found no visible element.
//		ErrNotVisible = errors.New("browser: element not visible")
//		// ErrNavigation: Page.navigate answered an errorText (never quoted).
//		ErrNavigation = errors.New("browser: navigation failed")
//	)
//
//	type PageOptions struct {
//		AllowedDomains []string     // connector Info().AllowedDomains; parsed with
//		                            // httpx.ParseAllowlist, refused with ErrInvalidDomain
//		Log            *slog.Logger // nil: discard
//		// PollWait pauses between two WaitVisible polls and returns ctx's
//		// error when ctx ends. nil: a 100 ms timer bounded by ctx.
//		PollWait func(ctx context.Context) error
//	}
//
//	// NewPage opens the login page over c (ADR 0008 "Cookies in memory",
//	// "Downloads and permissions", "In-browser allowlist"), in this order:
//	//   1. Target.createBrowserContext (browser session) -> browserContextId
//	//   2. Browser.setDownloadBehavior {behavior:"deny", browserContextId}
//	//   3. Target.createTarget {url:"about:blank", browserContextId} -> targetId
//	//   4. Target.attachToTarget {targetId, flatten:true} -> sessionId
//	//   5. page-session setup (Page.enable…; T9 adds Fetch.enable). Never navigates.
//	// A failure after step 1 disposes the context. An invalid allowlist is
//	// refused before any CDP call.
//	func NewPage(ctx context.Context, c *Client, opts PageOptions) (*Page, error)
//
//	// *Page implements connector.Browser. Every Page./Runtime./Input./
//	// Network. call runs on the attached session id.
//	//
//	// Page JavaScript: Runtime.callFunctionOn with returnByValue:true, an
//	// objectId obtained from Runtime.evaluate of a constant expression (the
//	// main frame's document), a constant functionDeclaration (jsVisible,
//	// jsCenter, jsFocus, jsActiveCheck; see export_test.go for their result
//	// shapes) and the selector ONLY as arguments[0].value. A selector is
//	// never concatenated into any expression or declaration.
//	//
//	// Navigate: URL check, then Page.navigate {url}; returns when it answers
//	//   (no load wait: WaitVisible does that). errorText -> ErrNavigation.
//	// WaitVisible: polls jsVisible, PollWait between polls, until true or
//	//   ctx ends (error wraps ctx.Err()).
//	// Click: jsCenter (null -> ErrNotVisible, no input event), then
//	//   Input.dispatchMouseEvent mousePressed and mouseReleased at {x, y},
//	//   button "left", clickCount 1. No waiting.
//	// TypeSecret: refuses an empty secret; jsFocus (false -> ErrNotVisible);
//	//   jsActiveCheck immediately before typing, refusing (ErrTypeRefused)
//	//   unless matches is true and origin is https with an allowlisted host;
//	//   then ONE Input.insertText {text: value.Expose()}. No key events. The
//	//   exposed value appears in no other message, log or error. The
//	//   caller's secret is not wiped.
//	// CurrentURL: Target.getTargetInfo {targetId} -> targetInfo.url.
//	// Cookies: Storage.getCookies {browserContextId} (or Network.getCookies on
//	//   the session); keeps cookies whose domain (leading dot ignored) the
//	//   allowlist allows and, when domains is not empty, that one of domains
//	//   matches (same pattern rules). Value as secret.Secret; expires <= 0 or
//	//   session -> zero Expires, else time.Unix UTC.
//	// Close: Target.disposeBrowserContext {browserContextId} once;
//	//   idempotent. It does not close the Client (the pool owns it).
//
//	// client.go (T7 amendment, "wiped where feasible"): Call clears the
//	// encoded request it passed to Transport.Send once Send has returned,
//	// and does not return a result before that.
package browser_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

var _ connector.Browser = (*browser.Page)(nil)

var testAllow = []string{"supplier.example", "*.supplier.example"}

const loginURL = "https://login.supplier.example/login"

// lockedBuffer is a goroutine-safe log sink.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p) //nolint:wrapcheck // test sink
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type pageEnv struct {
	f    *fakeCDP
	c    *browser.Client
	p    *browser.Page
	logs *lockedBuffer
}

// immediateWait is a PollWait that never pauses (no sleep in tests).
func immediateWait(ctx context.Context) error { return ctx.Err() }

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// pollDeadline is a context whose deadline is reached on demand: Err is
// context.DeadlineExceeded once expire is called, like a real deadline but
// without depending on wall-clock time.
type pollDeadline struct {
	context.Context
	once sync.Once
	done chan struct{}
}

func newPollDeadline(parent context.Context) *pollDeadline {
	return &pollDeadline{Context: parent, done: make(chan struct{})}
}

func (d *pollDeadline) expire() { d.once.Do(func() { close(d.done) }) }

func (d *pollDeadline) Done() <-chan struct{} { return d.done }

func (d *pollDeadline) Err() error {
	select {
	case <-d.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

// newEnv returns a fake browser, its client and the PageOptions logging to
// a raw (non-redacting) handler at debug level: what the page hands to its
// logger is what the tests inspect.
func newEnv(t *testing.T) (*fakeCDP, *browser.Client, browser.PageOptions, *lockedBuffer) {
	t.Helper()
	f := newFakeCDP(t)
	c := browser.NewClient(f)
	t.Cleanup(func() { _ = c.Close() })
	logs := &lockedBuffer{}
	opts := browser.PageOptions{
		AllowedDomains: testAllow,
		Log:            slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		PollWait:       immediateWait,
	}
	return f, c, opts, logs
}

func newPage(t *testing.T) *pageEnv {
	t.Helper()
	f, c, opts, logs := newEnv(t)
	p, err := browser.NewPage(testCtx(t), c, opts)
	if err != nil {
		t.Fatalf("NewPage = %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return &pageEnv{f: f, c: c, p: p, logs: logs}
}

func (e *pageEnv) navigate(t *testing.T, u string) {
	t.Helper()
	if err := e.p.Navigate(testCtx(t), u); err != nil {
		t.Fatalf("Navigate(%s) = %v", u, err)
	}
}

// --- browser context, downloads --------------------------------------

func TestBrowser_LoginRunsInFreshBrowserContext(t *testing.T) {
	t.Parallel()

	t.Run("context, blank target, flat attach, then the page session", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		setup := e.f.snapshot()
		iCtx := index(setup, "Target.createBrowserContext")
		iTgt := index(setup, "Target.createTarget")
		iAtt := index(setup, "Target.attachToTarget")
		if iCtx < 0 || iTgt < 0 || iAtt < 0 || iCtx >= iTgt || iTgt >= iAtt {
			t.Fatalf("setup methods = %q; want createBrowserContext, then createTarget, then attachToTarget", methods(setup))
		}
		if s := setup[iCtx].Session; s != "" {
			t.Errorf("createBrowserContext sent on session %q, want the browser session", s)
		}
		for _, c := range filter(setup, "Target.createTarget") {
			if c.Params["url"] != "about:blank" {
				t.Errorf("createTarget url = %v, want about:blank (Fetch is enabled before any navigation)", c.Params["url"])
			}
			if c.Params["browserContextId"] != fakeContextID {
				t.Errorf("createTarget browserContextId = %v, want %q (never the default, profile-backed context)", c.Params["browserContextId"], fakeContextID)
			}
		}
		att := setup[iAtt]
		if att.Params["targetId"] != fakeTargetID || att.Params["flatten"] != true {
			t.Errorf("attachToTarget params = %v, want targetId %q and flatten true", att.Params, fakeTargetID)
		}
		if i := index(setup, "Page.navigate"); i >= 0 {
			t.Errorf("NewPage navigated (call %d): the page must stay at about:blank", i)
		}

		e.navigate(t, loginURL) // the fake checks the page session id

		if err := e.p.Close(); err != nil {
			t.Fatalf("Close = %v", err)
		}
		if err := e.p.Close(); err != nil {
			t.Errorf("second Close = %v, want nil", err)
		}
		disp := filter(e.f.snapshot(), "Target.disposeBrowserContext")
		if len(disp) != 1 || disp[0].Params["browserContextId"] != fakeContextID {
			t.Errorf("disposeBrowserContext calls = %v, want exactly one for %q", disp, fakeContextID)
		}
	})

	t.Run("context creation failure stops the setup", func(t *testing.T) {
		t.Parallel()
		f, c, opts, _ := newEnv(t)
		f.setOverride("Target.createBrowserContext", func(cdpCall) any { return &cdpErr{code: -32000} })
		if p, err := browser.NewPage(testCtx(t), c, opts); err == nil {
			_ = p.Close()
			t.Fatal("NewPage = nil error, want the context failure")
		}
		if i := index(f.snapshot(), "Target.createTarget"); i >= 0 {
			t.Errorf("createTarget sent after the context failed: %q", methods(f.snapshot()))
		}
	})

	t.Run("attach failure disposes the context", func(t *testing.T) {
		t.Parallel()
		f, c, opts, _ := newEnv(t)
		f.setOverride("Target.attachToTarget", func(cdpCall) any { return &cdpErr{code: -32000} })
		if p, err := browser.NewPage(testCtx(t), c, opts); err == nil {
			_ = p.Close()
			t.Fatal("NewPage = nil error, want the attach failure")
		}
		if disp := filter(f.snapshot(), "Target.disposeBrowserContext"); len(disp) != 1 {
			t.Errorf("disposeBrowserContext calls = %d, want 1: %q", len(disp), methods(f.snapshot()))
		}
	})
}

func TestBrowser_DownloadsDenied(t *testing.T) {
	t.Parallel()

	t.Run("deny set during setup, before the first navigation", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		setup := e.f.snapshot()
		dl := filter(setup, "Browser.setDownloadBehavior")
		if len(dl) == 0 {
			t.Fatalf("setup methods = %q; want Browser.setDownloadBehavior", methods(setup))
		}
		if dl[0].Params["behavior"] != "deny" {
			t.Errorf("download behavior = %v, want deny", dl[0].Params["behavior"])
		}
		if dl[0].Params["browserContextId"] != fakeContextID {
			t.Errorf("setDownloadBehavior browserContextId = %v, want %q (the login context)", dl[0].Params["browserContextId"], fakeContextID)
		}
		if index(setup, "Browser.setDownloadBehavior") < index(setup, "Target.createBrowserContext") {
			t.Errorf("setDownloadBehavior before the context exists: %q", methods(setup))
		}
		e.navigate(t, loginURL)
		all := e.f.snapshot()
		if index(all, "Browser.setDownloadBehavior") > index(all, "Page.navigate") {
			t.Errorf("downloads denied after the first navigation: %q", methods(all))
		}
		for _, c := range filter(all, "Browser.setDownloadBehavior") {
			if c.Params["behavior"] != "deny" {
				t.Errorf("download behavior later set to %v", c.Params["behavior"])
			}
		}
	})

	t.Run("deny failure fails closed", func(t *testing.T) {
		t.Parallel()
		f, c, opts, _ := newEnv(t)
		f.setOverride("Browser.setDownloadBehavior", func(cdpCall) any { return &cdpErr{code: -32000} })
		if p, err := browser.NewPage(testCtx(t), c, opts); err == nil {
			_ = p.Close()
			t.Fatal("NewPage = nil error, want failure when downloads cannot be denied")
		}
		calls := f.snapshot()
		if index(calls, "Page.navigate") >= 0 {
			t.Errorf("navigated although downloads are not denied: %q", methods(calls))
		}
		if len(filter(calls, "Target.disposeBrowserContext")) != 1 {
			t.Errorf("context not disposed after the failure: %q", methods(calls))
		}
	})
}

// --- navigation -------------------------------------------------------

func TestPage_NavigateRefusesNonHTTPSAndOffAllowlist(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)

	refused := []struct{ name, url string }{
		{"empty", ""},
		{"file", "file:///etc/hosts"},
		{"chrome", "chrome://settings/"},
		{"chrome-extension", "chrome-extension://abcdefghijklmnop/page.html"},
		{"data", "data:text/html,<form></form>"},
		{"javascript", "javascript:alert(1)"},
		{"blob", "blob:https://login.supplier.example/0b6f0d2e-0000-4000-8000-000000000000"},
		{"view-source", "view-source:https://login.supplier.example/"},
		{"about", "about:blank"},
		{"http", "http://login.supplier.example/login"},
		{"ws", "wss://login.supplier.example/socket"},
		{"ftp", "ftp://login.supplier.example/"},
		{"scheme-relative", "//login.supplier.example/login"},
		{"opaque https", "https:login.supplier.example"},
		{"userinfo with secret", "https://user:" + canary + "@login.supplier.example/"},
		{"userinfo name only", "https://user@login.supplier.example/"},
		{"ipv4 literal", "https://192.0.2.10/login"},
		{"ipv6 literal", "https://[2001:db8::1]/login"},
		{"loopback", "https://127.0.0.1/"},
		{"localhost", "https://localhost/"},
		{"off allowlist", "https://evil.example/login"},
		{"lookalike suffix", "https://login.supplier.example.evil.example/"},
		{"fragment trick", "https://evil.example#@login.supplier.example/"},
		{"other port", "https://login.supplier.example:8443/"},
		{"trailing dot", "https://login.supplier.example./"},
		{"leading space", " https://login.supplier.example/"},
		{"control char", "https://login.supplier.example/\nx"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newPage(t)
			m := e.f.mark()
			err := e.p.Navigate(testCtx(t), tc.url)
			if !errors.Is(err, browser.ErrURLRefused) {
				t.Fatalf("Navigate(%q) = %v, want ErrURLRefused", tc.url, err)
			}
			if got := e.f.since(m); len(got) != 0 {
				t.Errorf("Navigate(%q) sent %q, want zero CDP calls", tc.url, methods(got))
			}
			if strings.Contains(err.Error(), canary) || strings.Contains(e.logs.String(), canary) {
				t.Errorf("userinfo secret leaked: err %q, logs %q", err, e.logs.String())
			}
		})
	}

	allowed := []string{
		"https://login.supplier.example/login?step=1#top",
		"https://api.supplier.example/",
		"https://supplier.example/",
		"https://LOGIN.supplier.example/",
		"https://login.supplier.example:443/",
	}
	for _, u := range allowed {
		t.Run("allowed "+u, func(t *testing.T) {
			t.Parallel()
			e := newPage(t)
			m := e.f.mark()
			if err := e.p.Navigate(testCtx(t), u); err != nil {
				t.Fatalf("Navigate(%q) = %v, want nil", u, err)
			}
			nav := filter(e.f.since(m), "Page.navigate")
			if len(nav) != 1 || nav[0].Params["url"] == nil {
				t.Fatalf("Page.navigate calls = %v, want one", nav)
			}
		})
	}

	t.Run("navigation error text never quoted", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.f.setOverride("Page.navigate", func(cdpCall) any {
			return map[string]any{"frameId": "frame-main", "errorText": "net::ERR_FAILED " + canary}
		})
		err := e.p.Navigate(testCtx(t), loginURL)
		if !errors.Is(err, browser.ErrNavigation) {
			t.Fatalf("Navigate = %v, want ErrNavigation", err)
		}
		if strings.Contains(err.Error(), canary) || strings.Contains(e.logs.String(), canary) {
			t.Errorf("errorText echoed: err %q", err)
		}
	})

	t.Run("invalid allowlist refused before any CDP call", func(t *testing.T) {
		t.Parallel()
		for _, al := range [][]string{nil, {}, {"*"}, {"https://login.supplier.example"}, {"login.supplier.example:443"}} {
			f, c, opts, _ := newEnv(t)
			opts.AllowedDomains = al
			p, err := browser.NewPage(testCtx(t), c, opts)
			if !errors.Is(err, browser.ErrInvalidDomain) {
				if p != nil {
					_ = p.Close()
				}
				t.Errorf("NewPage(AllowedDomains %q) = %v, want ErrInvalidDomain", al, err)
			}
			if got := f.snapshot(); len(got) != 0 {
				t.Errorf("NewPage(AllowedDomains %q) sent %q, want zero CDP calls", al, methods(got))
			}
		}
	})
}

// --- secret typing ----------------------------------------------------

func TestPage_TypeSecretUsesInsertTextNeverLogs(t *testing.T) {
	t.Parallel()

	t.Run("one insertText after the focus check, nowhere else", func(t *testing.T) {
		t.Parallel()
		canary := testsecrets.Canary(t, testsecrets.Password)
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.setElem("#password", fakeElem{visible: true, x: 10, y: 20})
		sec := secret.FromString(canary)

		m := e.f.mark()
		if err := e.p.TypeSecret(testCtx(t), "#password", sec); err != nil {
			t.Fatalf("TypeSecret = %v, want nil", err)
		}
		calls := e.f.since(m)

		var holders []string
		for _, c := range calls {
			if strings.Contains(c.Raw, canary) {
				holders = append(holders, c.Method)
			}
		}
		if !slices.Equal(holders, []string{"Input.insertText"}) {
			t.Fatalf("messages holding the value = %q, want exactly one Input.insertText", holders)
		}
		ins := filter(calls, "Input.insertText")
		if len(ins) != 1 || ins[0].Params["text"] != canary {
			t.Fatalf("Input.insertText calls = %d, want one with the exposed value as text", len(ins))
		}
		if i := index(calls, "Input.dispatchKeyEvent"); i >= 0 {
			t.Errorf("key events sent (call %d): the value must be typed with one insertText", i)
		}

		// The focus check is the last page call before typing, on the
		// same selector.
		iIns := index(calls, "Input.insertText")
		var last *cdpCall
		for i := iIns - 1; i >= 0; i-- {
			if calls[i].Method == "Runtime.callFunctionOn" {
				last = &calls[i]
				break
			}
		}
		if last == nil || last.Params["functionDeclaration"] != browser.JSActiveCheck {
			t.Fatalf("last Runtime.callFunctionOn before insertText is not jsActiveCheck: %q", methods(calls))
		}
		if sel, _ := firstArg(*last); sel != "#password" {
			t.Errorf("jsActiveCheck selector = %q, want #password", sel)
		}
		if len(funcCalls(calls[:iIns], browser.JSFocus)) == 0 {
			t.Errorf("no jsFocus before typing: %q", methods(calls))
		}

		if strings.Contains(e.logs.String(), canary) {
			t.Error("the typed value reached the logger")
		}
		if got := sec.Expose(); got != canary {
			t.Error("TypeSecret wiped or changed the caller's secret")
		}
		// Wiped where feasible: the request buffer the client handed to
		// the transport no longer holds the value.
		if bytes.Contains(ins[0].alias, []byte(canary)) {
			t.Error("the encoded Input.insertText request still holds the value after TypeSecret returned")
		}
	})

	t.Run("failures never echo the value", func(t *testing.T) {
		t.Parallel()
		canary := testsecrets.Canary(t, testsecrets.Password)
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.setElem("#password", fakeElem{visible: true})
		e.f.setOverride("Input.insertText", func(cdpCall) any { return &cdpErr{code: -32000} })
		err := e.p.TypeSecret(testCtx(t), "#password", secret.FromString(canary))
		if err == nil {
			t.Fatal("TypeSecret = nil, want the insertText failure")
		}
		if strings.Contains(err.Error(), canary) || strings.Contains(fmt.Sprintf("%+v %#v", err, err), canary) {
			t.Error("error echoes the value")
		}
		if strings.Contains(e.logs.String(), canary) {
			t.Error("the value reached the logger")
		}
	})

	t.Run("missing or hidden input: nothing typed", func(t *testing.T) {
		t.Parallel()
		canary := testsecrets.Canary(t, testsecrets.Password)
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.setElem("#hidden", fakeElem{visible: false})
		for _, sel := range []string{"#hidden", "#missing"} {
			m := e.f.mark()
			err := e.p.TypeSecret(testCtx(t), sel, secret.FromString(canary))
			if !errors.Is(err, browser.ErrNotVisible) {
				t.Errorf("TypeSecret(%s) = %v, want ErrNotVisible", sel, err)
			}
			if i := index(e.f.since(m), "Input.insertText"); i >= 0 {
				t.Errorf("TypeSecret(%s) typed into a missing or hidden input", sel)
			}
		}
	})

	t.Run("empty secret refused", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.setElem("#password", fakeElem{visible: true})
		for _, sec := range []secret.Secret{{}, secret.FromString("")} {
			m := e.f.mark()
			if err := e.p.TypeSecret(testCtx(t), "#password", sec); !errors.Is(err, browser.ErrTypeRefused) {
				t.Errorf("TypeSecret(empty) = %v, want ErrTypeRefused", err)
			}
			if i := index(e.f.since(m), "Input.insertText"); i >= 0 {
				t.Error("an empty secret was typed")
			}
		}
	})
}

// assertTypeRefused types a canary into #password after setup and checks
// the refusal: ErrTypeRefused, no Input.insertText, the value in no
// message, error or log.
func assertTypeRefused(t *testing.T, setup func(e *pageEnv)) {
	t.Helper()
	canary := testsecrets.Canary(t, testsecrets.Password)
	e := newPage(t)
	e.navigate(t, loginURL)
	e.f.setElem("#password", fakeElem{visible: true})
	setup(e)
	m := e.f.mark()
	err := e.p.TypeSecret(testCtx(t), "#password", secret.FromString(canary))
	if !errors.Is(err, browser.ErrTypeRefused) {
		t.Fatalf("TypeSecret = %v, want ErrTypeRefused", err)
	}
	calls := e.f.since(m)
	if i := index(calls, "Input.insertText"); i >= 0 {
		t.Errorf("Input.insertText sent despite the refusal: %q", methods(calls))
	}
	if len(funcCalls(calls, browser.JSActiveCheck)) == 0 {
		t.Errorf("refused without the jsActiveCheck pre-typing check: %q", methods(calls))
	}
	for _, c := range calls {
		if strings.Contains(c.Raw, canary) {
			t.Errorf("%s carries the value although typing was refused", c.Method)
		}
	}
	if strings.Contains(err.Error(), canary) || strings.Contains(e.logs.String(), canary) {
		t.Error("the value leaked into the error or the logs")
	}
}

func TestPage_TypeSecretRefusesWhenFocusInCrossOriginFrame(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, focus string }{
		{"iframe holds the focus", "iframe"},
		{"focus moved to another input", "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertTypeRefused(t, func(e *pageEnv) { e.f.setFocus(tc.focus) })
		})
	}
}

func TestPage_TypeSecretRefusesAfterNavigationOffAllowlist(t *testing.T) {
	t.Parallel()
	for _, u := range []string{
		"https://evil.example/login",
		"https://login.supplier.example.evil.example/login",
		"https://192.0.2.10/login",
		"https://login.supplier.example:8443/login",
	} {
		t.Run(u, func(t *testing.T) {
			t.Parallel()
			// The site redirected after Navigate: the page check must
			// read the origin again just before typing.
			assertTypeRefused(t, func(e *pageEnv) { e.f.setURL(u) })
		})
	}
}

func TestPage_TypeSecretRefusesNonHTTPSOrigin(t *testing.T) {
	t.Parallel()
	for _, u := range []string{
		"http://login.supplier.example/login",
		"data:text/html,<input id=password>",
		"about:blank",
		"file:///tmp/login.html",
	} {
		t.Run(u, func(t *testing.T) {
			t.Parallel()
			assertTypeRefused(t, func(e *pageEnv) { e.f.setURL(u) })
		})
	}
}

// --- cookies ----------------------------------------------------------

func TestCookies_FilteredToAllowlistAsSecrets(t *testing.T) {
	t.Parallel()
	const expiry = 1893456000 // 2030-01-01T00:00:00Z
	sid := testsecrets.Canary(t, testsecrets.Cookie)
	pref := testsecrets.Canary(t, testsecrets.Cookie)
	api := testsecrets.Canary(t, testsecrets.Cookie)
	off := testsecrets.Canary(t, testsecrets.Cookie)

	cookie := func(name, value, domain string, expires float64, session bool) map[string]any {
		return map[string]any{
			"name": name, "value": value, "domain": domain, "path": "/",
			"expires": expires, "size": len(name) + len(value),
			"httpOnly": true, "secure": true, "session": session, "sameSite": "Lax",
		}
	}
	jar := []map[string]any{
		cookie("sid", sid, "login.supplier.example", expiry, false),
		cookie("pref", pref, ".supplier.example", -1, true),
		cookie("api", api, "api.supplier.example", expiry, false),
		cookie("trk", off, ".tracker.example", expiry, false),
		cookie("evil", off, "supplier.example.evil.example", expiry, false),
		cookie("ip", off, "192.0.2.10", expiry, false),
		cookie("lh", off, "localhost", expiry, false),
		cookie("nodomain", off, "", expiry, false),
		cookie("dotonly", off, ".", expiry, false),
		cookie("public", off, ".example", expiry, false),
	}
	want := map[string]struct {
		value   string
		expires time.Time
	}{
		"sid":  {sid, time.Unix(expiry, 0).UTC()},
		"pref": {pref, time.Time{}},
		"api":  {api, time.Unix(expiry, 0).UTC()},
	}

	t.Run("allowlisted cookies only, values as secrets", func(t *testing.T) {
		t.Parallel()
		for _, domains := range [][]string{nil, testAllow, append(slices.Clone(testAllow), "tracker.example", "*.tracker.example")} {
			e := newPage(t)
			e.navigate(t, loginURL)
			e.f.setCookies(jar)
			got, err := e.p.Cookies(testCtx(t), domains)
			if err != nil {
				t.Fatalf("Cookies(%q) = %v", domains, err)
			}
			names := map[string]bool{}
			for _, c := range got {
				names[c.Name] = true
				w, ok := want[c.Name]
				if !ok {
					t.Errorf("Cookies(%q) returned %q on %q: off the allowlist", domains, c.Name, c.Domain)
					continue
				}
				if c.Value.Expose() != w.value {
					t.Errorf("cookie %s value does not round-trip through secret.Secret", c.Name)
				}
				if !c.Expires.Equal(w.expires) || (!w.expires.IsZero() && c.Expires.Location() != time.UTC) {
					t.Errorf("cookie %s Expires = %v, want %v (UTC; zero for a session cookie)", c.Name, c.Expires, w.expires)
				}
				if c.Path != "/" || !c.Secure || !c.HTTPOnly {
					t.Errorf("cookie %s attributes = path %q secure %v httpOnly %v", c.Name, c.Path, c.Secure, c.HTTPOnly)
				}
				if c.Value.Expose() == off {
					t.Errorf("an off-allowlist value was returned under %q", c.Name)
				}
			}
			for n := range want {
				if !names[n] {
					t.Errorf("Cookies(%q) dropped allowlisted cookie %q", domains, n)
				}
			}
			rendered := fmt.Sprintf("%v %+v %#v", got, got, got)
			for _, v := range []string{sid, pref, api, off} {
				if strings.Contains(rendered, v) {
					t.Error("formatting the cookies reveals a value")
				}
				if strings.Contains(e.logs.String(), v) {
					t.Error("a cookie value reached the logger")
				}
			}
		}
	})

	t.Run("requested domains narrow, never widen", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.setCookies(jar)
		got, err := e.p.Cookies(testCtx(t), []string{"api.supplier.example"})
		if err != nil {
			t.Fatalf("Cookies(api) = %v", err)
		}
		var names []string
		for _, c := range got {
			names = append(names, c.Name)
		}
		if !slices.Contains(names, "api") || slices.Contains(names, "sid") {
			t.Errorf("Cookies(api.supplier.example) names = %q, want api and not sid", names)
		}
		got, err = e.p.Cookies(testCtx(t), []string{"tracker.example", "*.tracker.example"})
		for _, c := range got {
			t.Errorf("Cookies(tracker) returned %q: the request widened the allowlist", c.Name)
		}
		_ = err // an error is acceptable here; returning tracker cookies is not
	})

	t.Run("CDP failure", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		fail := func(cdpCall) any { return &cdpErr{code: -32000} }
		e.f.setOverride("Storage.getCookies", fail)
		e.f.setOverride("Network.getCookies", fail)
		e.f.setOverride("Network.getAllCookies", fail)
		if got, err := e.p.Cookies(testCtx(t), nil); err == nil || len(got) != 0 {
			t.Errorf("Cookies = %d cookies, %v; want none and an error", len(got), err)
		}
	})
}

// --- waiting, clicking, URL -------------------------------------------

func TestWaitVisible_BoundedByContext(t *testing.T) {
	t.Parallel()

	t.Run("visible at once", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.f.setElem("#login", fakeElem{visible: true})
		if err := e.p.WaitVisible(testCtx(t), "#login"); err != nil {
			t.Fatalf("WaitVisible = %v", err)
		}
		if n := e.f.pollCount("#login"); n != 1 {
			t.Errorf("polls = %d, want 1", n)
		}
	})

	t.Run("visible on the third poll, PollWait between polls", func(t *testing.T) {
		t.Parallel()
		f, c, opts, _ := newEnv(t)
		var waits int
		var mu sync.Mutex
		opts.PollWait = func(ctx context.Context) error {
			mu.Lock()
			waits++
			mu.Unlock()
			return ctx.Err()
		}
		p, err := browser.NewPage(testCtx(t), c, opts)
		if err != nil {
			t.Fatalf("NewPage = %v", err)
		}
		t.Cleanup(func() { _ = p.Close() })
		f.setElem("#login", fakeElem{visibleAfter: 3})
		if err := p.WaitVisible(testCtx(t), "#login"); err != nil {
			t.Fatalf("WaitVisible = %v", err)
		}
		if n := f.pollCount("#login"); n != 3 {
			t.Errorf("polls = %d, want 3", n)
		}
		mu.Lock()
		defer mu.Unlock()
		if waits < 2 {
			t.Errorf("PollWait calls = %d, want one between each poll", waits)
		}
	})

	t.Run("cancelled while polling", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		ctx, cancel := context.WithCancel(testCtx(t))
		defer cancel()
		e.f.setOnVisiblePoll(func(n int) {
			if n == 3 {
				cancel()
			}
		})
		err := e.p.WaitVisible(ctx, "#never")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("WaitVisible = %v, want context.Canceled", err)
		}
	})

	t.Run("deadline with a real pause", func(t *testing.T) {
		t.Parallel()
		f, c, opts, _ := newEnv(t)
		// The deadline fires when WaitVisible first pauses between polls, not
		// after a wall-clock delay: under load a fixed 50 ms could expire
		// before the first poll completes.
		deadline := newPollDeadline(testCtx(t))
		opts.PollWait = func(ctx context.Context) error {
			deadline.expire()
			<-ctx.Done()
			return ctx.Err()
		}
		p, err := browser.NewPage(testCtx(t), c, opts)
		if err != nil {
			t.Fatalf("NewPage = %v", err)
		}
		t.Cleanup(func() { _ = p.Close() })
		ctx, cancel := context.WithCancel(deadline)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- p.WaitVisible(ctx, "#never") }()
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("WaitVisible = %v, want context.DeadlineExceeded", err)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("WaitVisible outlived its context")
		}
		if n := f.pollCount("#never"); n < 1 {
			t.Errorf("polls = %d, want at least one", n)
		}
	})

	t.Run("already cancelled: no CDP call", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		ctx, cancel := context.WithCancel(testCtx(t))
		cancel()
		m := e.f.mark()
		if err := e.p.WaitVisible(ctx, "#login"); !errors.Is(err, context.Canceled) {
			t.Errorf("WaitVisible = %v, want context.Canceled", err)
		}
		if got := e.f.since(m); len(got) != 0 {
			t.Errorf("sent %q after cancellation", methods(got))
		}
	})
}

func TestPage_ClickRequiresVisibleSelector(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		elem    *fakeElem
		wantErr error
	}{
		{"visible", &fakeElem{visible: true, x: 12.5, y: 40}, nil},
		{"hidden", &fakeElem{visible: false, x: 12.5, y: 40}, browser.ErrNotVisible},
		{"missing", nil, browser.ErrNotVisible},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newPage(t)
			e.navigate(t, loginURL)
			if tc.elem != nil {
				e.f.setElem("#submit", *tc.elem)
			}
			m := e.f.mark()
			err := e.p.Click(testCtx(t), "#submit")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Click = %v, want %v", err, tc.wantErr)
			}
			calls := e.f.since(m)
			mouse := filter(calls, "Input.dispatchMouseEvent")
			if tc.wantErr != nil {
				for _, c := range calls {
					if strings.HasPrefix(c.Method, "Input.") {
						t.Errorf("%s sent for a %s element", c.Method, tc.name)
					}
				}
				return
			}
			pressed, released := -1, -1
			for i, c := range mouse {
				typ, _ := c.Params["type"].(string)
				if typ != "mousePressed" && typ != "mouseReleased" {
					continue
				}
				if c.Params["x"] != 12.5 || c.Params["y"] != 40.0 || c.Params["button"] != "left" || c.Params["clickCount"] != 1.0 {
					t.Errorf("%s params = %v, want x 12.5 y 40 button left clickCount 1", typ, c.Params)
				}
				if typ == "mousePressed" && pressed < 0 {
					pressed = i
				}
				if typ == "mouseReleased" && released < 0 {
					released = i
				}
			}
			if pressed < 0 || released < 0 || pressed > released {
				t.Errorf("mouse events = %v, want mousePressed then mouseReleased", mouse)
			}
		})
	}
}

func TestPage_CurrentURL(t *testing.T) {
	t.Parallel()

	t.Run("navigated then redirected", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.navigate(t, loginURL)
		if got, err := e.p.CurrentURL(testCtx(t)); err != nil || got != loginURL {
			t.Errorf("CurrentURL = %q, %v; want %q", got, err, loginURL)
		}
		const redirected = "https://sso.supplier.example/authorize?step=2"
		e.f.setURL(redirected)
		if got, err := e.p.CurrentURL(testCtx(t)); err != nil || got != redirected {
			t.Errorf("CurrentURL after redirect = %q, %v; want %q", got, err, redirected)
		}
	})

	t.Run("CDP failure", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.f.setOverride("Target.getTargetInfo", func(cdpCall) any { return &cdpErr{code: -32000} })
		if got, err := e.p.CurrentURL(testCtx(t)); err == nil {
			t.Errorf("CurrentURL = %q, nil; want an error", got)
		}
	})
}

// --- selector injection -----------------------------------------------

func TestPage_SelectorInjectionRefused(t *testing.T) {
	t.Parallel()
	const marker = "INJECTMARK"
	selectors := []string{
		`#a'); window.` + marker + `=1; ('`,
		`#a"); window.` + marker + `=1; ("`,
		"#a`); window." + marker + "=1; (`",
		`#a\'); window.` + marker + `=1; //`,
		`input[name="` + marker + `"]`,
		`#a</script><script>` + marker + `</script>`,
		"#a window." + marker + "=1",
		"#a${window." + marker + "}",
	}
	consts := []string{browser.JSVisible, browser.JSCenter, browser.JSFocus, browser.JSActiveCheck}
	for i, sel := range selectors {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			canary := testsecrets.Canary(t, testsecrets.Password)
			e := newPage(t)
			e.navigate(t, loginURL)
			e.f.setElem(sel, fakeElem{visible: true, x: 1, y: 2})
			m := e.f.mark()
			ctx := testCtx(t)
			if err := e.p.WaitVisible(ctx, sel); err != nil {
				t.Errorf("WaitVisible = %v", err)
			}
			if err := e.p.Click(ctx, sel); err != nil {
				t.Errorf("Click = %v", err)
			}
			if err := e.p.TypeSecret(ctx, sel, secret.FromString(canary)); err != nil {
				t.Errorf("TypeSecret = %v", err)
			}
			calls := e.f.since(m)
			if len(filter(calls, "Runtime.callFunctionOn")) == 0 {
				t.Fatalf("no Runtime.callFunctionOn: %q", methods(calls))
			}
			for _, c := range calls {
				if expr, _ := c.Params["expression"].(string); strings.Contains(expr, marker) {
					t.Errorf("%s expression embeds the selector", c.Method)
				}
				if c.Method == "Runtime.callFunctionOn" {
					decl, _ := c.Params["functionDeclaration"].(string)
					if !slices.Contains(consts, decl) {
						t.Errorf("functionDeclaration is not one of the constant page functions (selector concatenated?)")
					}
					if got, ok := firstArg(c); !ok || got != sel {
						t.Errorf("arguments[0].value = %q, want the exact selector as a JSON value", got)
					}
					continue
				}
				if strings.Contains(c.Raw, marker) {
					t.Errorf("%s carries the selector outside callFunctionOn arguments", c.Method)
				}
			}
		})
	}
}
