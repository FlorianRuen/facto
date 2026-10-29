// fakeCDP is an in-memory, scripted CDP peer for the page tests (J1 T8). It
// implements browser.Transport, so NewClient talks to it directly: no
// process, no pipe, every OS. It records every request (method, session id,
// params, and an alias of the exact byte slice the client handed to Send)
// and answers from a tiny page model: one URL, a set of elements keyed by
// their exact selector, and where the focus sits.
//
// Page JavaScript is recognised by comparing Runtime.callFunctionOn's
// functionDeclaration with the constants re-exported by export_test.go
// (browser.JSVisible, JSCenter, JSFocus, JSActiveCheck). The selector is read
// from arguments[0].value only.
package browser_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// Ids handed out by the fake browser.
const (
	fakeContextID = "ctx-fake-1"
	fakeTargetID  = "tgt-fake-1"
	fakeSessionID = "sess-fake-1"
	// fakeFrameID is the main frame of the page target.
	fakeFrameID = "frame-main"
	// fakeIsolatedContextID is the execution context Page.createIsolatedWorld
	// returns; Runtime.evaluate in it hands out fakeIsolatedDocID.
	fakeIsolatedContextID = 77
	fakeIsolatedDocID     = "obj-isolated-document"
	fakeMainWorldDocID    = "obj-document"
)

type cdpCall struct {
	Method  string
	Session string
	Params  map[string]any
	Raw     string // copy of the frame at Send time
	alias   []byte // the slice the client passed to Send (not copied)
}

type fakeElem struct {
	visible bool
	x, y    float64
	// visibleAfter: when > 0, the element turns visible on that JSVisible
	// poll (1-based).
	visibleAfter int
}

type cdpErr struct{ code int64 }

// fakeCDP implements browser.Transport.
type fakeCDP struct {
	t *testing.T

	mu    sync.Mutex
	calls []cdpCall
	url   string
	elems map[string]*fakeElem
	polls map[string]int // JSVisible calls per selector
	// focus: "" (the element focused by JSFocus), "iframe" (an iframe
	// holds the focus), "other" (another input holds it).
	focus   string
	focused string // selector focused by the last JSFocus
	cookies []map[string]any
	// frameURL, when set, is the main frame URL Page.getFrameTree reports
	// instead of url: the browser-side truth a page script cannot spoof.
	frameURL string
	// override answers a method instead of the model. A non-nil *cdpErr
	// result becomes a CDP error object.
	override map[string]func(c cdpCall) any
	// onVisiblePoll runs (without the lock) after each JSVisible answer.
	onVisiblePoll func(n int)

	out       chan []byte
	closeOnce sync.Once
	closed    chan struct{}
}

var _ browser.Transport = (*fakeCDP)(nil)

func newFakeCDP(t *testing.T) *fakeCDP {
	t.Helper()
	return &fakeCDP{
		t:        t,
		url:      "about:blank",
		elems:    map[string]*fakeElem{},
		polls:    map[string]int{},
		override: map[string]func(c cdpCall) any{},
		out:      make(chan []byte, 1024),
		closed:   make(chan struct{}),
	}
}

func (f *fakeCDP) Send(msg []byte) error {
	var req struct {
		ID        int64          `json:"id"`
		Method    string         `json:"method"`
		SessionID string         `json:"sessionId"`
		Params    map[string]any `json:"params"`
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		f.t.Errorf("fake cdp: request is not JSON")
		return fmt.Errorf("%w: fake", browser.ErrBadFrame)
	}
	call := cdpCall{Method: req.Method, Session: req.SessionID, Params: req.Params, Raw: string(msg), alias: msg}
	if call.Params == nil {
		call.Params = map[string]any{}
	}
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()

	result, hook := f.answer(call)
	resp := map[string]any{"id": req.ID}
	if req.SessionID != "" {
		resp["sessionId"] = req.SessionID
	}
	if e, ok := result.(*cdpErr); ok {
		resp["error"] = map[string]any{"code": e.code, "message": "scripted failure"}
	} else {
		if result == nil {
			result = map[string]any{}
		}
		resp["result"] = result
	}
	b, err := json.Marshal(resp)
	if err != nil {
		f.t.Errorf("fake cdp: marshal response: %v", err)
		return nil
	}
	select {
	case f.out <- b:
	case <-f.closed:
	}
	if hook != nil {
		hook()
	}
	return nil
}

func (f *fakeCDP) Recv() ([]byte, error) {
	select {
	case b := <-f.out:
		return b, nil
	case <-f.closed:
		return nil, fmt.Errorf("%w: fake closed", browser.ErrBrowserGone)
	}
}

func (f *fakeCDP) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

// pageSessionMethod reports whether method must run on the page session.
func pageSessionMethod(m string) bool {
	for _, p := range []string{"Page.", "Runtime.", "Input.", "DOM.", "Network.", "Fetch."} {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	return false
}

func (f *fakeCDP) answer(c cdpCall) (any, func()) {
	f.mu.Lock()
	ov := f.override[c.Method]
	f.mu.Unlock()
	if ov != nil {
		return ov(c), nil
	}
	if pageSessionMethod(c.Method) && c.Session != fakeSessionID {
		f.t.Errorf("fake cdp: %s sent on session %q, want the attached page session", c.Method, c.Session)
		return &cdpErr{code: -32001}, nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	switch c.Method {
	case "Target.createBrowserContext":
		return map[string]any{"browserContextId": fakeContextID}, nil
	case "Target.createTarget":
		return map[string]any{"targetId": fakeTargetID}, nil
	case "Target.attachToTarget":
		return map[string]any{"sessionId": fakeSessionID}, nil
	case "Target.getTargetInfo":
		return map[string]any{"targetInfo": map[string]any{
			"targetId": fakeTargetID, "type": "page", "title": "", "url": f.url,
			"attached": true, "browserContextId": fakeContextID,
		}}, nil
	case "Page.navigate":
		u, _ := c.Params["url"].(string)
		f.url = u
		return map[string]any{"frameId": "frame-main", "loaderId": "loader-1"}, nil
	case "Page.getFrameTree":
		u := f.url
		if f.frameURL != "" {
			u = f.frameURL
		}
		return map[string]any{"frameTree": map[string]any{"frame": map[string]any{
			"id": fakeFrameID, "loaderId": "loader-1", "url": u, "securityOrigin": originOf(u), "mimeType": "text/html",
		}}}, nil
	case "Page.createIsolatedWorld":
		if id, _ := c.Params["frameId"].(string); id != fakeFrameID {
			f.t.Errorf("fake cdp: createIsolatedWorld frameId = %q, want %q", id, fakeFrameID)
		}
		return map[string]any{"executionContextId": fakeIsolatedContextID}, nil
	case "Runtime.evaluate":
		obj := fakeMainWorldDocID
		if id, _ := c.Params["contextId"].(float64); id == fakeIsolatedContextID {
			obj = fakeIsolatedDocID
		}
		return map[string]any{"result": map[string]any{"type": "object", "className": "HTMLDocument", "objectId": obj}}, nil
	case "Runtime.callFunctionOn":
		return f.callFunction(c)
	case "Storage.getCookies":
		if id, _ := c.Params["browserContextId"].(string); id != fakeContextID {
			f.t.Errorf("fake cdp: Storage.getCookies browserContextId = %q, want %q (never the default context)", id, fakeContextID)
		}
		return map[string]any{"cookies": f.cookies}, nil
	case "Network.getCookies", "Network.getAllCookies":
		return map[string]any{"cookies": f.cookies}, nil
	default:
		return map[string]any{}, nil
	}
}

func byValue(v any) map[string]any {
	if v == nil {
		return map[string]any{"result": map[string]any{"type": "object", "subtype": "null", "value": nil}}
	}
	typ := "object"
	if _, ok := v.(bool); ok {
		typ = "boolean"
	}
	return map[string]any{"result": map[string]any{"type": typ, "value": v}}
}

// origin returns the serialised origin of the fake's URL ("null" when
// opaque).
func (f *fakeCDP) origin() string {
	return originOf(f.url)
}

// originOf returns the serialised origin of raw ("null" when opaque).
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "null"
	}
	return u.Scheme + "://" + u.Host
}

func (f *fakeCDP) callFunction(c cdpCall) (any, func()) {
	if id, _ := c.Params["objectId"].(string); id == "" {
		f.t.Errorf("fake cdp: Runtime.callFunctionOn without objectId")
	}
	if rbv, _ := c.Params["returnByValue"].(bool); !rbv {
		f.t.Errorf("fake cdp: Runtime.callFunctionOn without returnByValue")
	}
	sel := ""
	if args, ok := c.Params["arguments"].([]any); ok && len(args) > 0 {
		if a, ok := args[0].(map[string]any); ok {
			sel, _ = a["value"].(string)
		}
	}
	decl, _ := c.Params["functionDeclaration"].(string)
	el := f.elems[sel]
	switch decl {
	case browser.JSVisible:
		f.polls[sel]++
		n := f.polls[sel]
		vis := el != nil && (el.visible || (el.visibleAfter > 0 && n >= el.visibleAfter))
		var hook func()
		if f.onVisiblePoll != nil {
			cb := f.onVisiblePoll
			hook = func() { cb(n) }
		}
		return byValue(vis), hook
	case browser.JSCenter:
		if el == nil || !el.visible {
			return byValue(nil), nil
		}
		return byValue(map[string]any{"x": el.x, "y": el.y}), nil
	case browser.JSFocus:
		if el == nil || !el.visible {
			return byValue(false), nil
		}
		f.focused = sel
		return byValue(true), nil
	case browser.JSActiveCheck:
		res := map[string]any{"origin": f.origin()}
		switch f.focus {
		case "iframe":
			res["matches"], res["activeTag"] = false, "IFRAME"
		case "other":
			res["matches"], res["activeTag"] = false, "INPUT"
		default:
			res["matches"], res["activeTag"] = f.focused == sel && sel != "", "INPUT"
		}
		return byValue(res), nil
	default:
		f.t.Errorf("fake cdp: unknown functionDeclaration (not one of the page constants)")
		return &cdpErr{code: -32602}, nil
	}
}

// --- test helpers -----------------------------------------------------

func (f *fakeCDP) setURL(u string) {
	f.mu.Lock()
	f.url = u
	f.mu.Unlock()
}

// setFrameURL makes Page.getFrameTree report u while the page scripts keep
// answering from the model URL.
func (f *fakeCDP) setFrameURL(u string) {
	f.mu.Lock()
	f.frameURL = u
	f.mu.Unlock()
}

func (f *fakeCDP) setElem(sel string, e fakeElem) {
	f.mu.Lock()
	f.elems[sel] = &e
	f.mu.Unlock()
}

func (f *fakeCDP) setFocus(where string) {
	f.mu.Lock()
	f.focus = where
	f.mu.Unlock()
}

func (f *fakeCDP) setCookies(c []map[string]any) {
	f.mu.Lock()
	f.cookies = c
	f.mu.Unlock()
}

func (f *fakeCDP) setOverride(method string, fn func(c cdpCall) any) {
	f.mu.Lock()
	f.override[method] = fn
	f.mu.Unlock()
}

func (f *fakeCDP) setOnVisiblePoll(fn func(n int)) {
	f.mu.Lock()
	f.onVisiblePoll = fn
	f.mu.Unlock()
}

func (f *fakeCDP) pollCount(sel string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.polls[sel]
}

// snapshot returns a copy of the calls recorded so far.
func (f *fakeCDP) snapshot() []cdpCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]cdpCall(nil), f.calls...)
}

// mark returns the number of calls so far, to slice later calls with since.
func (f *fakeCDP) mark() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeCDP) since(n int) []cdpCall {
	return f.snapshot()[n:]
}

func methods(calls []cdpCall) []string {
	out := make([]string, len(calls))
	for i, c := range calls {
		out[i] = c.Method
	}
	return out
}

// index returns the position of the first call to method, or -1.
func index(calls []cdpCall, method string) int {
	for i, c := range calls {
		if c.Method == method {
			return i
		}
	}
	return -1
}

func filter(calls []cdpCall, method string) []cdpCall {
	var out []cdpCall
	for _, c := range calls {
		if c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

// funcCalls returns the Runtime.callFunctionOn calls whose declaration is
// decl.
func funcCalls(calls []cdpCall, decl string) []cdpCall {
	var out []cdpCall
	for _, c := range calls {
		if d, _ := c.Params["functionDeclaration"].(string); c.Method == "Runtime.callFunctionOn" && d == decl {
			out = append(out, c)
		}
	}
	return out
}

func firstArg(c cdpCall) (string, bool) {
	args, ok := c.Params["arguments"].([]any)
	if !ok || len(args) == 0 {
		return "", false
	}
	a, ok := args[0].(map[string]any)
	if !ok {
		return "", false
	}
	s, ok := a["value"].(string)
	return s, ok
}
