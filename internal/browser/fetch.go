package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
)

// In-browser allowlist (ADR 0008 "Hardening / In-browser allowlist", A11).
// Every request of the login page, of its frames and workers and of its
// pop-ups is paused by Fetch and continued only when the page allowlist
// allows its URL; anything else fails with BlockedByClient. Auto-attached
// targets start paused and are resumed only once Fetch is enabled on them;
// a target that cannot be enforced is closed.

const (
	// enforceCallTimeout bounds each Fetch/Target call the enforcement
	// makes. A request that is never answered stays paused (never let
	// through).
	enforceCallTimeout = 10 * time.Second
	// maxBlockedHosts caps the distinct hosts BlockedHosts tracks; later
	// new hosts are counted under "".
	maxBlockedHosts = 256
	// maxHostLen is the longest host name kept as a BlockedHosts key.
	maxHostLen = 253
	// blockedReason is Fetch.failRequest's errorReason.
	blockedReason = "BlockedByClient"
)

// autoAttachParams are the Target.setAutoAttach params: every new target
// starts paused until its Fetch interception is on.
var autoAttachParams = map[string]any{"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}

// fetchEnableParams intercept every URL at the request stage.
var fetchEnableParams = map[string]any{"patterns": []map[string]any{{"urlPattern": "*"}}}

// BlockedHosts returns a copy of the number of requests failed by the
// in-browser allowlist, per lowercased host (no scheme, port, path, query
// or fragment). Requests without a parsable host are counted under "".
func (p *Page) BlockedHosts() map[string]int {
	p.blockedMu.Lock()
	defer p.blockedMu.Unlock()
	return maps.Clone(p.blocked)
}

// rootParent is the parent of the sessions NewPage watches (the browser
// session and the page session): they are never released by a detach.
const rootParent = "\x00root"

// watched is one session the page enforces on: its subscriptions and the
// session it was attached to.
type watched struct {
	parent string
	subs   []*Subscription
	typ    string // targetInfo.type ("" for the root sessions)
}

// watch subscribes, fail closed, the handlers of session on ONE queue read
// by one page goroutine until it closes: Fetch.requestPaused when fetch is
// set, Target.attachedToTarget and Target.detachedFromTarget when targets
// is set. Every event of a session is thus handled in arrival order,
// whatever its method: a detach never overtakes its attach, and an event
// that arrives after a detach is handled only once that detach took effect
// (with a queue per method, a later pause could be answered while an
// earlier detach was still waiting behind a slow attach). It returns false,
// subscribing nothing, when the page is stopping or parent is no longer
// watched (it was detached meanwhile).
func (p *Page) watch(session, parent string, fetch, targets bool, typ string) bool {
	p.subsMu.Lock()
	defer p.subsMu.Unlock()
	if p.stopped {
		return false
	}
	if _, ok := p.sessions[parent]; !ok && parent != rootParent {
		return false
	}
	w := &watched{parent: parent, typ: typ}
	var methods []string
	if fetch {
		methods = append(methods, "Fetch.requestPaused")
	}
	if targets {
		methods = append(methods, "Target.attachedToTarget", "Target.detachedFromTarget")
	}
	if len(methods) > 0 {
		sub := p.c.subscribeMethods(methods, session, SubscribeOptions{FailClosed: true})
		w.subs = append(w.subs, sub)
		p.handleLocked(sub, p.onSessionEvent)
	}
	p.sessions[session] = w
	p.notifyLocked()
	return true
}

// handleLocked runs fn for each event of s in a page goroutine; subsMu is
// held (stop cannot be waiting yet).
func (p *Page) handleLocked(s *Subscription, fn func(ev Event)) {
	p.running++
	p.wg.Go(func() {
		defer func() {
			p.subsMu.Lock()
			p.running--
			p.notifyLocked()
			p.subsMu.Unlock()
		}()
		for ev := range s.C() {
			fn(ev)
		}
	})
}

// notifyLocked wakes the waiters on the bookkeeping; subsMu is held.
func (p *Page) notifyLocked() {
	close(p.subsChanged)
	p.subsChanged = make(chan struct{})
}

// subCount is the number of open page subscriptions; subsMu is held.
func (p *Page) subCount() int {
	n := 0
	for _, w := range p.sessions {
		n += len(w.subs)
	}
	return n
}

// release closes the subscriptions of session and of every session
// attached under it. Root sessions are never released.
func (p *Page) release(session string) {
	p.subsMu.Lock()
	defer p.subsMu.Unlock()
	w, ok := p.sessions[session]
	if !ok || w.parent == rootParent {
		return
	}
	todo := []string{session}
	for len(todo) > 0 {
		s := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if w, ok := p.sessions[s]; ok {
			for _, sub := range w.subs {
				sub.Close()
			}
			delete(p.sessions, s)
		}
		for id, w := range p.sessions {
			if w.parent == s {
				todo = append(todo, id)
			}
		}
	}
	p.notifyLocked()
}

// stop closes the page's subscriptions, cancels its calls and waits for
// its handlers.
func (p *Page) stop() {
	p.subsMu.Lock()
	p.stopped = true
	for _, sub := range p.taps {
		sub.Close()
	}
	p.taps = nil
	for id, w := range p.sessions {
		for _, sub := range w.subs {
			sub.Close()
		}
		delete(p.sessions, id)
	}
	p.notifyLocked()
	p.subsMu.Unlock()
	p.cancel()
	p.wg.Wait()
}

// enforceCtx is the context of one enforcement call.
func (p *Page) enforceCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(p.bg, enforceCallTimeout)
}

// pausedRequest is the part of Fetch.requestPaused the page reads.
type pausedRequest struct {
	RequestID    string          `json:"requestId"`
	Request      json.RawMessage `json:"request"`
	ResourceType string          `json:"resourceType"`
}

// onRequestPaused continues an allowed request as is, and fails any other
// one. Nothing of the request (path, query, headers, body) is logged.
//
// Pauses are handled serially per session, one CDP round trip each, in
// arrival order with that session's target events. More than
// DefaultEventBuffer events queued at once on one session overflow
// its fail-closed queue: the client dies and every request fails. That is
// by design: a dropped pause would leave a request neither failed nor
// continued, and a login page has no business sending that many at once.
func (p *Page) onRequestPaused(ev Event) {
	var pr pausedRequest
	if json.Unmarshal(ev.Params, &pr) != nil || pr.RequestID == "" {
		// Nothing to continue nor fail: the request stays paused.
		p.log.Warn("browser: undecodable paused request left paused")
		return
	}
	var req struct {
		URL     string            `json:"url"`
		Method  string            `json:"method"`
		Headers map[string]string `json:"headers"`
	}
	rawURL := ""
	if len(pr.Request) > 0 && json.Unmarshal(pr.Request, &req) == nil {
		rawURL = req.URL
	}
	ctx, cancel := p.enforceCtx()
	defer cancel()
	if p.requestAllowed(rawURL) {
		if _, err := p.c.Call(ctx, ev.SessionID, "Fetch.continueRequest", map[string]any{"requestId": pr.RequestID}); err != nil {
			p.log.Debug("browser: continue request failed", "error", err)
		}
		return
	}
	if i := p.staticEntry(rawURL, req.Method, pr.ResourceType); i >= 0 {
		// Downloaded on facto's side off this session's queue: a slow
		// static file must not hold the page's other requests.
		p.fulfillStatic(ev.SessionID, pr.RequestID, i, req.Method, rawURL, req.Headers)
		return
	}
	p.countBlocked(blockedHost(rawURL))
	p.log.Debug("browser: request blocked by the allowlist")
	if _, err := p.c.Call(ctx, ev.SessionID, "Fetch.failRequest", map[string]any{
		"requestId": pr.RequestID, "errorReason": blockedReason,
	}); err != nil {
		p.log.Debug("browser: fail request failed", "error", err)
	}
}

// requestAllowed applies the in-browser rules: the URL parses, scheme
// https, no userinfo, not an IP literal, and the page allowlist allows its
// host (httpx.Allowlist.Allows: port 443 only).
func (p *Page) requestAllowed(raw string) bool {
	if hasUnsafeChar(raw) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.Host == "" || u.User != nil ||
		strings.Contains(u.Host, "%") || strings.HasPrefix(u.Host, "[") {
		return false
	}
	if _, err := netip.ParseAddr(u.Hostname()); err == nil {
		return false
	}
	return p.allow.Allows(u.Host)
}

// staticEntry is the index of the static entry a subresource may be
// served from, or -1. Never a document, never a WebSocket.
func (p *Page) staticEntry(raw, method, resourceType string) int {
	switch resourceType {
	case "Document", "WebSocket", "":
		return -1
	}
	return p.static.match(raw, method)
}

// hasUnsafeChar reports a control character, a space or a backslash.
func hasUnsafeChar(raw string) bool {
	for i := range len(raw) {
		if c := raw[i]; c <= ' ' || c == 0x7f || c == '\\' {
			return true
		}
	}
	return false
}

// blockedHost is the BlockedHosts key of raw: its lowercased host, or ""
// when there is none to name.
func blockedHost(raw string) string {
	if hasUnsafeChar(raw) {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	if len(h) > maxHostLen || strings.ContainsAny(h, "/?#@%") {
		return ""
	}
	return h
}

func (p *Page) countBlocked(host string) {
	p.blockedMu.Lock()
	defer p.blockedMu.Unlock()
	if _, ok := p.blocked[host]; !ok && len(p.blocked) >= maxBlockedHosts {
		host = ""
	}
	p.blocked[host]++
}

// attachedTarget is the part of Target.attachedToTarget the page reads.
type attachedTarget struct {
	SessionID          string `json:"sessionId"`
	WaitingForDebugger bool   `json:"waitingForDebugger"`
	TargetInfo         struct {
		TargetID         string `json:"targetId"`
		Type             string `json:"type"`
		BrowserContextID string `json:"browserContextId"`
	} `json:"targetInfo"`
}

// onSessionEvent handles the events of one session, in arrival order.
func (p *Page) onSessionEvent(ev Event) {
	switch ev.Method {
	case "Fetch.requestPaused":
		p.onRequestPaused(ev)
	case "Target.detachedFromTarget":
		var d struct {
			SessionID string `json:"sessionId"`
		}
		if json.Unmarshal(ev.Params, &d) == nil && d.SessionID != "" {
			p.release(d.SessionID)
		}
	default:
		p.onAttached(ev)
	}
}

// onAttached enforces the allowlist on an auto-attached target before it
// runs: Fetch.enable (plus setAutoAttach for pages, frames, dedicated and
// shared workers, which can start nested targets), then
// Runtime.runIfWaitingForDebugger. On failure the target is closed and
// never resumed. A target that is already running (not waiting for the
// debugger) may have sent requests unchecked: it is closed, unless it is
// the page's own target re-reported by the browser-level auto-attach. On
// the browser session only targets of the login context are handled;
// others are left alone (paused).
func (p *Page) onAttached(ev Event) {
	var at attachedTarget
	if json.Unmarshal(ev.Params, &at) != nil || at.SessionID == "" {
		p.log.Warn("browser: undecodable attached target left paused")
		return
	}
	if ev.SessionID == "" && at.TargetInfo.BrowserContextID != p.contextID {
		return
	}
	if !at.WaitingForDebugger && at.TargetInfo.TargetID != p.targetID {
		p.log.Warn("browser: attached target closed: already running")
		p.closeTarget(at.TargetInfo.TargetID)
		return
	}
	typ := at.TargetInfo.Type
	// Every target that can start nested targets gets setAutoAttach before
	// it runs, shared workers included (J1 T27): their nested workers start
	// paused too.
	nested := typ == "page" || typ == "iframe" || typ == "worker" || typ == "shared_worker"
	frame := typ == "iframe"
	if !p.watch(at.SessionID, ev.SessionID, true, nested, typ) {
		p.closeTarget(at.TargetInfo.TargetID)
		return
	}
	// Only a dedicated worker started under a watched page, frame or
	// worker session has a parent Fetch intercepting its requests.
	parentFetch := typ == "worker" && p.interceptsChildren(ev.SessionID)
	if err := p.enableChild(at.SessionID, parentFetch, nested); err != nil {
		p.release(at.SessionID)
		p.log.Warn("browser: attached target closed: allowlist not enforceable", "error", err)
		p.closeTarget(at.TargetInfo.TargetID)
		return
	}
	ctx, cancel := p.enforceCtx()
	defer cancel()
	if frame {
		// A frame attached while a secret is being typed starts frozen.
		if err := p.freezeAttached(ctx, at.SessionID); err != nil {
			p.release(at.SessionID)
			p.log.Warn("browser: attached frame closed: page scripts not frozen while typing", "error", err)
			p.closeTarget(at.TargetInfo.TargetID)
			return
		}
	}
	if _, err := p.c.Call(ctx, at.SessionID, "Runtime.runIfWaitingForDebugger", nil); err != nil {
		p.log.Debug("browser: resume target failed", "error", err)
	}
}

// closeTarget closes targetID (browser session), best effort.
func (p *Page) closeTarget(targetID string) {
	if targetID == "" {
		return
	}
	ctx, cancel := p.enforceCtx()
	defer cancel()
	if _, err := p.c.Call(ctx, "", "Target.closeTarget", map[string]any{"targetId": targetID}); err != nil {
		p.log.Debug("browser: close target failed", "error", err)
	}
}

// interceptsChildren reports whether session is a watched, non-browser
// session whose Fetch is known to cover its dedicated workers: the page
// session or a page, frame or worker session attached under it. A shared
// worker session is not one of them: that Chrome applies its Fetch to a
// nested dedicated worker is unproven (Chrome for Testing 156 refuses
// `new Worker` there), so such a worker without its own Fetch is closed.
func (p *Page) interceptsChildren(session string) bool {
	if session == "" {
		return false
	}
	p.subsMu.Lock()
	defer p.subsMu.Unlock()
	w, ok := p.sessions[session]
	return ok && w.typ != "shared_worker"
}

// enableChild turns the interception on for an attached target.
//
// Dedicated workers are the one exception (ADR 0008 Hardening #5): Chrome
// has no Fetch domain on their sessions and answers Fetch.enable with
// "method not found", while their network requests are intercepted by the
// parent page session's Fetch. When parentFetch is set (a "worker"
// attached under a watched page, frame or worker session), that answer is
// not a failure; setAutoAttach is still sent so nested workers start
// paused, and a "method not found" to it is tolerated too. Any other
// error, and that answer anywhere else, fails closed.
func (p *Page) enableChild(session string, parentFetch, nested bool) error {
	ctx, cancel := p.enforceCtx()
	defer cancel()
	if _, err := p.c.Call(ctx, session, "Fetch.enable", fetchEnableParams); err != nil {
		if !parentFetch || !isMethodNotFound(err) {
			return fmt.Errorf("enable fetch: %w", err)
		}
		p.log.Debug("browser: dedicated worker has no Fetch domain: its requests are intercepted by the page session")
		if _, err := p.c.Call(ctx, session, "Target.setAutoAttach", autoAttachParams); err != nil && !isMethodNotFound(err) {
			return fmt.Errorf("auto attach: %w", err)
		}
		return nil
	}
	if nested {
		if _, err := p.c.Call(ctx, session, "Target.setAutoAttach", autoAttachParams); err != nil {
			return fmt.Errorf("auto attach: %w", err)
		}
	}
	return nil
}

// maxStaticInflight bounds the concurrent facto-side static downloads of
// one page.
const maxStaticInflight = 6

// maxStaticPending bounds the static requests of one page waiting for or
// in a download; more are failed at once (a page looping on fetch cannot
// pile up goroutines).
const maxStaticPending = 128

// staticFetchTimeout bounds one facto-side static download.
const staticFetchTimeout = 60 * time.Second

// staticRequestHeaders are the only request headers forwarded to a static
// host: what a CORS, range or cache request needs; never a credential
// header (cookie, authorization) nor a custom one. (Accept is CORS
// safelisted, so page-settable, like the path and query already are.)
var staticRequestHeaders = []string{"Accept", "Origin", "Range", "If-None-Match", "If-Modified-Since"}

// staticResponseHeaders are the only response headers handed back to
// Chrome: what a script, style, font or image load needs. Never
// Set-Cookie; never Content-Encoding (httpx already decoded the body).
var staticResponseHeaders = []string{
	"Content-Type", "Content-Range", "Accept-Ranges", "Cache-Control", "ETag", "Last-Modified",
	"Access-Control-Allow-Origin", "Access-Control-Expose-Headers", "Timing-Allow-Origin",
	"Cross-Origin-Resource-Policy", "X-Content-Type-Options", "Vary",
}

// fulfillStatic downloads the paused request through the entry's
// StaticGet and fulfills it, in a page goroutine; any failure fails the
// request (never continued: Chrome cannot resolve a static host). Nothing
// of the URL is logged.
func (p *Page) fulfillStatic(session, requestID string, entry int, method, rawURL string, headers map[string]string) {
	header := map[string][]string{}
	for _, allowed := range staticRequestHeaders {
		for _, k := range slices.Sorted(maps.Keys(headers)) {
			if strings.EqualFold(k, allowed) {
				header[allowed] = []string{headers[k]}
				break
			}
		}
	}
	if p.staticPending.Add(1) > maxStaticPending {
		p.staticPending.Add(-1)
		p.countBlocked(blockedHost(rawURL))
		p.log.Debug("browser: too many pending static downloads")
		ctx, cancel := p.enforceCtx()
		defer cancel()
		if _, err := p.c.Call(ctx, session, "Fetch.failRequest", map[string]any{
			"requestId": requestID, "errorReason": "Failed",
		}); err != nil {
			p.log.Debug("browser: fail request failed", "error", err)
		}
		return
	}
	p.wg.Go(func() {
		defer p.staticPending.Add(-1)
		// One slot covers the download and the hand-over to Chrome, so at
		// most maxStaticInflight bodies (and their base64 copies) are held
		// at once (SEC-J2-9).
		select {
		case p.staticSem <- struct{}{}:
			defer func() { <-p.staticSem }()
		case <-p.bg.Done():
			return
		}
		res, err := p.staticDownload(entry, method, rawURL, header)
		ctx, cancel := p.enforceCtx()
		defer cancel()
		if err != nil || res.Status < 200 || res.Status > 599 {
			p.countBlocked(blockedHost(rawURL))
			p.log.Debug("browser: static download failed", "error", err)
			if _, err := p.c.Call(ctx, session, "Fetch.failRequest", map[string]any{
				"requestId": requestID, "errorReason": "Failed",
			}); err != nil {
				p.log.Debug("browser: fail request failed", "error", err)
			}
			return
		}
		params := map[string]any{
			"requestId": requestID, "responseCode": res.Status,
			"responseHeaders": staticHeaderEntries(res.Header),
			"body":            base64.StdEncoding.EncodeToString(res.Body),
		}
		if _, err := p.c.Call(ctx, session, "Fetch.fulfillRequest", params); err != nil {
			p.log.Debug("browser: fulfill request failed", "error", err)
		}
	})
}

// staticDownload runs one bounded download; the caller holds a staticSem
// slot.
func (p *Page) staticDownload(entry int, method, rawURL string, header map[string][]string) (StaticResponse, error) {
	ctx, cancel := context.WithTimeout(p.bg, staticFetchTimeout)
	defer cancel()
	res, err := p.staticGets[entry](ctx, method, rawURL, header)
	if err != nil {
		return StaticResponse{}, err
	}
	if len(res.Body) > MaxStaticBody {
		return StaticResponse{}, errStaticTooLarge
	}
	return res, nil
}

// errStaticTooLarge reports a static download over MaxStaticBody.
var errStaticTooLarge = errors.New("browser: static download over MaxStaticBody")

// staticHeaderEntries keeps the staticResponseHeaders of h, as
// Fetch.fulfillRequest header entries in a stable order.
func staticHeaderEntries(h map[string][]string) []map[string]string {
	out := []map[string]string{}
	for _, name := range staticResponseHeaders {
		for k, vs := range h {
			if !strings.EqualFold(k, name) {
				continue
			}
			for _, v := range vs {
				if !hasCtl(v) {
					out = append(out, map[string]string{"name": name, "value": v})
				}
			}
		}
	}
	return out
}

// hasCtl reports a control character (a header value must not carry one).
func hasCtl(v string) bool {
	for i := range len(v) {
		if c := v[i]; (c < ' ' && c != '\t') || c == 0x7f {
			return true
		}
	}
	return false
}
