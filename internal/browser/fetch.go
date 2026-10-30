package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
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
}

// watch subscribes, fail closed, the handlers of session: Fetch.requestPaused
// when fetch is set, Target.attachedToTarget and Target.detachedFromTarget
// (one queue, so a detach never overtakes its attach) when targets is set.
// Each subscription is read by one page goroutine until it closes. It
// returns false, subscribing nothing, when the page is stopping or parent
// is no longer watched (it was detached meanwhile).
func (p *Page) watch(session, parent string, fetch, targets bool) bool {
	p.subsMu.Lock()
	defer p.subsMu.Unlock()
	if p.stopped {
		return false
	}
	if _, ok := p.sessions[parent]; !ok && parent != rootParent {
		return false
	}
	w := &watched{parent: parent}
	opts := SubscribeOptions{FailClosed: true}
	if fetch {
		w.subs = append(w.subs, p.c.Subscribe("Fetch.requestPaused", session, opts))
		p.handleLocked(w.subs[len(w.subs)-1], p.onRequestPaused)
	}
	if targets {
		w.subs = append(w.subs, p.c.subscribeMethods(
			[]string{"Target.attachedToTarget", "Target.detachedFromTarget"}, session, opts))
		p.handleLocked(w.subs[len(w.subs)-1], p.onTargetEvent)
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
	RequestID string          `json:"requestId"`
	Request   json.RawMessage `json:"request"`
}

// onRequestPaused continues an allowed request as is, and fails any other
// one. Nothing of the request (path, query, headers, body) is logged.
//
// Pauses are handled serially per session, one CDP round trip each. More
// than DefaultEventBuffer requests paused at once on one session overflow
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
		URL string `json:"url"`
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

// onTargetEvent handles the attach and detach events of one session, in
// arrival order.
func (p *Page) onTargetEvent(ev Event) {
	if ev.Method == "Target.detachedFromTarget" {
		var d struct {
			SessionID string `json:"sessionId"`
		}
		if json.Unmarshal(ev.Params, &d) == nil && d.SessionID != "" {
			p.release(d.SessionID)
		}
		return
	}
	p.onAttached(ev)
}

// onAttached enforces the allowlist on an auto-attached target before it
// runs: Fetch.enable (plus setAutoAttach for pages, frames and dedicated
// workers, which can start nested targets), then
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
	nested := at.TargetInfo.Type == "page" || at.TargetInfo.Type == "iframe" || at.TargetInfo.Type == "worker"
	if !p.watch(at.SessionID, ev.SessionID, true, nested) {
		p.closeTarget(at.TargetInfo.TargetID)
		return
	}
	// Only a dedicated worker started under a watched page, frame or
	// worker session has a parent Fetch intercepting its requests.
	parentFetch := at.TargetInfo.Type == "worker" && p.interceptsChildren(ev.SessionID)
	if err := p.enableChild(at.SessionID, parentFetch, nested); err != nil {
		p.release(at.SessionID)
		p.log.Warn("browser: attached target closed: allowlist not enforceable", "error", err)
		p.closeTarget(at.TargetInfo.TargetID)
		return
	}
	ctx, cancel := p.enforceCtx()
	defer cancel()
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
// session whose attach events the page handles: the page session or a
// page, frame or worker session attached under it (only those subscribe
// to Target events, and each has Fetch enabled or inherits its parent's).
func (p *Page) interceptsChildren(session string) bool {
	if session == "" {
		return false
	}
	p.subsMu.Lock()
	defer p.subsMu.Unlock()
	_, ok := p.sessions[session]
	return ok
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
