package browser_test

import (
	"fmt"
	"testing"
)

// TestFetch_BlockedHostsBounded: a hostile page cannot grow BlockedHosts
// without bound; hosts past the cap are counted under "".
func TestFetch_BlockedHostsBounded(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	e.navigate(t, loginURL)
	const n = 300 // over the 256-host cap
	for i := range n {
		id := fmt.Sprintf("h-%d", i)
		e.f.requestPaused(fakeSessionID, id, fmt.Sprintf("https://h%d.evil.test/", i), "Image", nil)
		blocked(t, e.f, fakeSessionID, id)
	}
	got := e.p.BlockedHosts()
	if len(got) > 257 {
		t.Errorf("BlockedHosts holds %d keys, want at most 256 hosts plus \"\"", len(got))
	}
	total := 0
	for _, v := range got {
		total += v
	}
	if total != n {
		t.Errorf("BlockedHosts total = %d, want %d (every block counted)", total, n)
	}
}

// TestFetch_AttachInOtherContextIgnored: a target of another browser
// context reported on the browser session is neither enforced nor resumed
// by this page.
func TestFetch_AttachInOtherContextIgnored(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	e.navigate(t, loginURL)
	e.f.attachChild("", "sess-foreign", "tgt-foreign", "page", map[string]any{"browserContextId": "ctx-other"})
	// Then one of ours: once it is resumed, the foreign one was handled
	// (events are processed in order on the browser session).
	e.f.attachChild("", "sess-ours", "tgt-ours", "page", nil)
	e.f.waitCalls(t, 1, isCall("Runtime.runIfWaitingForDebugger", "sess-ours", ""))
	for _, c := range e.f.snapshot() {
		if c.Session == "sess-foreign" || c.Params["targetId"] == "tgt-foreign" {
			t.Errorf("foreign-context target touched: %s on %q", c.Method, c.Session)
		}
	}
}

// TestFetch_SeveralChildrenEnforced: two targets attached at once (an
// OOPIF on the page session, a pop-up on the browser session) are each
// enforced, then resumed.
func TestFetch_SeveralChildrenEnforced(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	e.navigate(t, loginURL)
	e.f.attachChild(fakeSessionID, "sess-frame", "tgt-frame", "iframe", nil)
	e.f.attachChild("", "sess-popup", "tgt-popup", "page", map[string]any{"openerId": fakeTargetID})
	resumed := e.f.waitCalls(t, 2, func(c cdpCall) bool {
		return c.Method == "Runtime.runIfWaitingForDebugger" && (c.Session == "sess-frame" || c.Session == "sess-popup")
	})
	if len(resumed) != 2 || resumed[0].Session == resumed[1].Session {
		t.Fatalf("resumed = %q, want each child once", methods(resumed))
	}
	for _, s := range []string{"sess-frame", "sess-popup"} {
		e.f.requestPaused(s, "x-"+s, "https://evil.test/x", "Script", nil)
		blocked(t, e.f, s, "x-"+s)
	}
}

// TestFetch_RunningTargetInContextClosed: a target of the login context
// that is already running when attached (not waiting for the debugger) may
// have sent requests unchecked: it is closed, never enforced after the
// fact. The page's own target, re-reported by the browser-level
// auto-attach, is enforced on its new session.
func TestFetch_RunningTargetInContextClosed(t *testing.T) {
	t.Parallel()
	for _, parent := range []string{"", fakeSessionID} {
		t.Run("parent "+parent, func(t *testing.T) {
			t.Parallel()
			e := newPage(t)
			e.navigate(t, loginURL)
			e.f.mu.Lock()
			e.f.children["sess-running"] = true
			e.f.mu.Unlock()
			e.f.emit(parent, "Target.attachedToTarget", map[string]any{
				"sessionId": "sess-running", "waitingForDebugger": false,
				"targetInfo": map[string]any{"targetId": "tgt-running", "type": "page", "browserContextId": fakeContextID},
			})
			closed := e.f.waitCalls(t, 1, func(c cdpCall) bool {
				return c.Method == "Target.closeTarget" && c.Params["targetId"] == "tgt-running"
			})
			if closed[0].Session != "" {
				t.Errorf("closeTarget on session %q, want the browser session", closed[0].Session)
			}
			for _, c := range e.f.snapshot() {
				if c.Session == "sess-running" {
					t.Errorf("running target handled as enforceable: %s", c.Method)
				}
			}
		})
	}

	t.Run("own page target re-attached", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.mu.Lock()
		e.f.children["sess-self"] = true
		e.f.mu.Unlock()
		e.f.emit("", "Target.attachedToTarget", map[string]any{
			"sessionId": "sess-self", "waitingForDebugger": false,
			"targetInfo": map[string]any{"targetId": fakeTargetID, "type": "page", "browserContextId": fakeContextID},
		})
		e.f.waitCalls(t, 1, func(c cdpCall) bool { return fetchEnableAll(c) && c.Session == "sess-self" })
		for _, c := range filter(e.f.snapshot(), "Target.closeTarget") {
			t.Errorf("own page target closed: %v", c.Params)
		}
		e.f.requestPaused("sess-self", "self-1", "https://evil.test/", "Script", nil)
		blocked(t, e.f, "sess-self", "self-1")
	})
}

// TestFetch_DetachedChildrenReleased: a detached target's subscriptions
// and handler goroutines are released, so attach/detach churn does not
// grow the page.
func TestFetch_DetachedChildrenReleased(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	e.navigate(t, loginURL)
	baseSubs, baseRun := e.p.Handlers()
	baseClient := e.c.Subscriptions()
	const n = 20
	for i := range n {
		child, tgt := fmt.Sprintf("sess-if-%d", i), fmt.Sprintf("tgt-if-%d", i)
		e.f.attachChild(fakeSessionID, child, tgt, "iframe", nil)
		e.f.waitCalls(t, 1, isCall("Runtime.runIfWaitingForDebugger", child, ""))
		// A nested worker of the frame, detached with it.
		e.f.attachChild(child, child+"-w", tgt+"-w", "worker", nil)
		e.f.waitCalls(t, 1, isCall("Runtime.runIfWaitingForDebugger", child+"-w", ""))
		e.f.emit(fakeSessionID, "Target.detachedFromTarget", map[string]any{"sessionId": child, "targetId": tgt})
	}
	if err := e.p.WaitHandlers(testCtx(t), baseSubs, baseRun); err != nil {
		s, r := e.p.Handlers()
		t.Fatalf("after %d attach/detach: %d subscriptions, %d handlers; want %d, %d", n, s, r, baseSubs, baseRun)
	}
	if got := e.c.Subscriptions(); got != baseClient {
		t.Errorf("client subscriptions = %d, want %d", got, baseClient)
	}
	// The page still enforces.
	e.f.requestPaused(fakeSessionID, "after", "https://evil.test/", "Script", nil)
	blocked(t, e.f, fakeSessionID, "after")
}
