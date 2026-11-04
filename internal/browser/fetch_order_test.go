package browser_test

import (
	"slices"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// holdFetchEnable makes the fake browser's answer to Fetch.enable on
// session wait until the returned function is called.
func holdFetchEnable(f *fakeCDP, sessions ...string) map[string]func() {
	gates := map[string]chan struct{}{}
	release := map[string]func(){}
	for _, s := range sessions {
		ch := make(chan struct{})
		gates[s] = ch
		var once sync.Once
		release[s] = func() { once.Do(func() { close(ch) }) }
	}
	f.setIntercept("Fetch.enable", func(c cdpCall) any {
		if ch, ok := gates[c.Session]; ok {
			select {
			case <-ch:
			case <-f.closed:
			}
		}
		return nil // the model answers
	})
	return release
}

// TestFetch_SessionEventsHandledInArrivalOrder (flake of
// TestAttack_ChildAttachingOnDetachedParentClosedNeverResumed): every event
// the page enforces on one session (Fetch.requestPaused,
// Target.attachedToTarget, Target.detachedFromTarget) is handled in
// arrival order, on one queue. A pause that arrives after a detach is
// answered only once that detach took effect, so a child attached under
// the detached session and still queued behind it is closed, never
// resumed.
//
// The losing interleaving is forced: an earlier attach on the page
// session is held, so the frame's detach cannot be handled yet when the
// later pause arrives. With one queue per method, the pause was answered
// at once, before the held attach and the detach, and the attack test's
// barrier proved nothing.
func TestFetch_SessionEventsHandledInArrivalOrder(t *testing.T) {
	t.Parallel()
	const (
		frame, x, w1, w2 = "sess-o-frame", "sess-o-x", "sess-o-w1", "sess-o-w2"
	)
	e := newPage(t)
	e.navigate(t, loginURL)
	release := holdFetchEnable(e.f, x, w1)
	defer func() {
		for _, r := range release {
			r()
		}
	}()

	e.f.attachChild(fakeSessionID, frame, "tgt-o-frame", "iframe", nil)
	e.f.waitCalls(t, 1, isCall("Runtime.runIfWaitingForDebugger", frame, ""))

	// The page session's handler is busy on x.
	e.f.attachChild(fakeSessionID, x, "tgt-o-x", "iframe", nil)
	e.f.waitCalls(t, 1, isCall("Fetch.enable", x, ""))
	// The frame's handler is busy on w1, w2 is queued behind it.
	e.f.attachChild(frame, w1, "tgt-o-w1", "worker", nil)
	e.f.waitCalls(t, 1, isCall("Fetch.enable", w1, ""))
	e.f.attachChild(frame, w2, "tgt-o-w2", "worker", nil)

	// The test's own subscription proves the barrier was queued for the
	// page too (one dispatch serves every subscriber).
	seen := e.c.Subscribe("Fetch.requestPaused", fakeSessionID, browser.SubscribeOptions{})
	defer seen.Close()
	e.f.emit(fakeSessionID, "Target.detachedFromTarget", map[string]any{"sessionId": frame, "targetId": "tgt-o-frame"})
	e.f.requestPaused(fakeSessionID, "barrier", "https://login.supplier.example/ok", "XHR", nil)
	select {
	case <-seen.C():
	case <-testCtx(t).Done():
		t.Fatal("barrier never dispatched")
	}

	release[x]()
	continued(t, e.f, fakeSessionID, "barrier")
	calls := e.f.snapshot()
	iResumeX := slices.IndexFunc(calls, isCall("Runtime.runIfWaitingForDebugger", x, ""))
	iBarrier := slices.IndexFunc(calls, isCall("Fetch.continueRequest", fakeSessionID, "barrier"))
	if iResumeX < 0 || iBarrier < iResumeX {
		t.Fatalf("pause answered (%d) before the earlier attach on the same session was handled (%d): %q",
			iBarrier, iResumeX, methods(calls))
	}

	release[w1]()
	closed := e.f.waitCalls(t, 1, func(c cdpCall) bool {
		return c.Method == "Target.closeTarget" && c.Params["targetId"] == "tgt-o-w2"
	})
	if s := closed[0].Session; s != "" {
		t.Errorf("closeTarget sent on session %q, want the browser session", s)
	}
	for _, c := range e.f.snapshot() {
		if c.Session == w2 && c.Method == "Runtime.runIfWaitingForDebugger" {
			t.Error("child of a detached parent resumed")
		}
	}
}
