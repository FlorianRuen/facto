package browser_test

import (
	"slices"
	"testing"
)

// cdpMethodNotFound is the JSON-RPC "method not found" code Chrome answers
// Fetch.enable with on dedicated-worker sessions (Chrome 156).
const cdpMethodNotFound = -32601

// TestFetch_WorkerWithoutFetchRelyOnParent (J1 T13, ADR 0008 Hardening
// #5): Chrome has no Fetch domain on dedicated-worker sessions and answers
// Fetch.enable with -32601; their network requests are intercepted by the
// parent page session's Fetch. For a "worker" target only, that answer is
// not a failure: setAutoAttach is still sent (nested workers stay paused
// until handled; a -32601 there is tolerated too), then the worker is
// resumed and the page keeps failing off-allowlist requests. This holds
// only for a worker attached under a watched page, frame or worker
// session; on the browser session, any other error, and -32601 on any
// other target type, the target is closed and never resumed.
func TestFetch_WorkerWithoutFetchRelyOnParent(t *testing.T) {
	t.Parallel()
	const child, target = "sess-worker-1", "tgt-worker-1"
	tests := []struct {
		name       string
		typ        string
		browser    bool  // attached on the browser session "" instead of the page session
		fetchCode  int64 // Fetch.enable error on the child; 0 = success
		attachCode int64 // Target.setAutoAttach error on the child; 0 = success
		wantResume bool
	}{
		{name: "worker without Fetch, auto-attach ok", typ: "worker", fetchCode: cdpMethodNotFound, wantResume: true},
		{name: "worker without Fetch nor auto-attach", typ: "worker", fetchCode: cdpMethodNotFound, attachCode: cdpMethodNotFound, wantResume: true},
		{name: "worker without Fetch, auto-attach fails otherwise", typ: "worker", fetchCode: cdpMethodNotFound, attachCode: -32000},
		{name: "worker with Fetch, auto-attach not found", typ: "worker", attachCode: cdpMethodNotFound},
		{name: "worker, Fetch.enable other error", typ: "worker", fetchCode: -32602},
		{name: "iframe without Fetch", typ: "iframe", fetchCode: cdpMethodNotFound},
		{name: "service worker without Fetch", typ: "service_worker", fetchCode: cdpMethodNotFound},
		{name: "shared worker without Fetch", typ: "shared_worker", fetchCode: cdpMethodNotFound},
		// No watched page, frame or worker session above it, so no parent
		// Fetch intercepts its requests: fail closed.
		{name: "worker without Fetch on the browser session", typ: "worker", browser: true, fetchCode: cdpMethodNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newPage(t)
			e.navigate(t, loginURL)
			onChild := func(code int64) func(c cdpCall) any {
				return func(c cdpCall) any {
					if c.Session == child && code != 0 {
						return &cdpErr{code: code}
					}
					return map[string]any{}
				}
			}
			e.f.setOverride("Fetch.enable", onChild(tt.fetchCode))
			e.f.setOverride("Target.setAutoAttach", onChild(tt.attachCode))
			parent := fakeSessionID
			if tt.browser {
				parent = "" // in the login context (attachChild sets it)
			}
			e.f.attachChild(parent, child, target, tt.typ, nil)

			if tt.wantResume {
				e.f.waitCalls(t, 1, isCall("Runtime.runIfWaitingForDebugger", child, ""))
				calls := e.f.snapshot()
				iAuto := slices.IndexFunc(calls, func(c cdpCall) bool { return autoAttachFlags(c) && c.Session == child })
				iResume := slices.IndexFunc(calls, func(c cdpCall) bool {
					return c.Method == "Runtime.runIfWaitingForDebugger" && c.Session == child
				})
				if iAuto < 0 || iAuto > iResume {
					t.Errorf("no Target.setAutoAttach on the worker before resume: %q", methods(calls))
				}
				for _, c := range filter(calls, "Target.closeTarget") {
					if c.Params["targetId"] == target {
						t.Error("worker closed although its requests are intercepted by the page session")
					}
				}
				// The page session (which intercepts the worker's
				// requests) still fails off-allowlist URLs.
				e.f.requestPaused(fakeSessionID, "w-1", "https://evil.test/from-worker", "Fetch", nil)
				blocked(t, e.f, fakeSessionID, "w-1")
				neverContinued(t, e.f, fakeSessionID, "w-1")
				if e.p.BlockedHosts()["evil.test"] != 1 {
					t.Errorf("BlockedHosts = %v, want the worker's request counted", e.p.BlockedHosts())
				}
				return
			}
			closed := e.f.waitCalls(t, 1, func(c cdpCall) bool {
				return c.Method == "Target.closeTarget" && c.Params["targetId"] == target
			})
			if s := closed[0].Session; s != "" {
				t.Errorf("closeTarget sent on session %q, want the browser session", s)
			}
			for _, c := range filter(e.f.snapshot(), "Runtime.runIfWaitingForDebugger") {
				if c.Session == child {
					t.Errorf("%s resumed although the allowlist is not enforceable on it", tt.typ)
				}
			}
		})
	}
}
