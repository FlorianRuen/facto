package browser_test

import (
	"slices"
	"testing"
)

// Shared workers (J1 T27, red-team finding LOW, T13 review): a
// shared_worker target gets Target.setAutoAttach {autoAttach,
// waitForDebuggerOnStart, flatten} before it is resumed, is closed
// unresumed when Chrome refuses it, and a dedicated worker it starts
// without a Fetch domain of its own is closed (no parent Fetch is known to
// cover it).
func TestFetch_SharedWorkerNestedFailClosed(t *testing.T) {
	t.Parallel()
	const shared, sharedTarget = "sess-shared", "tgt-shared"
	const nested, nestedTarget = "sess-shared-nested", "tgt-shared-nested"
	resumedOn := func(e *pageEnv, session string) bool {
		return slices.ContainsFunc(e.f.snapshot(), isCall("Runtime.runIfWaitingForDebugger", session, ""))
	}
	closedTarget := func(target string) func(c cdpCall) bool {
		return func(c cdpCall) bool { return c.Method == "Target.closeTarget" && c.Params["targetId"] == target }
	}

	t.Run("auto-attach before resume", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.attachChild("", shared, sharedTarget, "shared_worker", nil)
		e.f.waitCalls(t, 1, isCall("Runtime.runIfWaitingForDebugger", shared, ""))
		calls := e.f.snapshot()
		iAuto := slices.IndexFunc(calls, func(c cdpCall) bool { return autoAttachFlags(c) && c.Session == shared })
		iRun := slices.IndexFunc(calls, isCall("Runtime.runIfWaitingForDebugger", shared, ""))
		if iAuto < 0 || iAuto > iRun {
			t.Errorf("shared worker resumed without setAutoAttach first: %q", methods(calls))
		}
	})

	t.Run("auto-attach refused closes it", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.setOverride("Target.setAutoAttach", func(c cdpCall) any {
			if c.Session == shared {
				return &cdpErr{code: -32000}
			}
			return map[string]any{}
		})
		e.f.attachChild("", shared, sharedTarget, "shared_worker", nil)
		e.f.waitCalls(t, 1, closedTarget(sharedTarget))
		if resumedOn(e, shared) {
			t.Error("shared worker resumed although setAutoAttach failed")
		}
	})

	t.Run("nested worker without Fetch is closed", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.setOverride("Fetch.enable", func(c cdpCall) any {
			if c.Session == nested {
				return &cdpErr{code: cdpMethodNotFound}
			}
			return map[string]any{}
		})
		e.f.attachChild("", shared, sharedTarget, "shared_worker", nil)
		e.f.waitCalls(t, 1, isCall("Runtime.runIfWaitingForDebugger", shared, ""))
		e.f.attachChild(shared, nested, nestedTarget, "worker", nil)
		e.f.waitCalls(t, 1, closedTarget(nestedTarget))
		if resumedOn(e, nested) {
			t.Error("dedicated worker under a shared worker resumed without Fetch of its own")
		}
	})
}
