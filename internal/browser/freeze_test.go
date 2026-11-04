package browser_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// Script freeze around TypeSecret (J1 T27, red-team finding LOW "focus
// swap"; ADR 0008 "Secret typing"): page scripts are disabled on the page
// session and on every out-of-process frame session from the pre-typing
// check to the post-typing one, always re-enabled, and a session that
// cannot be frozen refuses the typing.

const setScripts = "Emulation.setScriptExecutionDisabled"

func scriptsCall(session string, disabled bool) func(c cdpCall) bool {
	return func(c cdpCall) bool {
		return c.Method == setScripts && c.Session == session && c.Params["value"] == disabled
	}
}

func TestPage_TypeSecretFreezesPageScripts(t *testing.T) {
	t.Parallel()
	const frame, frameTarget = "sess-oopif", "tgt-oopif"
	e := newPage(t)
	e.navigate(t, loginURL)
	e.f.setElem("#password", fakeElem{visible: true})
	e.f.attachChild(fakeSessionID, frame, frameTarget, "iframe", nil)
	e.f.waitCalls(t, 1, isCall("Runtime.runIfWaitingForDebugger", frame, ""))

	m := e.f.mark()
	if err := e.p.TypeSecret(testCtx(t), "#password", secret.FromString(testsecrets.Canary(t, testsecrets.Password))); err != nil {
		t.Fatalf("TypeSecret = %v, want nil", err)
	}
	calls := e.f.since(m)
	iIns := index(calls, "Input.insertText")
	checks := []int{}
	for i, c := range calls {
		if c.Method == "Runtime.callFunctionOn" && c.Params["functionDeclaration"] == browser.JSActiveCheck {
			checks = append(checks, i)
		}
	}
	if iIns < 0 || len(checks) < 2 {
		t.Fatalf("want a check, insertText and a check: %q", methods(calls))
	}
	for _, s := range []string{fakeSessionID, frame} {
		iOff := slices.IndexFunc(calls, scriptsCall(s, true))
		iOn := slices.IndexFunc(calls, scriptsCall(s, false))
		if iOff < 0 || iOff > checks[0] {
			t.Errorf("session %s: scripts not disabled before the pre-typing check: %q", s, methods(calls))
		}
		if iOn < 0 || iOn < checks[len(checks)-1] || iOn < iIns {
			t.Errorf("session %s: scripts not re-enabled after the post-typing check: %q", s, methods(calls))
		}
	}
	// The page's listeners hear about the change once scripts run again.
	iNotify := slices.IndexFunc(calls, func(c cdpCall) bool {
		return c.Method == "Runtime.evaluate" && c.Params["expression"] != "document"
	})
	if iNotify < 0 || iNotify < slices.IndexFunc(calls, scriptsCall(fakeSessionID, false)) {
		t.Errorf("no input notification after the unfreeze: %q", methods(calls))
	}
}

func TestPage_TypeSecretRefusedWhenScriptsCannotBeFrozen(t *testing.T) {
	t.Parallel()
	for _, failOn := range []string{"page", "frame"} {
		t.Run(failOn, func(t *testing.T) {
			t.Parallel()
			const frame, frameTarget = "sess-oopif", "tgt-oopif"
			e := newPage(t)
			e.navigate(t, loginURL)
			e.f.setElem("#password", fakeElem{visible: true})
			e.f.attachChild(fakeSessionID, frame, frameTarget, "iframe", nil)
			e.f.waitCalls(t, 1, isCall("Runtime.runIfWaitingForDebugger", frame, ""))
			bad := fakeSessionID
			if failOn == "frame" {
				bad = frame
			}
			e.f.setIntercept(setScripts, func(c cdpCall) any {
				if c.Session == bad && c.Params["value"] == true {
					return &cdpErr{code: -32000}
				}
				return nil
			})
			m := e.f.mark()
			err := e.p.TypeSecret(testCtx(t), "#password", secret.FromString(testsecrets.Canary(t, testsecrets.Password)))
			if !errors.Is(err, browser.ErrTypeRefused) {
				t.Fatalf("TypeSecret = %v, want ErrTypeRefused", err)
			}
			calls := e.f.since(m)
			if i := index(calls, "Input.insertText"); i >= 0 {
				t.Errorf("insertText sent although scripts were not frozen: %q", methods(calls))
			}
			for _, s := range []string{fakeSessionID, bad} {
				if slices.IndexFunc(calls, scriptsCall(s, false)) < 0 {
					t.Errorf("session %s: scripts not re-enabled after the refusal: %q", s, methods(calls))
				}
			}
		})
	}
}

func TestPage_TypeSecretReenablesScriptsAfterInsertFailure(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	e.navigate(t, loginURL)
	e.f.setElem("#password", fakeElem{visible: true})
	e.f.setOverride("Input.insertText", func(cdpCall) any { return &cdpErr{code: -32000} })
	m := e.f.mark()
	if err := e.p.TypeSecret(testCtx(t), "#password", secret.FromString(testsecrets.Canary(t, testsecrets.Password))); err == nil {
		t.Fatal("TypeSecret = nil, want the insertText failure")
	}
	if calls := e.f.since(m); slices.IndexFunc(calls, scriptsCall(fakeSessionID, false)) < 0 {
		t.Errorf("scripts not re-enabled after a failed insertText: %q", methods(calls))
	}
}

// TestPage_FrameAttachedDuringFreezeStartsFrozen: a frame attached while
// a secret is typed is frozen before it is resumed.
func TestPage_FrameAttachedDuringFreezeStartsFrozen(t *testing.T) {
	t.Parallel()
	const frame, frameTarget = "sess-late", "tgt-late"
	e := newPage(t)
	e.navigate(t, loginURL)
	e.f.setElem("#password", fakeElem{visible: true})
	attached := false
	e.f.setIntercept("Input.insertText", func(cdpCall) any {
		if !attached {
			attached = true
			e.f.attachChild(fakeSessionID, frame, frameTarget, "iframe", nil)
			e.f.waitCalls(t, 1, isCall("Runtime.runIfWaitingForDebugger", frame, ""))
		}
		return nil
	})
	if err := e.p.TypeSecret(testCtx(t), "#password", secret.FromString(testsecrets.Canary(t, testsecrets.Password))); err != nil {
		t.Fatalf("TypeSecret = %v, want nil", err)
	}
	calls := e.f.snapshot()
	iOff := slices.IndexFunc(calls, scriptsCall(frame, true))
	iRun := slices.IndexFunc(calls, isCall("Runtime.runIfWaitingForDebugger", frame, ""))
	if iOff < 0 || iOff > iRun {
		t.Errorf("frame attached during the freeze resumed before its scripts were disabled: %q", methods(calls))
	}
	if slices.IndexFunc(calls, scriptsCall(frame, false)) < 0 {
		t.Errorf("frame attached during the freeze never re-enabled: %q", methods(calls))
	}
}
