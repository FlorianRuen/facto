// Tests for J1 task T9, items from the T8 review (docs/agentic/plans/J1.md):
// the navigation race in the typing checks and the isolated-world cache.
//
// Expected behaviour (page.go), written before the implementation:
//
//	// run reads the main frame id, loaderId and URL (Page.getFrameTree),
//	// calls the page function, then reads Page.getFrameTree again: a
//	// different loaderId or URL means a navigation committed mid-check,
//	// and the check fails. TypeSecret then returns ErrTypeRefused and
//	// types nothing (pre-typing check), or ErrTypeRefused "focus or origin
//	// changed while typing" (post-typing check). The post-typing check
//	// also requires the loaderId seen by the pre-typing check: a new
//	// document committed during Input.insertText is a change.
//	//
//	// The isolated world (Page.createIsolatedWorld, worldName "facto") is
//	// cached per frame id + loaderId: one per document. A new loaderId (or
//	// frame id) creates a new one; so does a CDP error from
//	// Runtime.evaluate or Runtime.callFunctionOn in the cached world (the
//	// context was destroyed): the cache entry is dropped, so the next
//	// operation creates a fresh world (retrying within the same operation
//	// is allowed).
package browser_test

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

func TestPage_CheckRefusedWhenNavigationCommitsMidCheck(t *testing.T) {
	t.Parallel()
	// nth counts JSActiveCheck calls: 1 is the pre-typing check, 2 the
	// post-typing one.
	tests := []struct {
		name string
		// arm installs the change on the fake.
		arm         func(f *fakeCDP)
		typed       bool // Input.insertText expected
		afterTyping bool // the error must say "changed while typing"
	}{
		{
			name: "pre-typing: new document at the same URL",
			arm: func(f *fakeCDP) {
				onActiveCheck(f, 1, func() { f.setLoader("loader-2") })
			},
		},
		{
			name: "pre-typing: commit to another allowlisted URL",
			arm: func(f *fakeCDP) {
				onActiveCheck(f, 1, func() {
					f.setLoader("loader-2")
					f.setFrameURL("https://other.supplier.example/login")
				})
			},
		},
		{
			name: "pre-typing: URL changed, same loader",
			arm: func(f *fakeCDP) {
				onActiveCheck(f, 1, func() { f.setFrameURL("https://login.supplier.example/elsewhere") })
			},
		},
		{
			name:  "post-typing: new document mid-check",
			typed: true, afterTyping: true,
			arm: func(f *fakeCDP) {
				onActiveCheck(f, 2, func() { f.setLoader("loader-2") })
			},
		},
		{
			name:  "new document committed during insertText",
			typed: true, afterTyping: true,
			arm: func(f *fakeCDP) {
				f.setIntercept("Input.insertText", func(cdpCall) any {
					f.setLoader("loader-2")
					return nil // the model answers
				})
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			canary := testsecrets.Canary(t, testsecrets.Password)
			e := newPage(t)
			e.navigate(t, loginURL)
			e.f.setElem("#password", fakeElem{visible: true})
			tc.arm(e.f)
			m := e.f.mark()
			err := e.p.TypeSecret(testCtx(t), "#password", secret.FromString(canary))
			if !errors.Is(err, browser.ErrTypeRefused) {
				t.Fatalf("TypeSecret = %v, want ErrTypeRefused (a navigation committed during the check)", err)
			}
			calls := e.f.since(m)
			if typed := index(calls, "Input.insertText") >= 0; typed != tc.typed {
				t.Errorf("Input.insertText sent = %v, want %v: %q", typed, tc.typed, methods(calls))
			}
			if tc.afterTyping && !strings.Contains(err.Error(), "changed while typing") {
				t.Errorf("error = %q, want it to say the focus or origin changed while typing", err)
			}
			// Each check reads the frame tree after the page function too.
			for _, fn := range funcCalls(calls, browser.JSActiveCheck) {
				i := indexOf(calls, fn)
				if index(calls[i+1:], "Page.getFrameTree") < 0 {
					t.Errorf("no Page.getFrameTree after a JSActiveCheck: %q", methods(calls))
				}
			}
			if strings.Contains(err.Error(), canary) || strings.Contains(e.logs.String(), canary) {
				t.Error("the value leaked into the error or the logs")
			}
		})
	}

	t.Run("stable document: typed", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.setElem("#password", fakeElem{visible: true})
		if err := e.p.TypeSecret(testCtx(t), "#password", secret.FromString("x")); err != nil {
			t.Errorf("TypeSecret = %v, want nil", err)
		}
	})
}

// onActiveCheck runs fn once, right after the nth JSActiveCheck answer
// (before the page reads anything else).
func onActiveCheck(f *fakeCDP, nth int, fn func()) {
	var mu sync.Mutex
	n := 0
	f.setOnFunction(func(decl string) {
		if decl != browser.JSActiveCheck {
			return
		}
		mu.Lock()
		n++
		hit := n == nth
		mu.Unlock()
		if hit {
			fn()
		}
	})
}

// indexOf returns the position of the call whose raw frame is c's.
func indexOf(calls []cdpCall, c cdpCall) int {
	for i := range calls {
		if calls[i].Raw == c.Raw {
			return i
		}
	}
	return -1
}

func TestPage_IsolatedWorldReusedPerDocument(t *testing.T) {
	t.Parallel()

	t.Run("one world per document", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.setElem("#password", fakeElem{visible: true, x: 1, y: 2})
		ctx := testCtx(t)
		m := e.f.mark()
		if err := e.p.WaitVisible(ctx, "#password"); err != nil {
			t.Fatalf("WaitVisible = %v", err)
		}
		if err := e.p.Click(ctx, "#password"); err != nil {
			t.Fatalf("Click = %v", err)
		}
		if err := e.p.TypeSecret(ctx, "#password", secret.FromString("x")); err != nil {
			t.Fatalf("TypeSecret = %v", err)
		}
		if n := len(filter(e.f.since(m), "Page.createIsolatedWorld")); n != 1 {
			t.Errorf("createIsolatedWorld calls = %d over one document, want 1 (cached per frame id + loaderId)", n)
		}

		// A new document gets its own world, once.
		e.f.setLoader("loader-2")
		m = e.f.mark()
		for range 3 {
			if err := e.p.WaitVisible(ctx, "#password"); err != nil {
				t.Fatalf("WaitVisible = %v", err)
			}
		}
		worlds := filter(e.f.since(m), "Page.createIsolatedWorld")
		if len(worlds) != 1 {
			t.Errorf("createIsolatedWorld calls after navigation = %d, want 1", len(worlds))
		}
		for _, w := range worlds {
			if w.Params["frameId"] != fakeFrameID || w.Params["worldName"] != "facto" {
				t.Errorf("createIsolatedWorld params = %v", w.Params)
			}
		}
	})

	t.Run("recreated when the cached world fails", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.setElem("#password", fakeElem{visible: true})

		var mu sync.Mutex
		next := 100
		dead := map[float64]bool{}
		e.f.setIntercept("Page.createIsolatedWorld", func(cdpCall) any {
			mu.Lock()
			defer mu.Unlock()
			next++
			return map[string]any{"executionContextId": next}
		})
		e.f.setIntercept("Runtime.evaluate", func(c cdpCall) any {
			id, _ := c.Params["contextId"].(float64)
			mu.Lock()
			defer mu.Unlock()
			if dead[id] {
				return &cdpErr{code: -32000} // Cannot find context with specified id
			}
			return map[string]any{"result": map[string]any{
				"type": "object", "className": "HTMLDocument", "objectId": fmt.Sprintf("obj-iso-%d", int(id)),
			}}
		})
		e.f.setIntercept("Runtime.callFunctionOn", func(c cdpCall) any {
			obj, _ := c.Params["objectId"].(string)
			mu.Lock()
			defer mu.Unlock()
			for id := range dead {
				if obj == fmt.Sprintf("obj-iso-%d", int(id)) {
					return &cdpErr{code: -32000}
				}
			}
			return nil // the model answers
		})

		ctx := testCtx(t)
		if err := e.p.WaitVisible(ctx, "#password"); err != nil {
			t.Fatalf("WaitVisible = %v", err)
		}
		if err := e.p.WaitVisible(ctx, "#password"); err != nil {
			t.Fatalf("second WaitVisible = %v", err)
		}
		if n := len(filter(e.f.snapshot(), "Page.createIsolatedWorld")); n != 1 {
			t.Fatalf("createIsolatedWorld calls = %d before the failure, want 1", n)
		}

		// The context is destroyed without a new loaderId (for example a
		// renderer swap): the next operations must not keep using it.
		mu.Lock()
		dead[101] = true
		mu.Unlock()
		m := e.f.mark()
		_ = e.p.WaitVisible(ctx, "#password") // may fail once
		if err := e.p.WaitVisible(ctx, "#password"); err != nil {
			t.Fatalf("WaitVisible after the world died = %v, want a fresh world", err)
		}
		calls := e.f.since(m)
		worlds := filter(calls, "Page.createIsolatedWorld")
		if len(worlds) == 0 {
			t.Fatalf("no new createIsolatedWorld after the cached world failed: %q", methods(calls))
		}
		last := indexOf(calls, worlds[len(worlds)-1])
		for _, c := range calls[last:] {
			if c.Method == "Runtime.evaluate" && c.Params["contextId"] == float64(101) {
				t.Errorf("dead context 101 used after the new world was created")
			}
			if c.Method == "Runtime.callFunctionOn" && c.Params["objectId"] == "obj-iso-101" {
				t.Errorf("object of dead context 101 used after the new world was created")
			}
		}
		if len(worlds) > 2 {
			t.Errorf("createIsolatedWorld calls after one failure = %d, want at most 2", len(worlds))
		}

		// And the new one is cached again.
		m = e.f.mark()
		if err := e.p.WaitVisible(ctx, "#password"); err != nil {
			t.Fatalf("WaitVisible = %v", err)
		}
		if n := len(filter(e.f.since(m), "Page.createIsolatedWorld")); n != 0 {
			t.Errorf("createIsolatedWorld calls on a healthy cached world = %d, want 0", n)
		}
	})
}
