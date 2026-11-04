// T8 review fixes (security): page scripts run in an isolated world, the
// origin is read from the browser (Page.getFrameTree), and focus and
// origin are checked again after typing.
package browser_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

func TestPage_TypeSecretRefusesWhenFrameURLOffAllowlistDespiteJSAnswer(t *testing.T) {
	t.Parallel()
	for _, u := range []string{
		"https://evil.test/login",
		"http://login.supplier.example/login",
		"https://login.supplier.example.evil.test/",
		"about:blank",
	} {
		t.Run(u, func(t *testing.T) {
			t.Parallel()
			// The page scripts still answer the allowlisted login origin
			// (a main-world script could fake it); the frame tree is the
			// browser's truth.
			assertTypeRefused(t, func(e *pageEnv) { e.f.setFrameURL(u) })
		})
	}
}

func TestPage_ScriptsRunInIsolatedWorld(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	e := newPage(t)
	e.navigate(t, loginURL)
	e.f.setElem("#password", fakeElem{visible: true, x: 3, y: 4})
	m := e.f.mark()
	ctx := testCtx(t)
	if err := e.p.WaitVisible(ctx, "#password"); err != nil {
		t.Fatalf("WaitVisible = %v", err)
	}
	if err := e.p.Click(ctx, "#password"); err != nil {
		t.Fatalf("Click = %v", err)
	}
	if err := e.p.TypeSecret(ctx, "#password", secret.FromString(canary)); err != nil {
		t.Fatalf("TypeSecret = %v", err)
	}
	calls := e.f.since(m)

	fns := filter(calls, "Runtime.callFunctionOn")
	if len(fns) < 4 {
		t.Fatalf("callFunctionOn calls = %d, want every page function: %q", len(fns), methods(calls))
	}
	for _, c := range fns {
		if c.Params["objectId"] != fakeIsolatedDocID {
			t.Errorf("callFunctionOn objectId = %v, want the isolated world's document %q", c.Params["objectId"], fakeIsolatedDocID)
		}
	}
	for _, c := range filter(calls, "Runtime.evaluate") {
		if c.Params["contextId"] != float64(fakeIsolatedContextID) {
			t.Errorf("Runtime.evaluate contextId = %v, want the isolated context %d", c.Params["contextId"], fakeIsolatedContextID)
		}
	}
	worlds := filter(calls, "Page.createIsolatedWorld")
	if len(worlds) == 0 {
		t.Fatalf("no Page.createIsolatedWorld: %q", methods(calls))
	}
	for _, w := range worlds {
		if w.Params["frameId"] != fakeFrameID || w.Params["worldName"] != "facto" {
			t.Errorf("createIsolatedWorld params = %v, want frameId %q worldName facto", w.Params, fakeFrameID)
		}
	}
	// The frame URL is read from the browser just before typing.
	iIns := index(calls, "Input.insertText")
	iTree := -1
	for i := iIns - 1; i >= 0; i-- {
		if calls[i].Method == "Page.getFrameTree" {
			iTree = i
			break
		}
	}
	if iTree < 0 || index(calls[iTree:iIns], "Input.") >= 0 {
		t.Errorf("no Page.getFrameTree right before Input.insertText: %q", methods(calls))
	}
}

func TestPage_TypeSecretDetectsChangeAfterTyping(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(f *fakeCDP){
		"focus moved to an iframe":   func(f *fakeCDP) { f.setFocus("iframe") },
		"focus moved to other input": func(f *fakeCDP) { f.setFocus("other") },
		"frame navigated off list":   func(f *fakeCDP) { f.setFrameURL("https://evil.test/") },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			canary := testsecrets.Canary(t, testsecrets.Password)
			e := newPage(t)
			e.navigate(t, loginURL)
			e.f.setElem("#password", fakeElem{visible: true})
			e.f.setOverride("Input.insertText", func(cdpCall) any {
				change(e.f)
				return map[string]any{}
			})
			m := e.f.mark()
			err := e.p.TypeSecret(testCtx(t), "#password", secret.FromString(canary))
			if !errors.Is(err, browser.ErrTypeRefused) {
				t.Fatalf("TypeSecret = %v, want ErrTypeRefused", err)
			}
			if !strings.Contains(err.Error(), "changed while typing") {
				t.Errorf("TypeSecret error = %q, want it to say the focus or origin changed while typing", err)
			}
			calls := e.f.since(m)
			iIns := index(calls, "Input.insertText")
			if iIns < 0 || len(funcCalls(calls[iIns:], browser.JSActiveCheck)) == 0 || index(calls[iIns:], "Page.getFrameTree") < 0 {
				t.Errorf("no focus and frame re-check after typing: %q", methods(calls))
			}
			if strings.Contains(err.Error(), canary) || strings.Contains(e.logs.String(), canary) {
				t.Error("the value leaked into the error or the logs")
			}
			if !strings.Contains(e.logs.String(), "changed while typing") {
				t.Errorf("no debug log for the change: %q", e.logs.String())
			}
		})
	}

	t.Run("unchanged: nil", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.navigate(t, loginURL)
		e.f.setElem("#password", fakeElem{visible: true})
		if err := e.p.TypeSecret(testCtx(t), "#password", secret.FromString("x")); err != nil {
			t.Errorf("TypeSecret = %v, want nil", err)
		}
	})
}
