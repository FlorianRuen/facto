// Additional page tests (J1 T8): default options, page script failures,
// requested cookie domains and Close failures.
package browser_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

func TestPage_CurrentURLAfterNavigatingToAnotherAllowedHost(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	const other = "https://api.supplier.example/invoices"
	e.navigate(t, other)
	if got, err := e.p.CurrentURL(testCtx(t)); err != nil || got != other {
		t.Errorf("CurrentURL = %q, %v; want %q", got, err, other)
	}
}

func TestPage_DefaultOptions(t *testing.T) {
	t.Parallel()

	t.Run("nil PollWait waits with a timer, nil Log discards", func(t *testing.T) {
		t.Parallel()
		f, c, opts, _ := newEnv(t)
		opts.PollWait, opts.Log = nil, nil
		p, err := browser.NewPage(testCtx(t), c, opts)
		if err != nil {
			t.Fatalf("NewPage = %v", err)
		}
		t.Cleanup(func() { _ = p.Close() })
		f.setElem("#login", fakeElem{visibleAfter: 2})
		if err := p.WaitVisible(testCtx(t), "#login"); err != nil {
			t.Fatalf("WaitVisible = %v", err)
		}
		if n := f.pollCount("#login"); n != 2 {
			t.Errorf("polls = %d, want 2", n)
		}
	})

	t.Run("nil PollWait honours the context", func(t *testing.T) {
		t.Parallel()
		f, c, opts, _ := newEnv(t)
		opts.PollWait = nil
		p, err := browser.NewPage(testCtx(t), c, opts)
		if err != nil {
			t.Fatalf("NewPage = %v", err)
		}
		t.Cleanup(func() { _ = p.Close() })
		ctx, cancel := context.WithCancel(testCtx(t))
		defer cancel()
		f.setOnVisiblePoll(func(int) { cancel() })
		if err := p.WaitVisible(ctx, "#never"); !errors.Is(err, context.Canceled) {
			t.Errorf("WaitVisible = %v, want context.Canceled", err)
		}
	})
}

func TestPage_ScriptFailuresNeverQuoted(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	answers := map[string]map[string]any{
		"exception": {
			"result":           map[string]any{"type": "object", "subtype": "error"},
			"exceptionDetails": map[string]any{"text": "Uncaught " + canary},
		},
		"wrong shape": {"result": map[string]any{"type": "string", "value": canary}},
	}
	for name, answer := range answers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newPage(t)
			e.navigate(t, loginURL)
			e.f.setOverride("Runtime.callFunctionOn", func(cdpCall) any { return answer })
			ctx := testCtx(t)
			errs := []error{
				e.p.WaitVisible(ctx, "#a"),
				e.p.Click(ctx, "#a"),
			}
			for i, err := range errs {
				if err == nil {
					t.Errorf("operation %d = nil, want an error", i)
					continue
				}
				if strings.Contains(err.Error(), canary) {
					t.Errorf("operation %d error quotes the page answer", i)
				}
			}
		})
	}

	t.Run("no document object", func(t *testing.T) {
		t.Parallel()
		e := newPage(t)
		e.f.setOverride("Runtime.evaluate", func(cdpCall) any {
			return map[string]any{"result": map[string]any{"type": "undefined"}}
		})
		if err := e.p.WaitVisible(testCtx(t), "#a"); err == nil {
			t.Error("WaitVisible = nil, want an error")
		}
		if i := index(e.f.snapshot(), "Runtime.callFunctionOn"); i >= 0 {
			t.Error("page function run without a document object")
		}
	})
}

func TestPage_NavigateCDPFailure(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	e.f.setOverride("Page.navigate", func(cdpCall) any { return &cdpErr{code: -32000} })
	if err := e.p.Navigate(testCtx(t), loginURL); !errors.Is(err, browser.ErrCDP) {
		t.Errorf("Navigate = %v, want ErrCDP", err)
	}
}

func TestCookies_InvalidRequestedDomainsRefused(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	m := e.f.mark()
	for _, d := range [][]string{{"*"}, {"https://supplier.example"}, {""}} {
		if _, err := e.p.Cookies(testCtx(t), d); !errors.Is(err, browser.ErrInvalidDomain) {
			t.Errorf("Cookies(%q) = %v, want ErrInvalidDomain", d, err)
		}
	}
	if got := e.f.since(m); len(got) != 0 {
		t.Errorf("sent %q for invalid domains, want zero CDP calls", methods(got))
	}
}

func TestPage_CloseFailureReportedOnce(t *testing.T) {
	t.Parallel()
	f, c, opts, _ := newEnv(t)
	p, err := browser.NewPage(testCtx(t), c, opts)
	if err != nil {
		t.Fatalf("NewPage = %v", err)
	}
	f.setOverride("Target.disposeBrowserContext", func(cdpCall) any { return &cdpErr{code: -32000} })
	if err := p.Close(); !errors.Is(err, browser.ErrCDP) {
		t.Errorf("Close = %v, want ErrCDP", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
	if n := len(filter(f.snapshot(), "Target.disposeBrowserContext")); n != 1 {
		t.Errorf("disposeBrowserContext calls = %d, want 1", n)
	}
}

func TestNewPage_SetupFailuresDisposeTheContext(t *testing.T) {
	t.Parallel()
	for _, m := range []string{"Target.createTarget", "Page.enable"} {
		t.Run(m, func(t *testing.T) {
			t.Parallel()
			f, c, opts, _ := newEnv(t)
			f.setOverride(m, func(cdpCall) any { return &cdpErr{code: -32000} })
			if p, err := browser.NewPage(testCtx(t), c, opts); err == nil {
				_ = p.Close()
				t.Fatal("NewPage = nil error")
			}
			calls := f.snapshot()
			if n := len(filter(calls, "Target.disposeBrowserContext")); n != 1 {
				t.Errorf("disposeBrowserContext calls = %d, want 1: %q", n, methods(calls))
			}
			if index(calls, "Page.navigate") >= 0 {
				t.Error("navigated after a setup failure")
			}
		})
	}

	t.Run("missing ids", func(t *testing.T) {
		t.Parallel()
		for _, m := range []string{"Target.createBrowserContext", "Target.createTarget", "Target.attachToTarget"} {
			f, c, opts, _ := newEnv(t)
			f.setOverride(m, func(cdpCall) any { return map[string]any{} })
			if p, err := browser.NewPage(testCtx(t), c, opts); err == nil {
				_ = p.Close()
				t.Errorf("NewPage with no id from %s = nil error", m)
			}
		}
	})
}
