package browser_test

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// TestTap_EnablesNetworkOnPageSessionOnlyAndDeliversEvents: Tap turns the
// Network domain on for the login page session (never the browser
// session), delivers its request/response events, and fetches a body with
// Network.getResponseBody on that same session.
func TestTap_EnablesNetworkOnPageSessionOnlyAndDeliversEvents(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	ctx := testCtx(t)
	tap, err := e.p.Tap(ctx)
	if err != nil {
		t.Fatalf("Tap: %v", err)
	}
	defer tap.Close()

	en := e.f.waitCalls(t, 1, isCall("Network.enable", fakeSessionID, ""))
	if len(en) != 1 {
		t.Fatalf("Network.enable calls = %d, want 1", len(en))
	}
	for _, c := range e.f.snapshot() {
		if c.Method == "Network.enable" && c.Session != fakeSessionID {
			t.Fatalf("Network.enable sent on session %q, want only the page session", c.Session)
		}
	}

	e.f.emit(fakeSessionID, "Network.requestWillBeSent", map[string]any{"requestId": "r1", "request": map[string]any{"url": "https://www.example.test/"}})
	e.f.emit("", "Network.requestWillBeSent", map[string]any{"requestId": "browser-level"})
	ev := <-tap.Events()
	if ev.Method != "Network.requestWillBeSent" || ev.SessionID != fakeSessionID {
		t.Fatalf("event = %+v, want the page session's requestWillBeSent", ev)
	}

	body := []byte("%PDF-1.7 synthetic")
	e.f.setOverride("Network.getResponseBody", func(c cdpCall) any {
		if c.Session != fakeSessionID || c.Params["requestId"] != "r1" {
			t.Errorf("getResponseBody on %q for %v", c.Session, c.Params["requestId"])
		}
		return map[string]any{"body": base64.StdEncoding.EncodeToString(body), "base64Encoded": true}
	})
	got, b64, err := tap.Body(ctx, "r1")
	if err != nil || !b64 || got != base64.StdEncoding.EncodeToString(body) {
		t.Fatalf("Body = %q, %v, %v", got, b64, err)
	}
}

// TestTap_BodyErrorsNeverQuoteTheBrowserAnswer and refuse an empty id.
func TestTap_BodyRefusesEmptyIDAndReportsErrors(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	ctx := testCtx(t)
	tap, err := e.p.Tap(ctx)
	if err != nil {
		t.Fatalf("Tap: %v", err)
	}
	defer tap.Close()
	if _, _, err := tap.Body(ctx, ""); err == nil {
		t.Fatal("Body(\"\") succeeded")
	}
	e.f.setOverride("Network.getResponseBody", func(cdpCall) any { return &cdpErr{code: -32000} })
	if _, _, err := tap.Body(ctx, "r9"); err == nil {
		t.Fatal("Body on a CDP error succeeded")
	}
}

// TestTap_ClosedWithThePage: closing the page ends the tap's channel and
// later Body calls fail with ErrBrowserGone.
func TestTap_ClosedWithThePage(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	ctx := testCtx(t)
	tap, err := e.p.Tap(ctx)
	if err != nil {
		t.Fatalf("Tap: %v", err)
	}
	tap.Close()
	for range tap.Events() {
	}
	if _, _, err := tap.Body(ctx, "r1"); !errors.Is(err, browser.ErrBrowserGone) {
		t.Fatalf("Body after Close = %v, want ErrBrowserGone", err)
	}
}

// TestPoolBrowser_TapNeedsARunningBrowser: a lease that is over has no tap.
func TestTap_EnableFailureReported(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	e.f.setOverride("Network.enable", func(cdpCall) any { return &cdpErr{code: -32601} })
	if _, err := e.p.Tap(testCtx(t)); err == nil {
		t.Fatal("Tap succeeded although Network.enable failed")
	}
}

// TestTap_PageCloseEndsTheTap: Page.Close closes every tap; a tap asked
// for on a closed page is refused.
func TestTap_PageCloseEndsTheTap(t *testing.T) {
	t.Parallel()
	e := newPage(t)
	ctx := testCtx(t)
	tap, err := e.p.Tap(ctx)
	if err != nil {
		t.Fatalf("Tap: %v", err)
	}
	_ = e.p.Close()
	for range tap.Events() {
	}
	if _, err := e.p.Tap(ctx); !errors.Is(err, browser.ErrBrowserGone) {
		t.Fatalf("Tap on a closed page = %v, want ErrBrowserGone", err)
	}
}
