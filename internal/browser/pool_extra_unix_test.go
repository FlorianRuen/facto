//go:build unix

package browser_test

import (
	"errors"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/secret"
)

// TestPool_ClosedLeaseRefusesEveryOperation: once the lease is over, every
// page operation and a relaunch fail with ErrBrowserGone; nothing restarts.
func TestPool_ClosedLeaseRefusesEveryOperation(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	r.interactive = true
	p := r.pool()
	b := launchOK(t.Context(), t, p)
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ctx := t.Context()
	_, urlErr := b.CurrentURL(ctx)
	_, cookieErr := b.Cookies(ctx, testDomains)
	ops := map[string]error{
		"Navigate":        b.Navigate(ctx, "https://login.supplier.example/"),
		"WaitVisible":     b.WaitVisible(ctx, "#login"),
		"TypeSecret":      b.TypeSecret(ctx, "#password", secret.New([]byte("synthetic-value"))),
		"Click":           b.Click(ctx, "#submit"),
		"CurrentURL":      urlErr,
		"Cookies":         cookieErr,
		"RelaunchVisible": b.RelaunchVisible(ctx),
	}
	for name, err := range ops {
		if !errors.Is(err, browser.ErrBrowserGone) {
			t.Errorf("%s after Close = %v, want ErrBrowserGone", name, err)
		}
	}
	if n := len(r.startsSnapshot()); n != 1 {
		t.Errorf("%d starts, want 1", n)
	}
}

func TestPool_LaunchAfterCloseRefused(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	p := r.pool()
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	b, err := p.Launch(t.Context(), connector.LaunchOptions{AllowedDomains: testDomains})
	if b != nil || !errors.Is(err, browser.ErrLaunchFailed) {
		t.Fatalf("Launch after Close = %v, %v; want nil, ErrLaunchFailed", b, err)
	}
	if n := len(r.startsSnapshot()); n != 0 {
		t.Errorf("%d starts, want 0", n)
	}
	if e := profileEntries(t, p.Base()); len(e) != 0 {
		t.Errorf("profiles left: %q", e)
	}
}

func TestStartPipeProcess_FailureReturnsNilProcess(t *testing.T) {
	t.Parallel()
	proc, err := browser.StartPipeProcess(t.Context(), browser.Command{})
	if proc != nil || !errors.Is(err, browser.ErrLaunchFailed) {
		t.Fatalf("StartPipeProcess(no path) = %v, %v; want nil, ErrLaunchFailed", proc, err)
	}
}
