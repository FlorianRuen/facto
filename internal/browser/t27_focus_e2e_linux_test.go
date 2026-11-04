//go:build e2e && chrome && linux

package browser_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// TestChrome_TypeSecretPageListenerSeesValue: freezing page scripts around
// Input.insertText must not hide the typed value from the page's own input
// listener (a framework-controlled field would otherwise submit empty).
func TestChrome_TypeSecretPageListenerSeesValue(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), e2eTimeout)
	defer cancel()
	s := newT27Site(t)
	b := t27Launch(ctx, t, t27Rig(t, s))
	if err := b.Navigate(ctx, "https://"+siteHost+"/listen"); err != nil {
		t.Fatalf("Navigate: %v", err)
	}
	wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
	defer wcancel()
	if err := b.WaitVisible(wctx, "#ready"); err != nil {
		t.Fatalf("page not ready: %v", err)
	}
	typed := testsecrets.Canary(t, testsecrets.Password)
	sec := secret.FromString(typed)
	err := b.TypeSecret(ctx, "#pass", sec)
	sec.Wipe()
	if err != nil {
		t.Fatalf("TypeSecret: %v", err)
	}
	if err := b.WaitVisible(wctx, "#seen"); err != nil {
		t.Fatalf("the page's input listener never ran: %v", err)
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		if slices.ContainsFunc(s.values(), func(v string) bool { return v == typed }) {
			break
		}
		cctx, ccancel := context.WithTimeout(ctx, 100*time.Millisecond)
		_ = b.WaitVisible(cctx, "#never-there")
		ccancel()
		select {
		case <-deadline.C:
			t.Fatalf("the page's input listener never saw the whole typed value (%d reports)", len(s.values()))
		default:
		}
	}
}
