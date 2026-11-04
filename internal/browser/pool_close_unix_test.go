//go:build unix

package browser_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/connector"
)

// T7c review S2: Pool.Close waits for in-flight Launches, but never forever.
// The pool holds a context that Close cancels once PoolConfig.CloseGrace
// has elapsed, and every browser lifetime is bound to it, so a Launch whose
// own ctx never ends cannot hold Close.

func TestPool_CloseCancelsLaunchOnNeverEndingCtx(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	s := newProcStarter(t)
	s.gate = make(chan struct{}) // never closed: the start ends only on ctx
	cfg := r.config()
	cfg.Start = s.start
	cfg.CloseGrace = 10 * time.Millisecond
	p, err := browser.NewPool(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewPool = %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	launched := make(chan error, 1)
	go func() {
		// A context that never ends, as a careless caller would pass.
		b, err := p.Launch(context.Background(), connector.LaunchOptions{AllowedDomains: testDomains})
		if b != nil {
			_ = b.Close()
		}
		launched <- err
	}()
	waitChan(t, chanOf(s.entered), "first start")

	closed := make(chan error, 1)
	go func() { closed <- p.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Errorf("Close = %v", err)
		}
	case <-time.After(portWait):
		t.Fatal("Pool.Close blocked on a Launch whose ctx never ends")
	}
	select {
	case err := <-launched:
		if err == nil || (!errors.Is(err, browser.ErrLaunchFailed) && !errors.Is(err, context.Canceled)) {
			t.Errorf("in-flight Launch = %v, want ErrLaunchFailed or context.Canceled", err)
		}
	case <-time.After(portWait):
		t.Fatal("in-flight Launch never returned")
	}
	if left := profileEntries(t, p.Base()); len(left) != 0 {
		t.Errorf("profiles left after Close: %q", left)
	}
}

func TestPool_CloseEndsLeaseOnNeverEndingCtx(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	s := newProcStarter(t)
	cfg := r.config()
	cfg.Start = s.start
	p, err := browser.NewPool(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewPool = %v", err)
	}
	b, err := p.Launch(context.Background(), connector.LaunchOptions{AllowedDomains: testDomains})
	if err != nil {
		t.Fatalf("Launch = %v", err)
	}
	pb, ok := b.(*browser.PoolBrowser)
	if !ok {
		t.Fatalf("Launch returned %T", b)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	waitClosed(t, pb.Done(), "lease after Pool.Close")
	_, procs := s.snapshot()
	for i, pr := range procs {
		if pr.closes.Load() == 0 {
			t.Errorf("browser %d still running after Pool.Close", i)
		}
	}
	assertGone(t, pb.ProfileDir())
}
