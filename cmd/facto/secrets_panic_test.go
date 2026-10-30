package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/FlorianRuen/facto/internal/connector"
)

// errSyntheticPanic is the value the panicking seam panics with.
const errSyntheticPanic = "synthetic panic after the resolver was built"

// panicPool is a NewPool seam that panics. Both collect and login build the
// browser pool after the secret resolver and outside the orchestrator's
// per-connector recover, so it stands for any panic in cmd/facto, the
// store, the inbox ingest or normalize (SEC-J1-13).
func panicPool(context.Context, env, poolParams) (browserPool, error) {
	panic(errSyntheticPanic)
}

// recoverPanic runs f and returns the value it panicked with (nil if none).
func recoverPanic(f func()) (v any) {
	defer func() { v = recover() }()
	f()
	return nil
}

// TestCollect_ResolverClosedOnPanic: a panic after the resolver is built
// still closes it (locks the password manager) exactly once, and the panic
// is not swallowed.
func TestCollect_ResolverClosedOnPanic(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	cfg := s.writeConfig(t, validConfig)
	spy := &spyResolver{}
	e := s.env()
	e.NewSecrets = spy.factory(nil)
	e.NewPool = panicPool
	var stdout, stderr bytes.Buffer

	got := recoverPanic(func() {
		_ = collect(t.Context(), e, collectParams{
			configPath: cfg,
			period:     connector.Year(2026),
			stdout:     &stdout,
			stderr:     &stderr,
		})
	})
	if got != errSyntheticPanic {
		t.Fatalf("recovered %v, want the synthetic panic to propagate", got)
	}
	if built, closed := spy.counts(); built != 1 || closed != 1 {
		t.Errorf("resolver built %d, closed %d; want 1 and 1 (the password manager must be locked on panic)", built, closed)
	}
}

// TestLogin_ResolverClosedOnPanic: same guarantee for login.
func TestLogin_ResolverClosedOnPanic(t *testing.T) {
	t.Parallel()
	r := newLoginRig(t, &synthConn{}, true, "synthetic")
	cfg := r.s.writeConfig(t, synthConfig(true, r.chrom, ""))
	e := r.env()
	e.NewPool = panicPool
	var stdout, stderr bytes.Buffer

	got := recoverPanic(func() {
		_ = login(t.Context(), e, loginParams{id: synthID, configPath: cfg, stdout: &stdout, stderr: &stderr})
	})
	if got != errSyntheticPanic {
		t.Fatalf("recovered %v, want the synthetic panic to propagate", got)
	}
	if built, closed := r.secr.counts(); built != 1 || closed != 1 {
		t.Errorf("resolver built %d, closed %d; want 1 and 1 (the password manager must be locked on panic)", built, closed)
	}
}
