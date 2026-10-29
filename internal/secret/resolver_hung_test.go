package secret_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// hungProvider blocks every Resolve until release is closed and ignores ctx:
// the worst case of a keyring daemon that never answers (SEC-J0-23).
type hungProvider struct {
	scheme  string
	value   string
	entered chan struct{}
	release chan struct{}

	mu     sync.Mutex
	closes int
	late   secret.Secret // the Secret handed back after release
}

func (p *hungProvider) Scheme() string { return p.scheme }

func (p *hungProvider) Resolve(_ context.Context, _ secret.Ref) (secret.Secret, error) {
	p.entered <- struct{}{}
	<-p.release
	s := secret.FromString(p.value)
	p.mu.Lock()
	p.late = s
	p.mu.Unlock()
	return s, nil
}

func (p *hungProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closes++
	return nil
}

// TestResolver_CloseAllNotBlockedByHungProvider: CloseAll must close every
// provider (so the password manager is locked) even while a Resolve is stuck
// in a provider that ignores ctx. The stuck Resolve, once the provider
// answers after CloseAll, returns ErrClosed and its late Secret is wiped:
// a closed resolver hands out no secret.
func TestResolver_CloseAllNotBlockedByHungProvider(t *testing.T) {
	t.Parallel()
	const guard = 5 * time.Second // failure guard only, never an assertion
	canary := testsecrets.Canary(t, testsecrets.Password)
	hung := &hungProvider{scheme: "keyring", value: canary, entered: make(chan struct{}, 1), release: make(chan struct{})}
	released := false
	t.Cleanup(func() {
		if !released {
			close(hung.release)
		}
	})
	bw, _ := newProviders()
	r := mustResolver(t, bw, hung)

	type result struct {
		s   secret.Secret
		err error
	}
	resc := make(chan result, 1)
	go func() {
		s, err := r.Resolve(context.Background(), "keyring://facto/ileo/login")
		resc <- result{s, err}
	}()
	select {
	case <-hung.entered:
	case <-time.After(guard):
		t.Fatal("Resolve never reached the provider")
	}

	closed := make(chan error, 1)
	go func() { closed <- r.CloseAll() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Errorf("CloseAll = %v, want nil", err)
		}
	case <-time.After(guard):
		t.Fatal("CloseAll blocked by a hung provider: the password manager is never locked")
	}
	hung.mu.Lock()
	hc := hung.closes
	hung.mu.Unlock()
	if hc != 1 || bw.closeCount() != 1 {
		t.Errorf("closes: hung %d, bw %d; want 1, 1", hc, bw.closeCount())
	}
	if _, err := r.Resolve(context.Background(), "bw://"+itemUUID+"/password"); !errors.Is(err, secret.ErrClosed) {
		t.Errorf("Resolve after CloseAll = %v, want ErrClosed", err)
	}

	released = true
	close(hung.release)
	var res result
	select {
	case res = <-resc:
	case <-time.After(guard):
		t.Fatal("in-flight Resolve never returned after the provider answered")
	}
	if !errors.Is(res.err, secret.ErrClosed) {
		t.Errorf("in-flight Resolve finishing after CloseAll = %v, want ErrClosed", res.err)
	}
	if !res.s.IsZero() {
		t.Error("closed resolver handed out a Secret")
	}
	hung.mu.Lock()
	late := hung.late
	hung.mu.Unlock()
	if !late.IsZero() {
		t.Error("Secret returned by the provider after CloseAll was not wiped")
	}
	if res.err != nil && strings.Contains(res.err.Error(), canary) {
		t.Error("error carries the secret")
	}
}
