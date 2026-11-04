// Tests for J1 task T15 (SEC-J0-23, ADR 0009): keyring Get, Set and Delete
// are bounded and cancellable. A hung OS keyring (go-keyring over D-Bus
// cannot be cancelled) must never block the caller past its context or the
// provider timeout. The blocked backend call is abandoned: it may finish
// later, its result is discarded, and no other goroutine of the provider
// outlives it.
//
// Time: clock.Fake has no timers, so the provider timeout is driven by an
// injected After function (keyring.WithAfter) that the test fires by hand.
// Wall-clock waits below are failure guards only, never assertions.
package keyring_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/keyring"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// guard bounds every wait so a broken implementation fails instead of
// hanging the suite. It is never what a test asserts on.
const guard = 5 * time.Second

// blockingBackend blocks every call until release is closed, like a hung
// keyring daemon. It reports when a call enters and when it returns.
type blockingBackend struct {
	entered  chan string // op name, one per call
	release  chan struct{}
	returned chan string // op name, sent just before the call returns
	// lateValue is what Get returns once released (after the caller gave up).
	lateValue string
	// errText is returned (as an error) by every call once released.
	errText string
}

func newBlockingBackend() *blockingBackend {
	return &blockingBackend{
		entered:   make(chan string, 8),
		release:   make(chan struct{}),
		returned:  make(chan string, 8),
		lateValue: "late-synthetic-value",
	}
}

func (b *blockingBackend) wait(op string) error {
	b.entered <- op
	<-b.release
	defer func() { b.returned <- op }()
	if b.errText != "" {
		return errors.New(b.errText)
	}
	return nil
}

func (b *blockingBackend) Get(_, _ string) (string, error) {
	if err := b.wait("get"); err != nil {
		return "", err
	}
	return b.lateValue, nil
}

func (b *blockingBackend) Set(_, _, _ string) error { return b.wait("set") }

func (b *blockingBackend) Delete(_, _ string) error { return b.wait("delete") }

var _ keyring.Backend = (*blockingBackend)(nil)

// fakeTimer is the injected After: it records the requested durations and
// fires only when the test calls fire.
type fakeTimer struct {
	mu        sync.Mutex
	durations []time.Duration
	chans     []chan time.Time
	requested chan struct{}
}

func newFakeTimer() *fakeTimer {
	return &fakeTimer{requested: make(chan struct{}, 8)}
}

func (f *fakeTimer) After(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := make(chan time.Time, 1)
	f.durations = append(f.durations, d)
	f.chans = append(f.chans, c)
	f.requested <- struct{}{}
	return c
}

// fire expires every timer requested so far.
func (f *fakeTimer) fire() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.chans {
		select {
		case c <- time.Time{}:
		default:
		}
	}
}

func (f *fakeTimer) requests() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.durations...)
}

// deadlineCtx is a context whose deadline the test hits by hand: Done
// closes and Err becomes context.DeadlineExceeded. No wall clock involved.
type deadlineCtx struct {
	context.Context
	done chan struct{}
	once sync.Once
}

func newDeadlineCtx() *deadlineCtx {
	return &deadlineCtx{Context: context.Background(), done: make(chan struct{})}
}

func (c *deadlineCtx) Done() <-chan struct{} { return c.done }

func (c *deadlineCtx) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func (c *deadlineCtx) hit() { c.once.Do(func() { close(c.done) }) }

// keyringOp runs one provider operation on keyring://facto/ileo/session.
type keyringOp struct {
	name string
	run  func(ctx context.Context, p *keyring.Provider) error
}

var (
	opGet = keyringOp{name: "get", run: func(ctx context.Context, p *keyring.Provider) error {
		s, err := p.Resolve(ctx, secret.Ref{Scheme: "keyring", Item: "facto", Field: "ileo/session"})
		if err != nil && !s.IsZero() {
			return fmt.Errorf("non-empty Secret returned with error %w", err)
		}
		return err
	}}
	opSet = keyringOp{name: "set", run: func(ctx context.Context, p *keyring.Provider) error {
		return p.Set(ctx, secret.Ref{Scheme: "keyring", Item: "facto", Field: "ileo/session"}, secret.FromString("synthetic-key-value"))
	}}
	opDelete = keyringOp{name: "delete", run: func(ctx context.Context, p *keyring.Provider) error {
		return p.Delete(ctx, secret.Ref{Scheme: "keyring", Item: "facto", Field: "ileo/session"})
	}}
)

// checkHonoursContext blocks the backend, stops the call in each way a
// caller can (cancel, caller deadline, provider timeout) and checks that:
// the call returns while the backend is still blocked, with the right error;
// once the backend is released, the abandoned call finishes and no provider
// goroutine is left behind.
//
// Not parallel on purpose: the goroutine-leak check reads every goroutine
// stack of the test binary, and top-level parallel tests stay paused (in
// testing code, not in keyring code) while a sequential test runs.
func checkHonoursContext(t *testing.T, op keyringOp) {
	t.Helper()
	tests := []struct {
		name string
		// stop ends the call: cancel, deadline hit, or provider timeout.
		stop    string
		wantErr []error
	}{
		{name: "caller cancels", stop: "cancel", wantErr: []error{context.Canceled}},
		{name: "caller deadline hits", stop: "deadline", wantErr: []error{context.DeadlineExceeded}},
		{name: "provider timeout", stop: "timeout", wantErr: []error{keyring.ErrTimeout, context.DeadlineExceeded}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newBlockingBackend()
			b.errText = "dbus: org.freedesktop.Secret late failure synthetic-backend-text"
			released := false
			t.Cleanup(func() {
				if !released {
					close(b.release)
				}
			})
			timer := newFakeTimer()
			p := keyring.New(b, keyring.WithAfter(timer.After))

			var ctx context.Context
			var stop func()
			switch tc.stop {
			case "cancel":
				c, cancel := context.WithCancel(context.Background())
				ctx, stop = c, cancel
				t.Cleanup(cancel)
			case "deadline":
				dc := newDeadlineCtx()
				ctx, stop = dc, dc.hit
			case "timeout":
				ctx, stop = context.Background(), timer.fire
			}

			errc := make(chan error, 1)
			go func() { errc <- op.run(ctx, p) }()

			select {
			case got := <-b.entered:
				if got != op.name {
					t.Fatalf("backend entered %q, want %q", got, op.name)
				}
			case <-time.After(guard):
				t.Fatalf("%s never reached the backend", op.name)
			}
			if tc.stop == "timeout" {
				select {
				case <-timer.requested:
				case <-time.After(guard):
					t.Fatalf("%s started a backend call without a bound (no After requested)", op.name)
				}
			}
			stop()

			var err error
			select {
			case err = <-errc:
			case <-time.After(guard):
				t.Fatalf("%s still blocked after %s: it waits for the hung backend", op.name, tc.stop)
			}
			for _, want := range tc.wantErr {
				if !errors.Is(err, want) {
					t.Errorf("%s error = %v, want errors.Is %v", op.name, err, want)
				}
			}
			select {
			case got := <-b.returned:
				t.Fatalf("backend %s returned before release; the test did not exercise a hung backend", got)
			default:
			}

			// Release the abandoned backend call: it must finish, and the
			// provider must not keep a goroutine around afterwards.
			released = true
			close(b.release)
			select {
			case <-b.returned:
			case <-time.After(guard):
				t.Fatal("abandoned backend call never returned")
			}
			assertNoProviderGoroutine(t)
		})
	}
}

// assertNoProviderGoroutine fails when a goroutine still runs code of
// package keyring (not keyring_test) once every backend call has returned.
// The provider's helper goroutine needs a few scheduler turns to deliver or
// drop the late result, so it is given until guard to exit.
func assertNoProviderGoroutine(t *testing.T) {
	t.Helper()
	const frame = "facto/internal/secret/keyring.("
	expired := time.After(guard)
	var dump string
poll:
	for {
		buf := make([]byte, 1<<20)
		dump = string(buf[:runtime.Stack(buf, true)])
		if !strings.Contains(dump, frame) {
			return
		}
		select {
		case <-expired:
			break poll
		default:
			runtime.Gosched()
		}
	}
	var leaked []string
	for g := range strings.SplitSeq(dump, "\n\n") {
		if strings.Contains(g, frame) {
			leaked = append(leaked, g)
		}
	}
	t.Fatalf("provider goroutine still running after the backend returned:\n%s", strings.Join(leaked, "\n\n"))
}

func TestKeyring_GetHonoursContext(t *testing.T) { checkHonoursContext(t, opGet) }

func TestKeyring_SetHonoursContext(t *testing.T) { checkHonoursContext(t, opSet) }

func TestKeyring_DeleteHonoursContext(t *testing.T) { checkHonoursContext(t, opDelete) }

// The bound used for every backend call is DefaultTimeout unless WithTimeout
// sets another one.
func TestKeyring_BackendCallsAreBounded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		opts func(*fakeTimer) []keyring.Option
		want time.Duration
	}{
		{name: "default", opts: func(f *fakeTimer) []keyring.Option {
			return []keyring.Option{keyring.WithAfter(f.After)}
		}, want: keyring.DefaultTimeout},
		{name: "custom", opts: func(f *fakeTimer) []keyring.Option {
			return []keyring.Option{keyring.WithAfter(f.After), keyring.WithTimeout(3 * time.Second)}
		}, want: 3 * time.Second},
	}
	if keyring.DefaultTimeout <= 0 {
		t.Fatalf("DefaultTimeout = %v, want > 0", keyring.DefaultTimeout)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, op := range []keyringOp{opGet, opSet, opDelete} {
				f := newFakeTimer()
				b := &fakeBackend{values: map[[2]string]string{{"facto", "ileo/session"}: "synthetic"}}
				_ = op.run(t.Context(), keyring.New(b, tc.opts(f)...))
				got := f.requests()
				if len(got) != 1 || got[0] != tc.want {
					t.Errorf("%s: timer requests = %v, want exactly [%v]", op.name, got, tc.want)
				}
			}
		})
	}
}

func TestKeyring_SetStoresSecret(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		ref         string
		wantService string
		wantUser    string
	}{
		{name: "session key (ADR 0009 layout)", ref: "keyring://facto-session/inst-0001/ileo", wantService: "facto-session", wantUser: "inst-0001/ileo"},
		{name: "simple key", ref: "keyring://facto/ileo-password", wantService: "facto", wantUser: "ileo-password"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			canary := testsecrets.Canary(t, testsecrets.Session)
			value := secret.FromString(canary)
			b := &fakeBackend{}
			p := keyring.New(b)
			if err := p.Set(t.Context(), mustRef(t, tc.ref), value); err != nil {
				t.Fatalf("Set(%q): %v", tc.ref, err)
			}
			ops := b.opLog()
			want := backendOp{op: "set", service: tc.wantService, user: tc.wantUser, value: canary}
			if len(ops) != 1 || ops[0] != want {
				t.Fatalf("backend ops = %d ops, want exactly one Set(%q, %q, <value>)", len(ops), tc.wantService, tc.wantUser)
			}
			if value.Expose() != canary {
				t.Error("Set wiped or changed the caller's Secret; the caller owns it")
			}
			got, err := p.Resolve(t.Context(), mustRef(t, tc.ref))
			if err != nil || got.Expose() != canary {
				t.Errorf("Resolve after Set: err %v, value round-trip ok = %v", err, got.Expose() == canary)
			}
		})
	}
}

func TestKeyring_SetRejectsBadInput(t *testing.T) {
	t.Parallel()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	good := secret.Ref{Scheme: "keyring", Item: "facto", Field: "k"}
	tests := []struct {
		name    string
		ctx     context.Context
		ref     secret.Ref
		value   secret.Secret
		wantErr error
	}{
		{name: "empty value", ctx: context.Background(), ref: good, value: secret.Secret{}, wantErr: keyring.ErrEmptyValue},
		{name: "wrong scheme", ctx: context.Background(), ref: secret.Ref{Scheme: "bw", Item: "facto", Field: "k"}, value: secret.FromString("v"), wantErr: secret.ErrInvalidRef},
		{name: "traversal in key", ctx: context.Background(), ref: secret.Ref{Scheme: "keyring", Item: "facto", Field: "../other/k"}, value: secret.FromString("v"), wantErr: secret.ErrInvalidRef},
		{name: "slash in service", ctx: context.Background(), ref: secret.Ref{Scheme: "keyring", Item: "facto/../login.example", Field: "token"}, value: secret.FromString("v"), wantErr: secret.ErrInvalidRef},
		{name: "NUL in key", ctx: context.Background(), ref: secret.Ref{Scheme: "keyring", Item: "facto", Field: "k\x00"}, value: secret.FromString("v"), wantErr: secret.ErrInvalidRef},
		{name: "canceled context", ctx: canceled, ref: good, value: secret.FromString("v"), wantErr: context.Canceled},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := &fakeBackend{}
			err := keyring.New(b).Set(tc.ctx, tc.ref, tc.value)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Set error = %v, want %v", err, tc.wantErr)
			}
			if ops := b.opLog(); len(ops) != 0 {
				t.Errorf("backend reached %d times, want none", len(ops))
			}
		})
	}
}

func TestKeyring_DeleteRemovesEntry(t *testing.T) {
	t.Parallel()
	b := &fakeBackend{values: map[[2]string]string{
		{"facto-session", "inst-0001/ileo"}: "synthetic-key",
		{"facto-session", "inst-0001/edf"}:  "synthetic-other",
	}}
	p := keyring.New(b)
	if err := p.Delete(t.Context(), mustRef(t, "keyring://facto-session/inst-0001/ileo")); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	ops := b.opLog()
	want := backendOp{op: "delete", service: "facto-session", user: "inst-0001/ileo"}
	if len(ops) != 1 || ops[0] != want {
		t.Fatalf("backend ops = %+v, want exactly [%+v]", ops, want)
	}
	if len(b.callLog()) != 0 {
		t.Error("Delete read the entry; ADR 0009 deletes without reading")
	}
	if _, err := p.Resolve(t.Context(), mustRef(t, "keyring://facto-session/inst-0001/ileo")); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("Resolve after Delete = %v, want ErrNotFound", err)
	}
	if s, err := p.Resolve(t.Context(), mustRef(t, "keyring://facto-session/inst-0001/edf")); err != nil || s.Expose() != "synthetic-other" {
		t.Errorf("other entry touched by Delete: %v", err)
	}
}

// Delete is idempotent: a missing entry is not an error (ephemeral cleanup
// deletes keys that may never have been written). Choice documented here and
// expected in the Delete doc comment.
func TestKeyring_DeleteMissingIsNotError(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Token)
	tests := []struct {
		name    string
		backend *fakeBackend
	}{
		{name: "no entry", backend: &fakeBackend{}},
		{name: "bare ErrNotFound", backend: &fakeBackend{delErr: keyring.ErrNotFound}},
		{name: "wrapped ErrNotFound quoting text", backend: &fakeBackend{delErr: fmt.Errorf("no item %s: %w", canary, keyring.ErrNotFound)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := keyring.New(tc.backend).Delete(t.Context(), mustRef(t, "keyring://facto-session/inst-0001/ileo")); err != nil {
				t.Errorf("Delete of a missing entry = %v, want nil", err)
			}
		})
	}
}

func TestKeyring_DeleteRejectsBadInput(t *testing.T) {
	t.Parallel()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name    string
		ctx     context.Context
		ref     secret.Ref
		wantErr error
	}{
		{name: "wrong scheme", ctx: context.Background(), ref: secret.Ref{Scheme: "bw", Item: "facto", Field: "k"}, wantErr: secret.ErrInvalidRef},
		{name: "zero ref", ctx: context.Background(), ref: secret.Ref{}, wantErr: secret.ErrInvalidRef},
		{name: "traversal in key", ctx: context.Background(), ref: secret.Ref{Scheme: "keyring", Item: "facto-session", Field: "../login.example/token"}, wantErr: secret.ErrInvalidRef},
		{name: "other service by slash", ctx: context.Background(), ref: secret.Ref{Scheme: "keyring", Item: "facto-session/../login.example", Field: "token"}, wantErr: secret.ErrInvalidRef},
		{name: "unicode dot in service", ctx: context.Background(), ref: secret.Ref{Scheme: "keyring", Item: "login․example", Field: "token"}, wantErr: secret.ErrInvalidRef},
		{name: "canceled context", ctx: canceled, ref: secret.Ref{Scheme: "keyring", Item: "facto", Field: "k"}, wantErr: context.Canceled},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := &fakeBackend{values: map[[2]string]string{{"login.example", "token"}: "synthetic-other-program"}}
			err := keyring.New(b).Delete(tc.ctx, tc.ref)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Delete error = %v, want %v", err, tc.wantErr)
			}
			if ops := b.opLog(); len(ops) != 0 {
				t.Errorf("backend reached: %+v, want no call", ops)
			}
		})
	}
}

// Backend error text may quote the value (some keyrings echo the item data):
// Set and Delete hide it like Resolve does, while errors.Is still reaches the
// backend error. Every rendering goes to an artifact for make leakcheck.
func TestKeyring_SetDeleteErrorsNeverEchoBackendText(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Session)
	errSet := fmt.Errorf("security: could not store item data %q", canary)
	errDel := fmt.Errorf("dbus: delete %s refused", canary)
	tests := []struct {
		name    string
		run     func(p *keyring.Provider) error
		backend *fakeBackend
		wantIs  error
	}{
		{name: "set", backend: &fakeBackend{setErr: errSet}, wantIs: errSet, run: func(p *keyring.Provider) error {
			return p.Set(t.Context(), mustRef(t, "keyring://facto-session/inst-0001/ileo"), secret.FromString(canary))
		}},
		{name: "delete", backend: &fakeBackend{delErr: errDel}, wantIs: errDel, run: func(p *keyring.Provider) error {
			return p.Delete(t.Context(), mustRef(t, "keyring://facto-session/inst-0001/ileo"))
		}},
	}
	var rendered strings.Builder
	for _, tc := range tests {
		err := tc.run(keyring.New(tc.backend))
		if err == nil {
			t.Errorf("%s: nil error, want the backend error", tc.name)
			continue
		}
		if !errors.Is(err, tc.wantIs) {
			t.Errorf("%s: error does not wrap the backend error", tc.name)
		}
		if errors.Is(err, secret.ErrSecretNotFound) {
			t.Errorf("%s: backend failure reported as not found", tc.name)
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			out := fmt.Sprintf(verb, err)
			fmt.Fprintf(&rendered, "%s %s: %s\n", tc.name, verb, out)
			if strings.Contains(out, canary) {
				t.Errorf("%s: error formatted with %s holds backend text", tc.name, verb)
			}
		}
	}
	writeArtifact(t, "keyring-set-delete-errors.txt", rendered.String())
}

// The late result of an abandoned call never reaches the caller: the error
// returned on timeout carries neither the late value nor backend text.
func TestKeyring_TimeoutErrorCarriesNoBackendText(t *testing.T) {
	canary := testsecrets.Canary(t, testsecrets.Password)
	b := newBlockingBackend()
	b.lateValue = canary
	released := false
	t.Cleanup(func() {
		if !released {
			close(b.release)
		}
	})
	timer := newFakeTimer()
	p := keyring.New(b, keyring.WithAfter(timer.After))
	errc := make(chan error, 1)
	go func() { errc <- opGet.run(context.Background(), p) }()
	select {
	case <-timer.requested:
	case <-time.After(guard):
		t.Fatal("Resolve requested no timer")
	}
	timer.fire()
	var err error
	select {
	case err = <-errc:
	case <-time.After(guard):
		t.Fatal("Resolve still blocked after the provider timeout")
	}
	if !errors.Is(err, keyring.ErrTimeout) {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
	var rendered strings.Builder
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		out := fmt.Sprintf(verb, err)
		fmt.Fprintf(&rendered, "%s: %s\n", verb, out)
		if strings.Contains(out, canary) {
			t.Errorf("timeout error formatted with %s holds the late value", verb)
		}
	}
	writeArtifact(t, "keyring-timeout-error.txt", rendered.String())
	released = true
	close(b.release)
	select {
	case <-b.returned:
	case <-time.After(guard):
		t.Fatal("abandoned backend call never returned")
	}
	assertNoProviderGoroutine(t)
}

// setRecorder blocks every Set until release is closed and records the
// value the backend received. Get and Delete are not used.
type setRecorder struct {
	got     chan string
	release chan struct{}
}

func (b *setRecorder) Get(_, _ string) (string, error) { return "", keyring.ErrNotFound }

func (b *setRecorder) Set(_, _, value string) error {
	b.got <- value
	<-b.release
	return nil
}

func (b *setRecorder) Delete(_, _ string) error { return nil }

// A Set abandoned on timeout must still write the value the caller passed,
// even when the caller wipes its Secret right after the timeout: the value
// is taken before the call starts, so a late write never stores "" (which
// would leave an empty keyring entry, treated as missing). The timer is
// already expired when Set starts, so Set returns before its goroutine is
// guaranteed to have run; several rounds make an unsafe ordering show up.
func TestKeyring_SetTimeoutThenWipeNeverWritesEmpty(t *testing.T) {
	t.Parallel()
	expired := func(time.Duration) <-chan time.Time {
		c := make(chan time.Time, 1)
		c <- time.Time{}
		return c
	}
	for i := range 200 {
		b := &setRecorder{got: make(chan string, 1), release: make(chan struct{})}
		p := keyring.New(b, keyring.WithAfter(expired))
		value := secret.FromString("synthetic-key-value")
		err := p.Set(t.Context(), secret.Ref{Scheme: "keyring", Item: "facto", Field: "ileo/session"}, value)
		if !errors.Is(err, keyring.ErrTimeout) {
			close(b.release)
			t.Fatalf("round %d: Set error = %v, want ErrTimeout", i, err)
		}
		value.Wipe()
		close(b.release)
		select {
		case got := <-b.got:
			if got != "synthetic-key-value" {
				t.Fatalf("round %d: late Set wrote %q after the caller wiped its Secret, want the original value", i, got)
			}
		case <-time.After(guard):
			t.Fatalf("round %d: abandoned Set never reached the backend", i)
		}
	}
}
