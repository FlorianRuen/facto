package httpx_test

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
)

// slowRoute is a handler that never answers on its own: it counts the hit,
// signals arrived, then blocks until release is closed. It deliberately never
// watches r.Context(): returning early would hand a still-waiting client an
// empty 200, turning a timeout test into a success.
type slowRoute struct {
	hits    atomic.Int64
	arrived chan struct{}
	release chan struct{}
}

func newSlowRoute() *slowRoute {
	return &slowRoute{arrived: make(chan struct{}, 1), release: make(chan struct{})}
}

func (s *slowRoute) serve(_ http.ResponseWriter, _ *http.Request) {
	s.hits.Add(1)
	select {
	case s.arrived <- struct{}{}:
	default:
	}
	<-s.release
}

// releaseAtCleanup unblocks the handler when the test ends. Call it after
// newEnv: cleanups run last-in first-out and the server's Close waits for
// the blocked handler.
func (s *slowRoute) releaseAtCleanup(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { close(s.release) })
}

// manualDeadline is a parent context whose deadline the test fires by hand.
// Once expired, Done is closed and Err is context.DeadlineExceeded, so the
// child context httpx derives with Options.Timeout ends with the same error
// as a real timeout, with no dependency on wall-clock time.
type manualDeadline struct {
	context.Context

	done chan struct{}
	once sync.Once
}

func (m *manualDeadline) Done() <-chan struct{} { return m.done }

func (m *manualDeadline) Err() error {
	select {
	case <-m.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func (m *manualDeadline) expire() { m.once.Do(func() { close(m.done) }) }

// expireOnArrival returns a context that reaches its deadline as soon as
// the request is blocked inside s (or when the test ends). Requests sent
// with it fail with context.DeadlineExceeded after hitting s exactly once.
func expireOnArrival(t *testing.T, s *slowRoute) context.Context {
	t.Helper()
	// WithoutCancel: values only, so context.Cause cannot reach the test's
	// own cancelCtx through the embedded parent.
	md := &manualDeadline{Context: context.WithoutCancel(t.Context()), done: make(chan struct{})}
	go func() {
		select {
		case <-s.arrived:
		case <-t.Context().Done():
		}
		md.expire()
	}()
	return md
}
