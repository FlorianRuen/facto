package browser

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// scriptedTransport delivers queued frames and never answers calls.
type scriptedTransport struct {
	in        chan []byte
	closeOnce sync.Once
	closed    chan struct{}
}

func (s *scriptedTransport) Send([]byte) error { return nil }

func (s *scriptedTransport) Recv() ([]byte, error) {
	select {
	case b := <-s.in:
		return b, nil
	case <-s.closed:
		return nil, ErrBrowserGone
	}
}

func (s *scriptedTransport) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

// TestClient_OverflowRunsFatalHook: a full FailClosed queue kills the
// client like any other unusable stream: the fatal hook (which kills the
// browser's process group under StartPipe) runs once.
func TestClient_OverflowRunsFatalHook(t *testing.T) {
	t.Parallel()
	tr := &scriptedTransport{in: make(chan []byte, 8), closed: make(chan struct{})}
	fatal := make(chan struct{}, 4)
	c := newClient(tr, func() { fatal <- struct{}{} })
	t.Cleanup(func() { _ = c.Close() })
	s := c.Subscribe("Fetch.requestPaused", "s1", SubscribeOptions{Buffer: 1, FailClosed: true})
	t.Cleanup(s.Close)
	for range 3 {
		tr.in <- []byte(`{"method":"Fetch.requestPaused","sessionId":"s1","params":{"requestId":"r"}}`)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	select {
	case <-fatal:
	case <-ctx.Done():
		t.Fatal("fatal hook not run after a fail-closed overflow")
	}
	if _, err := c.Call(ctx, "", "Barrier.ping", nil); !errors.Is(err, ErrEventOverflow) {
		t.Errorf("Call = %v, want ErrEventOverflow", err)
	}
	_ = c.Close()
	select {
	case <-fatal:
		t.Error("fatal hook ran twice")
	default:
	}
}
