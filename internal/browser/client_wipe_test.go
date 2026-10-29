// T8 review fixes: frame buffers cleared after Send, and a response that
// overtakes Send's return never holds Call past its context.
package browser_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// aliasWriter keeps the slices handed to Write, without copying them.
type aliasWriter struct {
	mu     sync.Mutex
	writes [][]byte
}

func (w *aliasWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, p)
	return len(p), nil
}

func TestPipeTransport_SendClearsFrameAfterWrite(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	w := &aliasWriter{}
	tr := browser.NewPipeTransport(bytes.NewReader(nil), w)
	msg := []byte(`{"id":1,"method":"Input.insertText","params":{"text":"` + canary + `"}}`)
	if err := tr.Send(msg); err != nil {
		t.Fatalf("Send = %v", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.writes) != 1 {
		t.Fatalf("writes = %d, want 1", len(w.writes))
	}
	if got := w.writes[0]; len(got) != len(msg)+1 || bytes.ContainsFunc(got, func(r rune) bool { return r != 0 }) {
		t.Error("the frame handed to the writer still holds bytes after Send returned")
	}
}

// overtakingTransport answers each request before its Send returns, then
// runs onAnswered and blocks Send until release is closed.
type overtakingTransport struct {
	out        chan []byte
	onAnswered func()
	release    chan struct{}
	closed     chan struct{}
	closeOnce  sync.Once
}

func (o *overtakingTransport) Send(msg []byte) error {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		return fmt.Errorf("%w: fake", browser.ErrBadFrame)
	}
	o.out <- []byte(fmt.Sprintf(`{"id":%d,"result":{"ok":true}}`, req.ID))
	o.onAnswered()
	select {
	case <-o.release:
	case <-o.closed:
	}
	return nil
}

func (o *overtakingTransport) Recv() ([]byte, error) {
	select {
	case b := <-o.out:
		return b, nil
	case <-o.closed:
		return nil, fmt.Errorf("%w: fake closed", browser.ErrBrowserGone)
	}
}

func (o *overtakingTransport) Close() error {
	o.closeOnce.Do(func() { close(o.closed) })
	return nil
}

func TestClient_ResponseBeforeSendReturnsThenCancelled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tr := &overtakingTransport{
		out:     make(chan []byte, 1),
		release: make(chan struct{}),
		closed:  make(chan struct{}),
	}
	answered := make(chan struct{})
	tr.onAnswered = func() { close(answered) }
	c := browser.NewClient(tr)
	t.Cleanup(func() {
		close(tr.release)
		_ = c.Close()
	})

	done := make(chan error, 1)
	go func() {
		_, err := c.Call(ctx, "", "Some.method", nil)
		done <- err
	}()
	<-answered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Call = %v, want context.Canceled (no result before Send returned)", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Call hung after its context was cancelled")
	}
}
