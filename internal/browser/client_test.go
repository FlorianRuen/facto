// In-memory tests of NewClient over any Transport (J1 T7): the browser side
// is a goroutine on io.Pipes, so these run on every OS.
package browser_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// memBrowser answers each request read from in with answer(req), written
// NUL-framed to out. A nil answer sends nothing.
func memBrowser(t *testing.T, answer func(req map[string]any) []string) *browser.Client {
	t.Helper()
	toBrowserR, toBrowserW := io.Pipe()
	fromBrowserR, fromBrowserW := io.Pipe()
	c := browser.NewClient(browser.NewPipeTransport(fromBrowserR, toBrowserW))
	go func() {
		defer func() { _ = fromBrowserW.Close() }()
		r := bufio.NewReader(toBrowserR)
		for {
			raw, err := r.ReadBytes(0)
			if err != nil {
				return
			}
			var req map[string]any
			if json.Unmarshal(raw[:len(raw)-1], &req) != nil {
				return
			}
			for _, a := range answer(req) {
				if _, err := io.WriteString(fromBrowserW, a+"\x00"); err != nil {
					return
				}
			}
		}
	}()
	t.Cleanup(func() {
		_ = c.Close()
		_ = toBrowserR.Close()
	})
	return c
}

func memCall(t *testing.T, c *browser.Client, method string, params any) (json.RawMessage, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	return c.Call(ctx, "", method, params)
}

func TestClient_InMemory(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)

	t.Run("result, CDP error code only, events dropped", func(t *testing.T) {
		t.Parallel()
		c := memBrowser(t, func(req map[string]any) []string {
			id := int64(req["id"].(float64))
			idS, _ := json.Marshal(id)
			switch req["method"] {
			case "Ok.call":
				return []string{`{"method":"Some.event","params":{}}`, `{"id":` + string(idS) + `,"result":{"ok":true}}`}
			default:
				return []string{`{"id":` + string(idS) + `,"error":{"code":-32000,"message":"` + canary + `"}}`}
			}
		})
		res, err := memCall(t, c, "Ok.call", map[string]any{"a": 1})
		if err != nil || string(res) != `{"ok":true}` {
			t.Fatalf("Call = %s, %v; want {\"ok\":true}", res, err)
		}
		_, err = memCall(t, c, "Bad.call", nil)
		if !errors.Is(err, browser.ErrCDP) {
			t.Fatalf("Call = %v, want ErrCDP", err)
		}
		if strings.Contains(err.Error(), canary) || !strings.Contains(err.Error(), "-32000") {
			t.Errorf("CDP error = %q, want the code and no message", err)
		}
	})

	t.Run("cancelled context before the call", func(t *testing.T) {
		t.Parallel()
		c := memBrowser(t, func(map[string]any) []string { return nil })
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := c.Call(ctx, "", "X.y", nil); !errors.Is(err, context.Canceled) {
			t.Errorf("Call = %v, want context.Canceled", err)
		}
	})

	t.Run("unencodable params refused without echo", func(t *testing.T) {
		t.Parallel()
		c := memBrowser(t, func(map[string]any) []string { return nil })
		_, err := memCall(t, c, "X.y", map[string]any{canary: func() {}})
		if !errors.Is(err, browser.ErrBadFrame) {
			t.Fatalf("Call = %v, want ErrBadFrame", err)
		}
		if strings.Contains(err.Error(), canary) {
			t.Errorf("error echoes the payload: %q", err)
		}
	})

	t.Run("closed client", func(t *testing.T) {
		t.Parallel()
		c := memBrowser(t, func(map[string]any) []string { return nil })
		if err := c.Close(); err != nil {
			t.Fatalf("Close = %v", err)
		}
		if err := c.Close(); err != nil {
			t.Errorf("second Close = %v, want nil", err)
		}
		if _, err := memCall(t, c, "X.y", nil); !errors.Is(err, browser.ErrBrowserGone) {
			t.Errorf("Call after Close = %v, want ErrBrowserGone", err)
		}
	})

	t.Run("write failure kills the client", func(t *testing.T) {
		t.Parallel()
		r, w := io.Pipe()
		_ = r.Close() // the browser stopped reading
		fr, _ := io.Pipe()
		c := browser.NewClient(browser.NewPipeTransport(fr, w))
		t.Cleanup(func() { _ = c.Close() })
		if _, err := memCall(t, c, "X.y", nil); !errors.Is(err, browser.ErrBrowserGone) {
			t.Errorf("Call = %v, want ErrBrowserGone", err)
		}
		if _, err := memCall(t, c, "X.y", nil); !errors.Is(err, browser.ErrBrowserGone) {
			t.Errorf("second Call = %v, want ErrBrowserGone", err)
		}
	})
}

func TestPipeTransport_SendAfterClose(t *testing.T) {
	t.Parallel()
	_, w := io.Pipe()
	r, _ := io.Pipe()
	tr := browser.NewPipeTransport(r, w)
	if err := tr.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if err := tr.Send([]byte(`{}`)); !errors.Is(err, browser.ErrBrowserGone) {
		t.Errorf("Send after Close = %v, want ErrBrowserGone", err)
	}
	if _, err := tr.Recv(); !errors.Is(err, browser.ErrBrowserGone) {
		t.Errorf("Recv after Close = %v, want ErrBrowserGone", err)
	}
}

// stuckTransport is a browser that stops reading: Send blocks until
// release is closed, then fails like a broken pipe.
type stuckTransport struct {
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func (s *stuckTransport) Send([]byte) error {
	<-s.release
	return fmt.Errorf("%w: write: broken pipe", browser.ErrBrowserGone)
}

func (s *stuckTransport) Recv() ([]byte, error) {
	<-s.closed
	return nil, fmt.Errorf("%w: closed", browser.ErrBrowserGone)
}

func (s *stuckTransport) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

// TestClient_WriteErrorAfterCallReturnedKillsClient: a write that fails
// after its Call already returned on ctx still kills the client, since the
// stream may hold a partial frame.
func TestClient_WriteErrorAfterCallReturnedKillsClient(t *testing.T) {
	t.Parallel()
	tr := &stuckTransport{release: make(chan struct{}), closed: make(chan struct{})}
	c := browser.NewClient(tr)
	t.Cleanup(func() { _ = c.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Call(ctx, "", "X.y", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Call = %v, want context.DeadlineExceeded", err)
	}
	close(tr.release) // the blocked write now fails
	select {
	case <-tr.closed: // the client died and closed its transport
	case <-time.After(20 * time.Second):
		t.Fatal("a failed write after Call returned did not kill the client")
	}
	if _, err := memCall(t, c, "X.y", nil); !errors.Is(err, browser.ErrBrowserGone) {
		t.Errorf("Call after the failed write = %v, want ErrBrowserGone", err)
	}
}
