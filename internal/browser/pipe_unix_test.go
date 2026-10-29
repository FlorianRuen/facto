//go:build unix

// Process-level tests of the CDP pipe (J1 T7, ADR 0008): the real StartPipe
// starts this test binary as a fake browser (fakebrowser_unix_test.go) that
// speaks NUL-delimited JSON on fds 3/4. Expected API: see pipe_api_test.go.
package browser_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// waitLimit bounds every wait on the fake browser (the machine may be
// loaded); a correct implementation is far faster.
const waitLimit = 20 * time.Second

// The real unix StartFunc for Launch.
var _ browser.StartFunc = (&browser.PipeStarter{}).Start

// syncBuffer is a goroutine-safe stderr sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p) //nolint:wrapcheck // bytes.Buffer never fails
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startFake starts the fake browser through the real StartPipe under ctx.
// Cleanup closes it and kills its process group whatever happened.
func startFake(ctx context.Context, t *testing.T) (*browser.PipeProcess, *syncBuffer) {
	t.Helper()
	stderr := &syncBuffer{}
	cmd, err := selfCommand(modeCDP, stderr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := browser.StartPipe(ctx, cmd)
	if err != nil {
		t.Fatalf("StartPipe: %v", err)
	}
	if p == nil {
		t.Fatal("StartPipe returned a nil process and no error")
	}
	pid := p.Pid()
	t.Cleanup(func() {
		_ = p.Close()
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	})
	return p, stderr
}

// call runs one CDP call bounded by waitLimit.
func call(t *testing.T, c *browser.Client, session, method string, params any) (json.RawMessage, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), waitLimit)
	defer cancel()
	return c.Call(ctx, session, method, params)
}

func decodeEcho(t *testing.T, raw json.RawMessage) echoResult {
	t.Helper()
	var e echoResult
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("decode echo result: %v", err)
	}
	return e
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatalf("unmarshal %q: %v", a, err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatalf("unmarshal %q: %v", b, err)
	}
	return reflect.DeepEqual(x, y)
}

// waitDone reports whether p's process exited within waitLimit.
func waitDone(p *browser.PipeProcess) bool {
	select {
	case <-p.Done():
		return true
	case <-time.After(waitLimit):
		return false
	}
}

// waitGone polls until pid no longer runs or waitLimit passes.
func waitGone(pid int) bool {
	deadline := time.After(waitLimit)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for !processGone(pid) {
		select {
		case <-deadline:
			return false
		case <-tick.C:
		}
	}
	return true
}

// spawnChild asks the fake to start a deaf grandchild and returns its pid.
func spawnChild(t *testing.T, c *browser.Client, holdPipe bool) int {
	t.Helper()
	res, err := call(t, c, "", "Fake.spawnChild", map[string]any{"holdPipe": holdPipe})
	if err != nil {
		t.Fatalf("Fake.spawnChild: %v", err)
	}
	var r struct{ Pid int }
	if err := json.Unmarshal(res, &r); err != nil || r.Pid <= 0 {
		t.Fatalf("Fake.spawnChild result %s: %v", res, err)
	}
	t.Cleanup(func() { _ = syscall.Kill(r.Pid, syscall.SIGKILL) })
	return r.Pid
}

func TestPipe_RoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		session string
		params  any
		want    string // params as the browser must see them
	}{
		{name: "browser target", params: map[string]any{"n": 1, "s": `quote " backslash \ slash / é`}, want: `{"n":1,"s":"quote \" backslash \\ slash / é"}`},
		{name: "flat session", session: "SESSION-A", params: map[string]any{"url": "about:blank"}, want: `{"url":"about:blank"}`},
		{name: "no params", params: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, stderr := startFake(t.Context(), t)
			c := p.Client()
			res, err := call(t, c, tt.session, "Fake.echo", tt.params)
			if err != nil {
				t.Fatalf("Call: %v", err)
			}
			e := decodeEcho(t, res)
			if e.Method != "Fake.echo" || e.SessionID != tt.session {
				t.Errorf("browser saw method %q session %q, want Fake.echo %q", e.Method, e.SessionID, tt.session)
			}
			if tt.want == "" {
				if s := string(e.Params); s != "" && s != "null" && s != "{}" {
					t.Errorf("browser saw params %s, want none", s)
				}
			} else if !jsonEqual(t, e.Params, []byte(tt.want)) {
				t.Errorf("browser saw params %s, want %s", e.Params, tt.want)
			}
			if e.Frame != 1 {
				t.Errorf("browser read %d frames, want 1", e.Frame)
			}
			// A second call on the same client gets its own answer.
			res2, err := call(t, c, tt.session, "Fake.echo", map[string]any{"second": true})
			if err != nil {
				t.Fatalf("second Call: %v", err)
			}
			if e2 := decodeEcho(t, res2); e2.Frame != 2 || !jsonEqual(t, e2.Params, []byte(`{"second":true}`)) {
				t.Errorf("second call answered %s, want frame 2 with its own params", res2)
			}

			// Own process group, so teardown can kill the whole tree.
			pid := p.Pid()
			if pgid, err := syscall.Getpgid(pid); err != nil || pgid != pid {
				t.Errorf("Getpgid(browser) = %d, %v; want its own group %d (Setpgid)", pgid, err, pid)
			}
			if pid == os.Getpid() || syscall.Getpgrp() == pid {
				t.Errorf("browser shares the test's process group")
			}

			if err := p.Close(); err != nil {
				t.Errorf("Close = %v, want nil", err)
			}
			if err := p.Close(); err != nil {
				t.Errorf("second Close = %v, want nil (idempotent)", err)
			}
			if !waitDone(p) {
				t.Fatal("Done not closed after Close")
			}
			if !strings.Contains(stderr.String(), fakeStderrMarker) {
				t.Errorf("Command.Stderr did not receive the browser's stderr")
			}
			if _, err := call(t, c, "", "Fake.echo", nil); !errors.Is(err, browser.ErrBrowserGone) {
				t.Errorf("Call after Close = %v, want ErrBrowserGone", err)
			}
		})
	}

	t.Run("PipeStarter is the StartFunc", func(t *testing.T) {
		t.Parallel()
		var s browser.PipeStarter
		if s.Process() != nil {
			t.Fatal("Process() before Start is not nil")
		}
		cmd, err := selfCommand(modeCDP, &syncBuffer{})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Start(t.Context(), cmd); err != nil {
			t.Fatalf("Start: %v", err)
		}
		p := s.Process()
		if p == nil {
			t.Fatal("Process() after Start is nil")
		}
		pid := p.Pid()
		t.Cleanup(func() { _ = p.Close(); _ = syscall.Kill(-pid, syscall.SIGKILL) })
		if _, err := call(t, p.Client(), "", "Fake.echo", nil); err != nil {
			t.Fatalf("Call through PipeStarter: %v", err)
		}
	})
}

func TestPipe_FramingSplitAndCoalesced(t *testing.T) {
	t.Parallel()

	t.Run("reply written one byte at a time", func(t *testing.T) {
		t.Parallel()
		p, _ := startFake(t.Context(), t)
		res, err := call(t, p.Client(), "", "Fake.splitReply", map[string]any{"text": strings.Repeat("s", 5000)})
		if err != nil {
			t.Fatalf("Call: %v", err)
		}
		if e := decodeEcho(t, res); e.Method != "Fake.splitReply" {
			t.Errorf("echo method = %q", e.Method)
		}
	})

	t.Run("replies and an event coalesced in one write, out of call order", func(t *testing.T) {
		t.Parallel()
		p, _ := startFake(t.Context(), t)
		c := p.Client()
		const n = 3
		type out struct {
			res json.RawMessage
			err error
		}
		results := make([]out, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				r, err := call(t, c, "", "Fake.hold", map[string]any{"i": i})
				results[i] = out{r, err}
			})
		}
		if _, err := call(t, c, "", "Fake.flush", map[string]any{"size": n}); err != nil {
			t.Fatalf("flush: %v", err)
		}
		wg.Wait()
		for i, r := range results {
			if r.err != nil {
				t.Fatalf("held call %d: %v", i, r.err)
			}
			if e := decodeEcho(t, r.res); !jsonEqual(t, e.Params, fmt.Appendf(nil, `{"i":%d}`, i)) {
				t.Errorf("held call %d got the answer for %s", i, e.Params)
			}
		}
	})
}

func TestPipe_OversizedMessageRefused(t *testing.T) {
	t.Parallel()
	p, _ := startFake(t.Context(), t)
	pid := p.Pid()
	_, err := call(t, p.Client(), "", "Fake.oversize", map[string]any{"size": browser.MaxMessageBytes + 4096})
	if !errors.Is(err, browser.ErrMessageTooLarge) {
		t.Fatalf("Call(oversized reply) = %v, want ErrMessageTooLarge", err)
	}
	if !waitDone(p) {
		t.Fatal("browser still running after an oversized message, want it killed")
	}
	if !waitGone(pid) {
		t.Errorf("browser pid %d still alive", pid)
	}
	_, err = call(t, p.Client(), "", "Fake.echo", nil)
	if !errors.Is(err, browser.ErrBrowserGone) && !errors.Is(err, browser.ErrMessageTooLarge) {
		t.Errorf("Call after overflow = %v, want ErrBrowserGone or ErrMessageTooLarge", err)
	}
}

func TestPipe_PeerExitFailsPending(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// grandchild: a child of the fake inherits the pipe ends and
		// stderr, so the pipe never reaches EOF: exit must be seen from
		// the process itself.
		grandchild bool
	}{
		{name: "browser exits"},
		{name: "browser exits while a grandchild holds the pipe and stderr", grandchild: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, _ := startFake(t.Context(), t)
			c := p.Client()
			if tt.grandchild {
				spawnChild(t, c, true)
			}
			pending := make(chan error, 1)
			go func() {
				_, err := call(t, c, "SESSION-A", "Fake.hang", nil)
				pending <- err
			}()
			if _, err := call(t, c, "", "Fake.exit", nil); !errors.Is(err, browser.ErrBrowserGone) {
				t.Errorf("Call(Fake.exit) = %v, want ErrBrowserGone", err)
			}
			select {
			case err := <-pending:
				if !errors.Is(err, browser.ErrBrowserGone) {
					t.Errorf("pending call = %v, want ErrBrowserGone", err)
				}
			case <-time.After(waitLimit):
				t.Fatal("pending call still blocked after the browser exited")
			}
			if !waitDone(p) {
				t.Error("Done not closed after the browser exited")
			}
			if _, err := call(t, c, "", "Fake.echo", nil); !errors.Is(err, browser.ErrBrowserGone) {
				t.Errorf("Call after exit = %v, want ErrBrowserGone", err)
			}
		})
	}
}

func TestPipe_ContextCancelKillsProcess(t *testing.T) {
	t.Parallel()

	t.Run("call context cancelled: call fails, browser lives", func(t *testing.T) {
		t.Parallel()
		p, _ := startFake(t.Context(), t)
		c := p.Client()
		ctx, cancel := context.WithCancel(t.Context())
		errc := make(chan error, 1)
		go func() {
			_, err := c.Call(ctx, "", "Fake.hang", nil)
			errc <- err
		}()
		cancel()
		select {
		case err := <-errc:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("cancelled Call = %v, want context.Canceled", err)
			}
		case <-time.After(waitLimit):
			t.Fatal("cancelled Call still blocked")
		}
		select {
		case <-p.Done():
			t.Fatal("a cancelled call killed the browser")
		default:
		}
		if _, err := call(t, c, "", "Fake.echo", nil); err != nil {
			t.Errorf("Call after a cancelled call = %v, want nil", err)
		}
	})

	t.Run("call deadline exceeded", func(t *testing.T) {
		t.Parallel()
		p, _ := startFake(t.Context(), t)
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		if _, err := p.Client().Call(ctx, "", "Fake.hang", nil); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Call past deadline = %v, want context.DeadlineExceeded", err)
		}
	})

	t.Run("process context cancelled: browser killed, pending call fails", func(t *testing.T) {
		t.Parallel()
		lctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		p, _ := startFake(lctx, t)
		pid := p.Pid()
		c := p.Client()
		if _, err := call(t, c, "", "Fake.echo", nil); err != nil {
			t.Fatalf("warm-up Call: %v", err)
		}
		errc := make(chan error, 1)
		go func() {
			_, err := call(t, c, "", "Fake.hang", nil)
			errc <- err
		}()
		cancel()
		select {
		case err := <-errc:
			if !errors.Is(err, browser.ErrBrowserGone) {
				t.Errorf("pending call = %v, want ErrBrowserGone", err)
			}
		case <-time.After(waitLimit):
			t.Fatal("pending call still blocked after the process context was cancelled")
		}
		if !waitDone(p) {
			t.Fatal("browser not reaped after the process context was cancelled")
		}
		if !waitGone(pid) {
			t.Errorf("browser pid %d still alive", pid)
		}
	})
}

func TestPipe_ErrorsNeverEchoPayload(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	tests := []struct {
		name    string
		method  string
		params  map[string]any
		before  string // method called first, error ignored
		wantErr error  // nil: any outcome, but an error must not echo
	}{
		{name: "CDP error object quoting the canary", method: "Fake.cdpError", params: map[string]any{"text": canary}, wantErr: browser.ErrCDP},
		{name: "non-JSON frame quoting the canary", method: "Fake.garbage", params: map[string]any{"text": canary}},
		{name: "oversized message made of the canary", method: "Fake.oversize", params: map[string]any{"text": canary, "size": browser.MaxMessageBytes + 4096}, wantErr: browser.ErrMessageTooLarge},
		{name: "send to an exited browser", before: "Fake.exit", method: "Fake.echo", params: map[string]any{"text": canary}, wantErr: browser.ErrBrowserGone},
		{name: "canary in a session id", method: "Fake.cdpError", params: map[string]any{"text": "x"}, wantErr: browser.ErrCDP},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, stderr := startFake(t.Context(), t)
			c := p.Client()
			session := ""
			if strings.Contains(tt.name, "session id") {
				session = canary
			}
			if tt.before != "" {
				_, _ = call(t, c, "", tt.before, nil)
				waitDone(p)
			}
			_, err := call(t, c, session, tt.method, tt.params)
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("Call = %v, want %v", err, tt.wantErr)
			}
			if err != nil {
				for _, s := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
					if strings.Contains(s, canary) {
						t.Errorf("error echoes the payload: %.200q", s)
					}
				}
			}
			_ = p.Close()
			if strings.Contains(stderr.String(), canary) {
				t.Errorf("browser stderr holds the canary (fake bug)")
			}
		})
	}
}

func TestPipe_ConcurrentSendsNotInterleaved(t *testing.T) {
	t.Parallel()
	p, _ := startFake(t.Context(), t)
	c := p.Client()
	// Each message is far over PIPE_BUF and the pipe buffer, so unguarded
	// writers would interleave and the fake would exit on a corrupt frame.
	const (
		writers = 8
		perG    = 4
		size    = 128 << 10
		letters = "abcdefgh"
	)
	var (
		mu     sync.Mutex
		frames = map[int]bool{}
		wg     sync.WaitGroup
	)
	for g := range writers {
		wg.Go(func() {
			for i := range perG {
				text := fmt.Sprintf("%d/%d:", g, i) + strings.Repeat(letters[g:g+1], size)
				res, err := call(t, c, fmt.Sprintf("SESSION-%d", g), "Fake.echo", map[string]any{"text": text})
				if err != nil {
					t.Errorf("writer %d call %d: %v", g, i, err)
					return
				}
				var e echoResult
				if err := json.Unmarshal(res, &e); err != nil {
					t.Errorf("writer %d call %d: decode: %v", g, i, err)
					return
				}
				var got struct{ Text string }
				if err := json.Unmarshal(e.Params, &got); err != nil || got.Text != text {
					t.Errorf("writer %d call %d: browser saw another payload (len %d)", g, i, len(got.Text))
				}
				mu.Lock()
				if frames[e.Frame] {
					t.Errorf("frame %d answered twice", e.Frame)
				}
				frames[e.Frame] = true
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(frames) != writers*perG {
		t.Errorf("browser read %d distinct frames, want %d", len(frames), writers*perG)
	}
}

func TestPipe_SecretWithNULCannotSplitFrame(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	// A value that, sent raw, would end the frame and inject a command.
	sec := secret.FromString("before\x00{\"id\":1,\"method\":\"Fake.exit\"}\x00after-" + canary)
	defer sec.Wipe()

	p, _ := startFake(t.Context(), t)
	c := p.Client()
	res, err := call(t, c, "SESSION-A", "Fake.echo", map[string]any{"text": sec.Expose()})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	e := decodeEcho(t, res)
	if e.Frame != 1 {
		t.Errorf("browser read %d frames for one call, want 1", e.Frame)
	}
	if bytes.IndexByte(e.Raw, 0) >= 0 {
		t.Error("raw NUL on the wire inside a frame")
	}
	if !bytes.Contains(e.Raw, []byte(`\u0000`)) {
		t.Error("NUL not JSON-escaped as \\u0000 on the wire")
	}
	var got struct{ Text string }
	if err := json.Unmarshal(e.Params, &got); err != nil || got.Text != sec.Expose() {
		t.Error("browser did not receive the exact secret value")
	}
	// No injected frame was executed: the next call is frame 2.
	res, err = call(t, c, "", "Fake.echo", nil)
	if err != nil {
		t.Fatalf("Call after the NUL secret: %v", err)
	}
	if e := decodeEcho(t, res); e.Frame != 2 {
		t.Errorf("next call is frame %d, want 2 (an injected frame was read)", e.Frame)
	}

	// A secret.Secret passed as is is masked, never exposed on the wire.
	res, err = call(t, c, "", "Fake.echo", map[string]any{"text": sec})
	if err != nil {
		t.Fatalf("Call with a secret.Secret param: %v", err)
	}
	if e := decodeEcho(t, res); bytes.Contains(e.Raw, []byte(canary)) {
		t.Error("an unexposed secret.Secret reached the wire in clear")
	}
}

func TestClient_UnknownIDAndSessionIgnored(t *testing.T) {
	t.Parallel()
	for _, session := range []string{"", "SESSION-A"} {
		t.Run("session="+session, func(t *testing.T) {
			t.Parallel()
			p, _ := startFake(t.Context(), t)
			c := p.Client()
			// The fake answers with an unknown id, the right id under
			// another (or a missing) session, an event, the right answer
			// and a late duplicate.
			res, err := call(t, c, session, "Fake.unknown", nil)
			if err != nil {
				t.Fatalf("Call: %v", err)
			}
			if !jsonEqual(t, res, []byte(`{"x":"right"}`)) {
				t.Errorf("result = %s, want the answer matching id and session", res)
			}
			// The duplicate and strays never reach the next call.
			res, err = call(t, c, session, "Fake.echo", map[string]any{"next": true})
			if err != nil {
				t.Fatalf("next Call: %v", err)
			}
			if e := decodeEcho(t, res); e.Method != "Fake.echo" {
				t.Errorf("next call got %s, want its own echo", res)
			}
			select {
			case <-p.Done():
				t.Error("stray responses killed the browser")
			default:
			}
		})
	}
}

func TestLaunch_KillsWholeProcessGroup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		teardown func(p *browser.PipeProcess, cancel context.CancelFunc) error
	}{
		{name: "Close", teardown: func(p *browser.PipeProcess, _ context.CancelFunc) error { return p.Close() }},
		{name: "context cancel", teardown: func(_ *browser.PipeProcess, cancel context.CancelFunc) error { cancel(); return nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			p, _ := startFake(lctx, t)
			pid := p.Pid()
			child := spawnChild(t, p.Client(), true)
			if pgid, err := syscall.Getpgid(child); err != nil || pgid != pid {
				t.Fatalf("grandchild pgid = %d, %v; want the browser's group %d", pgid, err, pid)
			}
			if err := tt.teardown(p, cancel); err != nil {
				t.Errorf("teardown: %v", err)
			}
			if !waitDone(p) {
				t.Error("browser not reaped")
			}
			if !waitGone(pid) {
				t.Errorf("browser pid %d still alive", pid)
			}
			if !waitGone(child) {
				t.Errorf("grandchild pid %d still alive: the process group was not killed", child)
			}
		})
	}
}

// startParentOfFake runs this binary in modeParent: it starts a deaf fake
// browser (ignores pipe EOF) through StartPipe and prints its pid. Returns
// the parent command and the fake's pid; cleanup kills both.
func startParentOfFake(t *testing.T) (*exec.Cmd, int) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	parent := exec.CommandContext(t.Context(), exe) //nolint:gosec // re-executes this test binary
	parent.Env = []string{fakeModeEnv + "=" + modeParent}
	out, err := parent.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := parent.Start(); err != nil {
		t.Fatalf("start parent: %v", err)
	}
	t.Cleanup(func() {
		_ = parent.Process.Kill()
		_ = parent.Wait()
	})
	pid, err := readPidLine(out)
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = syscall.Kill(pid, syscall.SIGKILL)
	})
	if processGone(pid) {
		t.Fatalf("fake browser %d not running", pid)
	}
	return parent, pid
}

// killParent SIGKILLs the parent (no cleanup code runs in it) and reaps it.
func killParent(t *testing.T, parent *exec.Cmd) {
	t.Helper()
	if err := parent.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("kill parent: %v", err)
	}
	_ = parent.Wait()
}
