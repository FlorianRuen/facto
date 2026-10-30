package browser_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/httpx/cdploopback"
)

// Extra T7c cases (implementer): lifetime and error mapping of the port
// transport, on every OS.

func TestPortStarter_ContextEndKillsBrowser(t *testing.T) {
	t.Parallel()
	r := newPortRig(t)
	ctx, cancel := context.WithCancel(testCtx(t))
	proc, err := r.start(ctx, emptyProfile(t))
	if err != nil {
		t.Fatalf("start = %v", err)
	}
	cancel()
	waitChan(t, proc.Done(), "Done after the lifetime ctx ended")
	assertKilled(t, r.exec)
	waitChan(t, r.ws.closed, "websocket closed after the lifetime ctx ended")
}

func TestPortStarter_BrowserExitDuringConnectFails(t *testing.T) {
	t.Parallel()
	r := newPortRig(t)
	// The browser dies before writing its port file: the start gives up
	// at once instead of polling until the connect timeout.
	r.exec.onStart = nil
	cfg := r.config()
	cfg.PortFile.Wait = func(ctx context.Context) error {
		_, procs := r.exec.snapshot()
		procs[0].exit()
		<-ctx.Done()
		return fmt.Errorf("wait: %w", ctx.Err())
	}
	proc, err := browser.NewPortStarter(cfg)(testCtx(t), r.cmd(emptyProfile(t)))
	if proc != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("start with the browser gone = %v, %v; want nil, context.Canceled", proc, err)
	}
	if dials, _ := r.seen(); len(dials) != 0 {
		t.Errorf("dialled %+v for a browser that exited", dials)
	}
}

func TestPortStarter_NoExecConfigured(t *testing.T) {
	t.Parallel()
	r := newPortRig(t)
	cfg := r.config()
	cfg.Exec = nil
	if proc, err := browser.NewPortStarter(cfg)(testCtx(t), r.cmd(emptyProfile(t))); proc != nil || !errors.Is(err, browser.ErrLaunchFailed) {
		t.Errorf("start without Exec = %v, %v; want nil, ErrLaunchFailed", proc, err)
	}
}

func TestPortStarter_DialFailureKillsBrowser(t *testing.T) {
	t.Parallel()
	r := newPortRig(t)
	r.dialOK = false
	proc, err := r.start(testCtx(t), emptyProfile(t))
	if proc != nil || !errors.Is(err, browser.ErrLaunchFailed) {
		t.Fatalf("start with a failing dial = %v, %v; want nil, ErrLaunchFailed", proc, err)
	}
	assertKilled(t, r.exec)
}

// writeTestFileCtx is writeTestFile bounded by ctx (a callback's context),
// for callers that hold one.
func writeTestFileCtx(ctx context.Context, t *testing.T, dir, name string, data []byte) {
	t.Helper()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("fsx.Open(%s): %v", dir, err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(ctx, name, data); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// oversizedWS reads through the fake until fail is set, then fails like a
// peer over the message cap.
type oversizedWS struct {
	*fakeWS
	fail atomic.Bool
}

func (w *oversizedWS) ReadMessage(ctx context.Context) ([]byte, error) {
	if w.fail.Load() {
		return nil, fmt.Errorf("frame: %w", cdploopback.ErrMessageTooLarge)
	}
	return w.fakeWS.ReadMessage(ctx)
}

func TestPortTransport_ErrorsMapToTransportSentinels(t *testing.T) {
	t.Parallel()
	ws := &oversizedWS{fakeWS: newFakeWS()}
	answerVersion(t, ws.fakeWS)
	tr := browser.NewPortTransport(ws)
	t.Cleanup(func() { _ = tr.Close() })
	if err := tr.Handshake(testCtx(t)); err != nil {
		t.Fatalf("Handshake = %v", err)
	}
	if err := tr.Handshake(testCtx(t)); err != nil {
		t.Errorf("second Handshake = %v, want nil (already done)", err)
	}
	ws.fail.Store(true)
	if m, err := tr.Recv(); m != nil || !errors.Is(err, browser.ErrMessageTooLarge) {
		t.Errorf("Recv(oversized) = %q, %v; want nil, ErrMessageTooLarge", m, err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
	if err := tr.Send([]byte(`{"id":2,"method":"Browser.getVersion"}`)); err == nil {
		t.Error("Send accepted after Close")
	}
	if writes, _ := ws.snapshot(); len(writes) != 1 {
		t.Errorf("%d messages written, want only the handshake", len(writes))
	}
}

func TestPortFile_DefaultWaitPolls(t *testing.T) {
	t.Parallel()
	var opens atomic.Int32
	open := func(string) (io.ReadCloser, error) {
		// Missing at arm time and at the first read, then written.
		if opens.Add(1) <= 2 {
			return nil, fs.ErrNotExist
		}
		return io.NopCloser(strings.NewReader("9222\n" + testGUIDPath)), nil
	}
	pf, err := browser.ArmPortFile(emptyProfile(t), browser.PortFileConfig{Open: open})
	if err != nil {
		t.Fatalf("ArmPortFile = %v", err)
	}
	got, err := pf.Read(testCtx(t))
	if err != nil || got.Port != 9222 {
		t.Errorf("Read = %+v, %v; want port 9222 after one default wait", got, err)
	}
	if n := opens.Load(); n != 3 {
		t.Errorf("opened %d times, want 3 (arm, missing, written)", n)
	}

	ctx, cancel := context.WithCancel(testCtx(t))
	cancel()
	pf2, err := browser.ArmPortFile(emptyProfile(t), browser.PortFileConfig{Open: func(string) (io.ReadCloser, error) {
		return nil, fs.ErrNotExist
	}})
	if err != nil {
		t.Fatalf("ArmPortFile = %v", err)
	}
	if _, err := pf2.Read(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Read(cancelled ctx) = %v, want context.Canceled", err)
	}
}

// stuckProc is an ExecProcess whose kill fails and which never exits.
type stuckProc struct {
	done  chan struct{}
	kills atomic.Int32
}

func (p *stuckProc) Pid() int              { return testBrowserPID }
func (p *stuckProc) Done() <-chan struct{} { return p.done }
func (p *stuckProc) Kill() error {
	p.kills.Add(1)
	return errors.New("terminate process: access denied")
}

// T7c review S3: a kill that fails is reported, never waited on forever.
func TestPortProcess_CloseDoesNotHangWhenKillFails(t *testing.T) {
	t.Parallel()
	r := newPortRig(t)
	stuck := &stuckProc{done: make(chan struct{})}
	cfg := r.config()
	cfg.Exec = func(context.Context, browser.Command) (browser.ExecProcess, error) {
		r.opener.set([]byte(r.portLine))
		return stuck, nil
	}
	proc, err := browser.NewPortStarter(cfg)(testCtx(t), r.cmd(emptyProfile(t)))
	if err != nil {
		t.Fatalf("start = %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- proc.Close() }()
	select {
	case err := <-closed:
		if err == nil {
			t.Error("Close = nil although the kill failed")
		}
	case <-time.After(portWait):
		t.Fatal("Close blocked on a browser that could not be killed")
	}
	if stuck.kills.Load() == 0 {
		t.Error("Kill never attempted")
	}
	if !chanClosed(r.ws.closed) {
		t.Error("websocket left open")
	}
}
