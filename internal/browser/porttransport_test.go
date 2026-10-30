// Windows port-0 transport tests (J1 T7c), platform-neutral: the expected
// API is in the header of portfile_test.go. The browser process is an
// ExecProcess double, the WebSocket a WSConn double (bridged to the fakeCDP
// peer of fakecdp_test.go when a page is needed) and the TCP table an
// injected ListenerPID, so every case runs on Linux too.
package browser_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx/cdploopback"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

var (
	_ browser.Transport = (*browser.PortTransport)(nil)
	_ browser.WSConn    = (*cdploopback.Conn)(nil)
	_ browser.WSConn    = (*fakeWS)(nil)
	_ browser.Starter   = browser.NewPortStarter(browser.PortStarterConfig{})
)

// portWait bounds every wait of these tests (no sleep: channels only).
const portWait = 20 * time.Second

// testBrowserPID is the pid the fake exec hands out; testOtherPID belongs to
// "another local process".
const (
	testBrowserPID = 4242
	testOtherPID   = 31337
)

func waitChan(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(portWait):
		t.Fatalf("%s: not done within %v", what, portWait)
	}
}

func chanClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// fakeWS is a WSConn double. Writes are recorded (copied) and handed to
// onWrite; in feeds ReadMessage.
type fakeWS struct {
	mu      sync.Mutex
	writes  [][]byte
	reads   int
	onWrite func(msg []byte)

	in     chan []byte
	closed chan struct{}
	once   sync.Once
}

func newFakeWS() *fakeWS {
	return &fakeWS{in: make(chan []byte, 1024), closed: make(chan struct{})}
}

func (w *fakeWS) ReadMessage(ctx context.Context) ([]byte, error) {
	w.mu.Lock()
	w.reads++
	w.mu.Unlock()
	select {
	case m := <-w.in:
		return m, nil
	case <-w.closed:
		return nil, cdploopback.ErrClosed
	case <-ctx.Done():
		return nil, fmt.Errorf("fake ws: %w", ctx.Err())
	}
}

func (w *fakeWS) WriteMessage(_ context.Context, p []byte) error {
	if chanClosed(w.closed) {
		return cdploopback.ErrClosed
	}
	msg := slices.Clone(p)
	w.mu.Lock()
	w.writes = append(w.writes, msg)
	hook := w.onWrite
	w.mu.Unlock()
	if hook != nil {
		hook(msg)
	}
	return nil
}

func (w *fakeWS) Close() error {
	w.once.Do(func() { close(w.closed) })
	return nil
}

func (w *fakeWS) push(s string) { w.in <- []byte(s) }

func (w *fakeWS) snapshot() (writes []string, reads int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, m := range w.writes {
		writes = append(writes, string(m))
	}
	return writes, w.reads
}

func (w *fakeWS) setOnWrite(fn func(msg []byte)) {
	w.mu.Lock()
	w.onWrite = fn
	w.mu.Unlock()
}

// wsRequest decodes the id and method of a request written to the peer.
func wsRequest(t *testing.T, msg []byte) (int64, string) {
	t.Helper()
	var req struct {
		ID     int64  `json:"id"`
		Method string `json:"method"`
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		t.Errorf("request written to the browser is not JSON")
	}
	return req.ID, req.Method
}

// versionResult is a synthetic Browser.getVersion result.
var versionResult = map[string]any{
	"protocolVersion": "1.3",
	"product":         "HeadlessChrome/140.0.0.0",
	"revision":        "@0000000000000000000000000000000000000000",
	"userAgent":       "Mozilla/5.0 (synthetic)",
	"jsVersion":       "14.0.0",
}

// answerVersion makes ws answer Browser.getVersion like Chrome.
func answerVersion(t *testing.T, ws *fakeWS) {
	t.Helper()
	ws.setOnWrite(func(msg []byte) {
		id, method := wsRequest(t, msg)
		if method != "Browser.getVersion" {
			return
		}
		b, err := json.Marshal(map[string]any{"id": id, "result": versionResult})
		if err != nil {
			t.Errorf("marshal version: %v", err)
			return
		}
		ws.in <- b
	})
}

// bridge connects ws to the fakeCDP peer f (which also answers
// Browser.getVersion), so a Page can run over a PortTransport.
func bridge(t *testing.T, ws *fakeWS, f *fakeCDP) {
	t.Helper()
	f.setOverride("Browser.getVersion", func(cdpCall) any { return versionResult })
	ws.setOnWrite(func(msg []byte) { _ = f.Send(msg) })
	go func() {
		for {
			b, err := f.Recv()
			if err != nil {
				return
			}
			select {
			case ws.in <- b:
			case <-ws.closed:
				return
			}
		}
	}()
	t.Cleanup(func() { _ = f.Close() })
}

// fakeExecProc is an ExecProcess double.
type fakeExecProc struct {
	pid   int
	done  chan struct{}
	once  sync.Once
	kills atomic.Int32
}

func (p *fakeExecProc) Pid() int              { return p.pid }
func (p *fakeExecProc) Done() <-chan struct{} { return p.done }
func (p *fakeExecProc) Kill() error {
	p.kills.Add(1)
	p.exit()
	return nil
}
func (p *fakeExecProc) exit() { p.once.Do(func() { close(p.done) }) }

// fakeExec is a PortStarterConfig.Exec double.
type fakeExec struct {
	mu      sync.Mutex
	calls   []browser.Command
	procs   []*fakeExecProc
	err     error
	onStart func(cmd browser.Command) // runs once the process "started"
}

func (e *fakeExec) exec(_ context.Context, cmd browser.Command) (browser.ExecProcess, error) {
	e.mu.Lock()
	c := cmd
	c.Args = slices.Clone(cmd.Args)
	e.calls = append(e.calls, c)
	if e.err != nil {
		e.mu.Unlock()
		return nil, e.err
	}
	p := &fakeExecProc{pid: testBrowserPID, done: make(chan struct{})}
	e.procs = append(e.procs, p)
	hook := e.onStart
	e.mu.Unlock()
	if hook != nil {
		hook(cmd)
	}
	return p, nil
}

func (e *fakeExec) snapshot() ([]browser.Command, []*fakeExecProc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.calls), slices.Clone(e.procs)
}

// windowsArgv is the windows release argv (Flags) with --user-data-dir
// pointed at profile, a directory of the test host.
func windowsArgv(t *testing.T, profile string) []string {
	t.Helper()
	args := mustFlags(t, opts("windows"))
	out := make([]string, 0, len(args))
	n := 0
	for _, a := range args {
		if strings.HasPrefix(a, "--user-data-dir=") {
			a = "--user-data-dir=" + profile
			n++
		}
		out = append(out, a)
	}
	if n != 1 {
		t.Fatalf("windows argv %q: %d --user-data-dir switches, want 1", args, n)
	}
	return out
}

// portRig wires NewPortStarter to doubles: the port file appears (with
// portLine) only once Exec has started the process.
type portRig struct {
	t        *testing.T
	exec     *fakeExec
	opener   *portOpener
	ws       *fakeWS
	portLine string // DevToolsActivePort content written at start

	mu        sync.Mutex
	dials     []browser.DevToolsTarget
	lookups   []int
	listener  func(ctx context.Context, port int) (int, error)
	dialOK    bool // false: Dial returns an error
	nilDial   bool // true: PortStarterConfig.Dial left nil (DialLoopback)
	nilLookup bool
}

func newPortRig(t *testing.T) *portRig {
	t.Helper()
	r := &portRig{
		t:        t,
		exec:     &fakeExec{},
		opener:   &portOpener{},
		ws:       newFakeWS(),
		portLine: "40123\n" + testGUIDPath,
		dialOK:   true,
	}
	r.listener = func(context.Context, int) (int, error) { return testBrowserPID, nil }
	r.exec.onStart = func(browser.Command) { r.opener.set([]byte(r.portLine)) }
	answerVersion(t, r.ws)
	return r
}

func (r *portRig) config() browser.PortStarterConfig {
	cfg := browser.PortStarterConfig{
		Exec:     r.exec.exec,
		PortFile: browser.PortFileConfig{Open: r.opener.open, Wait: immediateWait},
		ListenerPID: func(ctx context.Context, port int) (int, error) {
			r.mu.Lock()
			r.lookups = append(r.lookups, port)
			fn := r.listener
			r.mu.Unlock()
			return fn(ctx, port)
		},
		Dial: func(_ context.Context, tg browser.DevToolsTarget) (browser.WSConn, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.dials = append(r.dials, tg)
			if !r.dialOK {
				return nil, errors.New("fake dial refused")
			}
			return r.ws, nil
		},
	}
	if r.nilDial {
		cfg.Dial = nil
	}
	if r.nilLookup {
		cfg.ListenerPID = nil
	}
	return cfg
}

func (r *portRig) cmd(profile string) browser.Command {
	r.t.Helper()
	return browser.Command{Path: `C:\facto-test\chrome.exe`, Args: windowsArgv(r.t, profile)}
}

func (r *portRig) start(ctx context.Context, profile string) (browser.Process, error) {
	r.t.Helper()
	proc, err := browser.NewPortStarter(r.config())(ctx, r.cmd(profile))
	if proc != nil {
		r.t.Cleanup(func() { _ = proc.Close() })
	}
	return proc, err
}

func (r *portRig) seen() (dials []browser.DevToolsTarget, lookups []int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.dials), slices.Clone(r.lookups)
}

// assertKilled checks that every exec'd process was killed and reaped.
func assertKilled(t *testing.T, e *fakeExec) {
	t.Helper()
	_, procs := e.snapshot()
	for i, p := range procs {
		if p.kills.Load() == 0 || !chanClosed(p.done) {
			t.Errorf("process %d (pid %d) not killed after the failed start", i, p.pid)
		}
	}
}

// dialSpy is a cdploopback.Dialer that records and refuses every dial.
type dialSpy struct {
	mu    sync.Mutex
	calls []string
}

func (d *dialSpy) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, network+" "+address)
	d.mu.Unlock()
	return nil, errors.New("dial spy: refused")
}

func (d *dialSpy) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.calls)
}

func TestPortTransport_DialsLoopbackOnly(t *testing.T) {
	t.Parallel()

	t.Run("DialLoopback dials 127.0.0.1:<port> over tcp4 once", func(t *testing.T) {
		t.Parallel()
		spy := &dialSpy{}
		conn, err := browser.DialLoopback(testCtx(t), browser.DevToolsTarget{Port: 40123, Path: testGUIDPath}, cdploopback.WithDialer(spy))
		if conn != nil || err == nil {
			t.Fatalf("DialLoopback over a refusing dialer = %v, %v; want an error", conn, err)
		}
		if got, want := spy.snapshot(), []string{"tcp4 127.0.0.1:40123"}; !slices.Equal(got, want) {
			t.Errorf("dials = %q, want %q", got, want)
		}
	})

	t.Run("invalid target never dialled", func(t *testing.T) {
		t.Parallel()
		for _, tg := range []browser.DevToolsTarget{
			{Port: 0, Path: testGUIDPath},
			{Port: 65536, Path: testGUIDPath},
			{Port: -1, Path: testGUIDPath},
			{Port: 9222, Path: "/json/version"},
			{Port: 9222, Path: "//attacker.example" + testGUIDPath},
			{Port: 9222, Path: "/devtools/page/" + testGUID},
			{Port: 9222, Path: testGUIDPath + "\r\nHost: attacker.example"},
			{Port: 9222, Path: ""},
		} {
			spy := &dialSpy{}
			if conn, err := browser.DialLoopback(testCtx(t), tg, cdploopback.WithDialer(spy)); conn != nil || err == nil {
				t.Errorf("DialLoopback(%+v) = %v, %v; want refused", tg, conn, err)
			}
			if got := spy.snapshot(); len(got) != 0 {
				t.Errorf("DialLoopback(%+v) dialled %q, want nothing", tg, got)
			}
		}
	})

	t.Run("starter dials the port of the file", func(t *testing.T) {
		t.Parallel()
		r := newPortRig(t)
		r.portLine = "51234\n" + testGUIDPath
		if _, err := r.start(testCtx(t), emptyProfile(t)); err != nil {
			t.Fatalf("start = %v", err)
		}
		dials, lookups := r.seen()
		if want := []browser.DevToolsTarget{{Port: 51234, Path: testGUIDPath}}; !slices.Equal(dials, want) {
			t.Errorf("dials = %+v, want %+v", dials, want)
		}
		if !slices.Equal(lookups, []int{51234}) {
			t.Errorf("listener lookups = %v, want [51234]", lookups)
		}
	})

	t.Run("default dial reaches the loopback listener of the file", func(t *testing.T) {
		t.Parallel()
		ln, err := (&net.ListenConfig{}).Listen(testCtx(t), "tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		port := ln.Addr().(*net.TCPAddr).Port
		accepted := make(chan netip.AddrPort, 4)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted <- c.LocalAddr().(*net.TCPAddr).AddrPort()
				_ = c.Close() // no WebSocket: the handshake fails
			}
		}()
		r := newPortRig(t)
		r.nilDial = true
		r.portLine = strconv.Itoa(port) + "\n" + testGUIDPath
		proc, err := r.start(testCtx(t), emptyProfile(t))
		if proc != nil || err == nil {
			t.Fatalf("start against a non-WebSocket listener = %v, %v; want an error", proc, err)
		}
		select {
		case got := <-accepted:
			if want := netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(port)); got != want {
				t.Errorf("connection accepted on %v, want %v", got, want)
			}
		case <-time.After(portWait):
			t.Fatal("the loopback listener named by the file was never dialled")
		}
		assertKilled(t, r.exec)
	})
}

func TestPortTransport_NoSecretBeforeHandshake(t *testing.T) {
	t.Parallel()

	t.Run("Send and Recv refused before the handshake", func(t *testing.T) {
		t.Parallel()
		canary := testsecrets.Canary(t, testsecrets.Password)
		ws := newFakeWS()
		ws.push(`{"id":1,"result":{}}`)
		tr := browser.NewPortTransport(ws)
		t.Cleanup(func() { _ = tr.Close() })
		msg := []byte(`{"id":1,"method":"Input.insertText","params":{"text":"` + canary + `"}}`)
		if err := tr.Send(msg); !errors.Is(err, browser.ErrNoHandshake) {
			t.Errorf("Send before handshake = %v, want ErrNoHandshake", err)
		}
		if m, err := tr.Recv(); m != nil || !errors.Is(err, browser.ErrNoHandshake) {
			t.Errorf("Recv before handshake = %q, %v; want nil, ErrNoHandshake", m, err)
		}
		writes, reads := ws.snapshot()
		if len(writes) != 0 || reads != 0 {
			t.Errorf("conn used before the handshake: %d writes, %d reads", len(writes), reads)
		}
	})

	t.Run("client call before the handshake refused", func(t *testing.T) {
		t.Parallel()
		canary := testsecrets.Canary(t, testsecrets.Password)
		ws := newFakeWS()
		answerVersion(t, ws)
		c := browser.NewClient(browser.NewPortTransport(ws))
		t.Cleanup(func() { _ = c.Close() })
		_, err := c.Call(testCtx(t), "", "Input.insertText", map[string]any{"text": canary})
		if !errors.Is(err, browser.ErrNoHandshake) {
			t.Errorf("Call before handshake = %v, want ErrNoHandshake", err)
		}
		writes, _ := ws.snapshot()
		for _, w := range writes {
			if strings.Contains(w, canary) {
				t.Fatal("secret reached the browser before the handshake")
			}
		}
		if len(writes) != 0 {
			t.Errorf("%d messages written before the handshake, want 0", len(writes))
		}
	})

	t.Run("getVersion first, then calls flow", func(t *testing.T) {
		t.Parallel()
		canary := testsecrets.Canary(t, testsecrets.Password)
		ws := newFakeWS()
		answerVersion(t, ws)
		tr := browser.NewPortTransport(ws)
		if err := tr.Handshake(testCtx(t)); err != nil {
			t.Fatalf("Handshake = %v", err)
		}
		writes, _ := ws.snapshot()
		if len(writes) != 1 {
			t.Fatalf("handshake wrote %d messages, want exactly 1", len(writes))
		}
		if _, m := wsRequest(t, []byte(writes[0])); m != "Browser.getVersion" {
			t.Errorf("first message method %q, want Browser.getVersion", m)
		}
		ws.setOnWrite(func(msg []byte) {
			id, _ := wsRequest(t, msg)
			ws.push(fmt.Sprintf(`{"id":%d,"result":{}}`, id))
		})
		c := browser.NewClient(tr)
		t.Cleanup(func() { _ = c.Close() })
		if _, err := c.Call(testCtx(t), "", "Input.insertText", map[string]any{"text": canary}); err != nil {
			t.Fatalf("Call after handshake = %v", err)
		}
		writes, _ = ws.snapshot()
		if len(writes) != 2 || !strings.Contains(writes[1], canary) {
			t.Errorf("writes after handshake = %d, want getVersion then the call", len(writes))
		}
	})

	t.Run("starter handshakes before handing out the client", func(t *testing.T) {
		t.Parallel()
		r := newPortRig(t)
		proc, err := r.start(testCtx(t), emptyProfile(t))
		if err != nil {
			t.Fatalf("start = %v", err)
		}
		if proc.Client() == nil {
			t.Fatal("Process.Client() = nil")
		}
		writes, _ := r.ws.snapshot()
		if len(writes) == 0 {
			t.Fatal("no handshake written")
		}
		if _, m := wsRequest(t, []byte(writes[0])); m != "Browser.getVersion" {
			t.Errorf("first message method %q, want Browser.getVersion", m)
		}
	})

	failures := []struct {
		name string
		peer func(t *testing.T, ws *fakeWS) // answers the getVersion request
	}{
		{"cdp error", func(t *testing.T, ws *fakeWS) {
			ws.setOnWrite(func(msg []byte) {
				id, _ := wsRequest(t, msg)
				ws.push(fmt.Sprintf(`{"id":%d,"error":{"code":-32601,"message":"no"}}`, id))
			})
		}},
		{"event first", func(t *testing.T, ws *fakeWS) {
			ws.setOnWrite(func(msg []byte) {
				id, _ := wsRequest(t, msg)
				ws.push(`{"method":"Target.targetCreated","params":{}}`)
				ws.push(fmt.Sprintf(`{"id":%d,"result":{"protocolVersion":"1.3","product":"Chrome/140"}}`, id))
			})
		}},
		{"other id", func(t *testing.T, ws *fakeWS) {
			ws.setOnWrite(func(msg []byte) {
				id, _ := wsRequest(t, msg)
				ws.push(fmt.Sprintf(`{"id":%d,"result":{"protocolVersion":"1.3","product":"Chrome/140"}}`, id+1))
			})
		}},
		{"session response", func(t *testing.T, ws *fakeWS) {
			ws.setOnWrite(func(msg []byte) {
				id, _ := wsRequest(t, msg)
				ws.push(fmt.Sprintf(`{"id":%d,"sessionId":"s1","result":{"protocolVersion":"1.3","product":"Chrome/140"}}`, id))
			})
		}},
		{"empty result", func(t *testing.T, ws *fakeWS) {
			ws.setOnWrite(func(msg []byte) {
				id, _ := wsRequest(t, msg)
				ws.push(fmt.Sprintf(`{"id":%d,"result":{}}`, id))
			})
		}},
		{"product not a string", func(t *testing.T, ws *fakeWS) {
			ws.setOnWrite(func(msg []byte) {
				id, _ := wsRequest(t, msg)
				ws.push(fmt.Sprintf(`{"id":%d,"result":{"protocolVersion":"1.3","product":7}}`, id))
			})
		}},
		{"not json", func(_ *testing.T, ws *fakeWS) {
			ws.setOnWrite(func([]byte) { ws.push("HTTP/1.1 200 OK") })
		}},
		{"peer closes", func(_ *testing.T, ws *fakeWS) {
			ws.setOnWrite(func([]byte) { _ = ws.Close() })
		}},
	}
	for _, tc := range failures {
		t.Run("handshake fails: "+tc.name, func(t *testing.T) {
			t.Parallel()
			ws := newFakeWS()
			tc.peer(t, ws)
			tr := browser.NewPortTransport(ws)
			if err := tr.Handshake(testCtx(t)); !errors.Is(err, browser.ErrHandshake) {
				t.Fatalf("Handshake = %v, want ErrHandshake", err)
			}
			if !chanClosed(ws.closed) {
				t.Error("conn left open after a failed handshake")
			}
			if err := tr.Send([]byte(`{"id":9,"method":"Input.insertText"}`)); err == nil {
				t.Error("Send accepted after a failed handshake")
			}
		})
	}

	t.Run("handshake fails: silent peer bounded by ctx", func(t *testing.T) {
		t.Parallel()
		ws := newFakeWS()
		tr := browser.NewPortTransport(ws)
		ctx, cancel := context.WithCancel(testCtx(t))
		ws.setOnWrite(func([]byte) { cancel() })
		if err := tr.Handshake(ctx); !errors.Is(err, browser.ErrHandshake) {
			t.Fatalf("Handshake(silent peer) = %v, want ErrHandshake", err)
		}
		if !chanClosed(ws.closed) {
			t.Error("conn left open after a failed handshake")
		}
	})

	t.Run("starter kills the browser when the handshake fails", func(t *testing.T) {
		t.Parallel()
		r := newPortRig(t)
		r.ws.setOnWrite(func(msg []byte) {
			id, _ := wsRequest(t, msg)
			r.ws.push(fmt.Sprintf(`{"id":%d,"error":{"code":-32000}}`, id))
		})
		proc, err := r.start(testCtx(t), emptyProfile(t))
		if proc != nil || !errors.Is(err, browser.ErrHandshake) {
			t.Fatalf("start = %v, %v; want nil, ErrHandshake", proc, err)
		}
		assertKilled(t, r.exec)
	})
}

func TestPortTransport_ListenerPIDMustBeBrowser(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		listener  func(context.Context, int) (int, error)
		nilLookup bool
		wantErr   bool
	}{
		{name: "browser pid", listener: func(context.Context, int) (int, error) { return testBrowserPID, nil }},
		{name: "another process", wantErr: true, listener: func(context.Context, int) (int, error) { return testOtherPID, nil }},
		{name: "pid 0", wantErr: true, listener: func(context.Context, int) (int, error) { return 0, nil }},
		{name: "lookup error", wantErr: true, listener: func(context.Context, int) (int, error) {
			return testBrowserPID, errors.New("tcp table unavailable")
		}},
		{name: "no lookup configured", wantErr: true, nilLookup: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newPortRig(t)
			if tc.listener != nil {
				r.listener = tc.listener
			}
			r.nilLookup = tc.nilLookup
			proc, err := r.start(testCtx(t), emptyProfile(t))
			dials, lookups := r.seen()
			if !tc.wantErr {
				if err != nil || proc == nil {
					t.Fatalf("start = %v, %v; want a process", proc, err)
				}
				if !slices.Equal(lookups, []int{40123}) {
					t.Errorf("lookups = %v, want [40123] (the port of the file)", lookups)
				}
				return
			}
			if proc != nil || !errors.Is(err, browser.ErrListenerNotBrowser) {
				t.Fatalf("start = %v, %v; want nil, ErrListenerNotBrowser", proc, err)
			}
			if len(dials) != 0 {
				t.Errorf("dialled %+v although the listener is not the browser", dials)
			}
			assertKilled(t, r.exec)
		})
	}

	t.Run("ConnectPort checks before dialling", func(t *testing.T) {
		t.Parallel()
		o := &portOpener{}
		pf := armed(t, o, immediateWait)
		o.set([]byte("40123\n" + testGUIDPath))
		dialled := false
		tr, err := browser.ConnectPort(testCtx(t), browser.PortConnectConfig{
			PortFile:    pf,
			BrowserPID:  testBrowserPID,
			ListenerPID: func(context.Context, int) (int, error) { return testOtherPID, nil },
			Dial: func(context.Context, browser.DevToolsTarget) (browser.WSConn, error) {
				dialled = true
				return newFakeWS(), nil
			},
		})
		if tr != nil || !errors.Is(err, browser.ErrListenerNotBrowser) || dialled {
			t.Errorf("ConnectPort(foreign listener) = %v, %v, dialled %v; want nil, ErrListenerNotBrowser, false", tr, err, dialled)
		}
	})
}

func TestListenerPID_LoopbackRowOnly(t *testing.T) {
	t.Parallel()
	row := func(addr string, pid int) browser.TCPListener {
		return browser.TCPListener{Addr: netip.MustParseAddrPort(addr), PID: pid}
	}
	tests := []struct {
		name    string
		rows    []browser.TCPListener
		want    int
		wantErr bool
	}{
		{name: "single loopback listener", rows: []browser.TCPListener{row("127.0.0.1:9222", testBrowserPID)}, want: testBrowserPID},
		{name: "other ports ignored", rows: []browser.TCPListener{
			row("0.0.0.0:445", 4), row("127.0.0.1:9222", testBrowserPID), row("127.0.0.1:9223", testOtherPID),
		}, want: testBrowserPID},
		{name: "no listener", rows: []browser.TCPListener{row("127.0.0.1:9223", testBrowserPID)}, wantErr: true},
		{name: "empty table", wantErr: true},
		{name: "all interfaces", rows: []browser.TCPListener{row("0.0.0.0:9222", testBrowserPID)}, wantErr: true},
		{name: "loopback plus all interfaces", rows: []browser.TCPListener{
			row("127.0.0.1:9222", testBrowserPID), row("0.0.0.0:9222", testOtherPID),
		}, wantErr: true},
		{name: "ipv6 loopback", rows: []browser.TCPListener{row("[::1]:9222", testBrowserPID)}, wantErr: true},
		{name: "ipv6 any next to loopback", rows: []browser.TCPListener{
			row("[::]:9222", testOtherPID), row("127.0.0.1:9222", testBrowserPID),
		}, wantErr: true},
		{name: "v4-mapped loopback", rows: []browser.TCPListener{row("[::ffff:127.0.0.1]:9222", testBrowserPID)}, wantErr: true},
		{name: "other loopback address", rows: []browser.TCPListener{row("127.0.0.2:9222", testBrowserPID)}, wantErr: true},
		{name: "two loopback owners", rows: []browser.TCPListener{
			row("127.0.0.1:9222", testBrowserPID), row("127.0.0.1:9222", testOtherPID),
		}, wantErr: true},
		{name: "pid 0", rows: []browser.TCPListener{row("127.0.0.1:9222", 0)}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := browser.LoopbackListenerPID(tc.rows, 9222)
			if tc.wantErr {
				if !errors.Is(err, browser.ErrListenerNotBrowser) {
					t.Errorf("LoopbackListenerPID = %d, %v; want ErrListenerNotBrowser", got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("LoopbackListenerPID = %d, %v; want %d", got, err, tc.want)
			}
		})
	}
}

func TestPortTransport_ClosedRightAfterLogin(t *testing.T) {
	t.Parallel()

	t.Run("process Close closes the websocket and kills the browser", func(t *testing.T) {
		t.Parallel()
		r := newPortRig(t)
		proc, err := r.start(testCtx(t), emptyProfile(t))
		if err != nil {
			t.Fatalf("start = %v", err)
		}
		if proc.Pid() != testBrowserPID {
			t.Errorf("Pid() = %d, want %d", proc.Pid(), testBrowserPID)
		}
		if err := proc.Close(); err != nil {
			t.Fatalf("Close = %v", err)
		}
		if !chanClosed(r.ws.closed) {
			t.Error("websocket still open after Close")
		}
		assertKilled(t, r.exec)
		if !chanClosed(proc.Done()) {
			t.Error("Done not closed after Close returned")
		}
		if err := proc.Close(); err != nil {
			t.Errorf("second Close = %v, want nil (idempotent)", err)
		}
	})

	t.Run("browser exit ends the process", func(t *testing.T) {
		t.Parallel()
		r := newPortRig(t)
		proc, err := r.start(testCtx(t), emptyProfile(t))
		if err != nil {
			t.Fatalf("start = %v", err)
		}
		_, procs := r.exec.snapshot()
		procs[0].exit()
		waitChan(t, proc.Done(), "Done after the browser exited")
	})

	t.Run("lease Close after login", func(t *testing.T) {
		t.Parallel()
		r := newPortRig(t)
		f := newFakeCDP(t)
		bridge(t, r.ws, f)
		port := browser.NewPortStarter(r.config())
		// The pool builds the host's argv (pipe on linux): rewrite it to the
		// windows release argv on the same profile, as Prepare would on
		// windows.
		start := func(ctx context.Context, cmd browser.Command) (browser.Process, error) {
			prof := ""
			for _, a := range cmd.Args {
				if v, ok := strings.CutPrefix(a, "--user-data-dir="); ok {
					prof = v
				}
			}
			cmd.Args = windowsArgv(t, prof)
			return port(ctx, cmd)
		}
		h := testHost(t, nil)
		p, err := browser.NewPool(testCtx(t), browser.PoolConfig{Host: h, StateDir: t.TempDir(), Start: start})
		if err != nil {
			t.Fatalf("NewPool = %v", err)
		}
		t.Cleanup(func() { _ = p.Close() })
		b, err := p.Launch(testCtx(t), connector.LaunchOptions{AllowedDomains: testDomains})
		if err != nil {
			t.Fatalf("Launch = %v", err)
		}
		pb, ok := b.(*browser.PoolBrowser)
		if !ok {
			t.Fatalf("Launch returned %T", b)
		}
		prof := pb.ProfileDir()
		calls := methods(f.snapshot())
		if len(calls) == 0 || calls[0] != "Browser.getVersion" {
			t.Errorf("first CDP method = %q, want Browser.getVersion before any page setup", calls)
		}

		if err := b.Close(); err != nil {
			t.Fatalf("lease Close = %v", err)
		}
		if !chanClosed(r.ws.closed) {
			t.Error("websocket still open after the lease was closed")
		}
		assertKilled(t, r.exec)
		if !chanClosed(pb.Done()) {
			t.Error("lease Done not closed when Close returned")
		}
		assertGoneAny(t, prof)
	})
}

func TestWindowsStarter_UsesPortZeroFlagOnly(t *testing.T) {
	t.Parallel()
	replace := func(args []string, from, to string) []string {
		out := slices.Clone(args)
		for i, a := range out {
			if a == from {
				out[i] = to
			}
		}
		return out
	}
	drop := func(args []string, name string) []string {
		return slices.DeleteFunc(slices.Clone(args), func(a string) bool { return strings.HasPrefix(a, name) })
	}
	const port0 = "--remote-debugging-port=0"
	tests := []struct {
		name    string
		argv    func(release []string) []string
		wantErr error // nil: Exec runs with the argv unchanged
	}{
		{name: "release argv", argv: func(a []string) []string { return a }},
		{name: "fixed port", wantErr: browser.ErrForbiddenFlag, argv: func(a []string) []string {
			return replace(a, port0, "--remote-debugging-port=9222")
		}},
		{name: "port with leading zero", wantErr: browser.ErrForbiddenFlag, argv: func(a []string) []string {
			return replace(a, port0, "--remote-debugging-port=00")
		}},
		{name: "port switch without value", wantErr: browser.ErrForbiddenFlag, argv: func(a []string) []string {
			return replace(a, port0, "--remote-debugging-port")
		}},
		{name: "port missing", wantErr: browser.ErrForbiddenFlag, argv: func(a []string) []string {
			return drop(a, "--remote-debugging-port")
		}},
		{name: "port twice", wantErr: browser.ErrForbiddenFlag, argv: func(a []string) []string {
			return append(slices.Clone(a), port0)
		}},
		{name: "second port spelled differently", wantErr: browser.ErrForbiddenFlag, argv: func(a []string) []string {
			return append(slices.Clone(a), "--Remote-Debugging-Port=9222")
		}},
		{name: "pipe as well", wantErr: browser.ErrForbiddenFlag, argv: func(a []string) []string {
			return append(slices.Clone(a), "--remote-debugging-pipe")
		}},
		{name: "io pipes as well", wantErr: browser.ErrForbiddenFlag, argv: func(a []string) []string {
			return append(slices.Clone(a), "--remote-debugging-io-pipes=3,4")
		}},
		{name: "no profile", wantErr: browser.ErrNoProfileDir, argv: func(a []string) []string {
			return drop(a, "--user-data-dir")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newPortRig(t)
			cmd := r.cmd(emptyProfile(t))
			cmd.Args = tc.argv(cmd.Args)
			want := slices.Clone(cmd.Args)
			proc, err := browser.NewPortStarter(r.config())(testCtx(t), cmd)
			if proc != nil {
				t.Cleanup(func() { _ = proc.Close() })
			}
			calls, _ := r.exec.snapshot()
			if tc.wantErr != nil {
				if proc != nil || !errors.Is(err, tc.wantErr) {
					t.Errorf("start = %v, %v; want nil, %v", proc, err, tc.wantErr)
				}
				if len(calls) != 0 {
					t.Errorf("Exec ran %d times for a refused argv", len(calls))
				}
				return
			}
			if err != nil {
				t.Fatalf("start = %v", err)
			}
			if len(calls) != 1 {
				t.Fatalf("Exec ran %d times, want 1", len(calls))
			}
			if !slices.Equal(calls[0].Args, want) {
				t.Errorf("Exec argv = %q, want the vetted argv unchanged %q", calls[0].Args, want)
			}
			if n := countPrefix(calls[0].Args, "--remote-debugging-port"); n != 1 || !slices.Contains(calls[0].Args, port0) {
				t.Errorf("Exec argv has %d debug-port switches, want exactly %s", n, port0)
			}
		})
	}

	t.Run("exec failure returns nil and ErrLaunchFailed", func(t *testing.T) {
		t.Parallel()
		r := newPortRig(t)
		r.exec.err = errors.New("exec: file not found")
		proc, err := browser.NewPortStarter(r.config())(testCtx(t), r.cmd(emptyProfile(t)))
		if proc != nil || !errors.Is(err, browser.ErrLaunchFailed) {
			t.Errorf("start = %v, %v; want nil, ErrLaunchFailed", proc, err)
		}
		if dials, _ := r.seen(); len(dials) != 0 {
			t.Errorf("dialled %+v without a browser", dials)
		}
	})

	t.Run("non-empty profile refused before exec", func(t *testing.T) {
		t.Parallel()
		r := newPortRig(t)
		prof := emptyProfile(t)
		writeTestFile(t, prof, browser.PortFileName, []byte("9222\n"+testGUIDPath))
		proc, err := browser.NewPortStarter(r.config())(testCtx(t), r.cmd(prof))
		if proc != nil || err == nil {
			t.Errorf("start(planted port file) = %v, %v; want refused", proc, err)
		}
		if calls, _ := r.exec.snapshot(); len(calls) != 0 {
			t.Errorf("Exec ran %d times on a profile holding a planted port file", len(calls))
		}
	})

	t.Run("port file read only after exec", func(t *testing.T) {
		t.Parallel()
		r := newPortRig(t)
		var started atomic.Bool
		inner := r.opener
		r.exec.onStart = func(browser.Command) {
			started.Store(true)
			inner.set([]byte(r.portLine))
		}
		var readBeforeStart atomic.Int32
		cfg := r.config()
		cfg.PortFile.Open = func(path string) (io.ReadCloser, error) {
			rc, err := inner.open(path)
			if err == nil && !started.Load() {
				readBeforeStart.Add(1)
			}
			return rc, err
		}
		if _, err := browser.NewPortStarter(cfg)(testCtx(t), r.cmd(emptyProfile(t))); err != nil {
			t.Fatalf("start = %v", err)
		}
		if n := readBeforeStart.Load(); n != 0 {
			t.Errorf("port file opened %d times before the browser started", n)
		}
	})
}

func countPrefix(args []string, prefix string) int {
	n := 0
	for _, a := range args {
		if strings.HasPrefix(strings.ToLower(a), prefix) {
			n++
		}
	}
	return n
}

// assertGoneAny checks that path no longer exists (every OS).
func assertGoneAny(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s still present (Lstat err = %v), want removed", path, err)
	}
}
