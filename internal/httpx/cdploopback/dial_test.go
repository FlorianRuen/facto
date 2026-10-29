package cdploopback_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/FlorianRuen/facto/internal/httpx/cdploopback"
)

func TestNew_RefusesPortZeroAndOutOfRange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		port    int
		wantErr error
	}{
		{name: "zero", port: 0, wantErr: cdploopback.ErrInvalidPort},
		{name: "negative", port: -1, wantErr: cdploopback.ErrInvalidPort},
		{name: "min int", port: -1 << 31, wantErr: cdploopback.ErrInvalidPort},
		{name: "just over max", port: 65536, wantErr: cdploopback.ErrInvalidPort},
		{name: "wraps to 9222 as uint16", port: 65536 + 9222, wantErr: cdploopback.ErrInvalidPort},
		{name: "huge", port: 1 << 40, wantErr: cdploopback.ErrInvalidPort},
		{name: "lowest valid", port: 1},
		{name: "highest valid", port: 65535},
		{name: "typical", port: 9222},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			spy := &spyDialer{}
			c, err := cdploopback.New(tt.port, cdploopback.WithDialer(spy))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("New(%d) err = %v, want %v", tt.port, err, tt.wantErr)
			}
			if tt.wantErr != nil {
				if c != nil {
					t.Fatalf("New(%d) returned a client with an error", tt.port)
				}
				if calls := spy.Calls(); len(calls) != 0 {
					t.Fatalf("New(%d) dialled %q", tt.port, calls)
				}
				return
			}
			if c == nil {
				t.Fatalf("New(%d) returned nil client", tt.port)
			}
		})
	}
}

func TestDial_OtherPortNeverDialled(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		port int
		path string
	}{
		{name: "plain path", port: 9222, path: browserPath},
		{name: "path naming another port", port: 9222, path: "/devtools/browser/x?port=9333"},
		{name: "high port", port: 65535, path: browserPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			spy := &spyDialer{} // refuses every dial
			c, err := cdploopback.New(tt.port, cdploopback.WithDialer(spy))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if _, err := c.Dial(testCtx(t), tt.path); err == nil {
				t.Fatal("Dial succeeded through a refusing dialer")
			}
			assertOnlyLoopbackDial(t, spy.Calls(), tt.port)
		})
	}
}

func TestDial_OtherPortNeverDialled_AfterSuccess(t *testing.T) {
	t.Parallel()
	srv := startServer(t, acceptThen(holdOpen))
	conn, spy := dialFake(t, srv)
	if err := conn.WriteMessage(testCtx(t), []byte(`{"id":1,"method":"Browser.getVersion"}`)); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	assertOnlyLoopbackDial(t, spy.Calls(), srv.port)
}

func TestDial_NonLoopbackIPRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		raw     string
		wantErr error // nil: any error
	}{
		{name: "private v4", raw: "ws://10.0.0.1:9222" + browserPath, wantErr: cdploopback.ErrNotLoopback},
		{name: "wildcard v4", raw: "ws://0.0.0.0:9222" + browserPath, wantErr: cdploopback.ErrNotLoopback},
		{name: "loopback v6", raw: "ws://[::1]:9222" + browserPath, wantErr: cdploopback.ErrNotLoopback},
		{name: "other loopback v4", raw: "ws://127.0.0.2:9222" + browserPath, wantErr: cdploopback.ErrNotLoopback},
		{name: "localhost name", raw: "ws://localhost:9222" + browserPath, wantErr: cdploopback.ErrNotLoopback},
		{name: "v4-mapped v6", raw: "ws://[::ffff:127.0.0.1]:9222" + browserPath, wantErr: cdploopback.ErrNotLoopback},
		{name: "bracketed v4 literal", raw: "ws://[127.0.0.1]:9222/x", wantErr: cdploopback.ErrNotLoopback},
		{name: "decimal integer form", raw: "ws://2130706433:9222" + browserPath, wantErr: cdploopback.ErrNotLoopback},
		{name: "octal form", raw: "ws://0177.0.0.1:9222" + browserPath, wantErr: cdploopback.ErrNotLoopback},
		{name: "short form", raw: "ws://127.1:9222" + browserPath, wantErr: cdploopback.ErrNotLoopback},
		{name: "trailing dot", raw: "ws://127.0.0.1.:9222" + browserPath, wantErr: cdploopback.ErrNotLoopback},
		{name: "public name", raw: "ws://example.invalid:9222" + browserPath, wantErr: cdploopback.ErrNotLoopback},
		{name: "userinfo hiding the host", raw: "ws://127.0.0.1:9222@10.0.0.1:9222" + browserPath},
		{name: "userinfo on loopback", raw: "ws://user@127.0.0.1:9222" + browserPath},
		{name: "tls scheme", raw: "wss://127.0.0.1:9222" + browserPath},
		{name: "http scheme", raw: "http://127.0.0.1:9222" + browserPath},
		{name: "no port", raw: "ws://127.0.0.1" + browserPath},
		{name: "port zero", raw: "ws://127.0.0.1:0" + browserPath, wantErr: cdploopback.ErrInvalidPort},
		{name: "port out of range", raw: "ws://127.0.0.1:65536" + browserPath, wantErr: cdploopback.ErrInvalidPort},
		{name: "relative", raw: "127.0.0.1:9222" + browserPath},
		{name: "empty", raw: ""},
		{name: "CRLF in path", raw: "ws://127.0.0.1:9222/devtools\r\nHost: 10.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := cdploopback.ParseTarget(tt.raw)
			if err == nil {
				t.Fatalf("ParseTarget(%q) = %+v, want an error", tt.raw, got)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("ParseTarget(%q) err = %v, want %v", tt.raw, err, tt.wantErr)
			}
		})
	}
}

func TestParseTarget_AcceptsLiteralLoopback(t *testing.T) {
	t.Parallel()
	got, err := cdploopback.ParseTarget("ws://127.0.0.1:9222" + browserPath)
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	want := cdploopback.Target{Port: 9222, Path: browserPath}
	if got != want {
		t.Fatalf("ParseTarget = %+v, want %+v", got, want)
	}
}

// A request path is never a place to smuggle a host: absolute URLs,
// authority forms and header injection are refused before any dial.
func TestDial_PathCannotRedirectOrInject(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
	}{
		{name: "absolute ws url", path: "ws://10.0.0.1:9222" + browserPath},
		{name: "absolute http url", path: "http://10.0.0.1/"},
		{name: "authority form", path: "10.0.0.1:9222"},
		{name: "empty", path: ""},
		{name: "no leading slash", path: "devtools/browser/x"},
		{name: "CRLF header injection", path: "/x\r\nHost: 10.0.0.1"},
		{name: "LF only", path: "/x\nOrigin: http://10.0.0.1"},
		{name: "space splits request line", path: "/x HTTP/1.1\r\n"},
		{name: "NUL", path: "/x\x00y"},
		{name: "fragment", path: "/x#frag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			spy := &spyDialer{}
			c, err := cdploopback.New(9222, cdploopback.WithDialer(spy))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			_, err = c.Dial(testCtx(t), tt.path)
			if !errors.Is(err, cdploopback.ErrInvalidTarget) {
				t.Fatalf("Dial(%q) err = %v, want ErrInvalidTarget", tt.path, err)
			}
			if calls := spy.Calls(); len(calls) != 0 {
				t.Fatalf("Dial(%q) dialled %q before validating the path", tt.path, calls)
			}
		})
	}
}

// The client never takes a host name, so no resolver is ever consulted. The
// spy resolver fails every lookup; a client resolving "localhost" (which a
// hostile resolver could map to 10.0.0.1) would show up as a lookup or as a
// dial address that is not the literal 127.0.0.1.
func TestDial_LocalhostResolvingElsewhereNeverUsed(t *testing.T) {
	t.Parallel()
	srv := startServer(t, acceptThen(holdOpen))
	var lookups atomic.Int64
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			lookups.Add(1)
			return nil, errors.New("resolver spy: lookup refused (localhost -> 10.0.0.1)")
		},
	}
	spy := &spyDialer{forward: &net.Dialer{Resolver: resolver}}
	c, err := cdploopback.New(srv.port, cdploopback.WithDialer(spy))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := c.Dial(testCtx(t), browserPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if n := lookups.Load(); n != 0 {
		t.Fatalf("resolver consulted %d times, want 0", n)
	}
	assertOnlyLoopbackDial(t, spy.Calls(), srv.port)

	// The parse path refuses the name outright: no dial, no lookup.
	if _, err := cdploopback.ParseTarget("ws://localhost:" + strconv.Itoa(srv.port) + browserPath); !errors.Is(err, cdploopback.ErrNotLoopback) {
		t.Fatalf("ParseTarget(localhost) err = %v, want ErrNotLoopback", err)
	}
	if n := lookups.Load(); n != 0 {
		t.Fatalf("resolver consulted %d times after ParseTarget, want 0", n)
	}
}

func TestDial_RedirectNotFollowed(t *testing.T) {
	t.Parallel()
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			t.Parallel()
			otherPort, otherAccepts := countingListener(t)
			srv := startServer(t, func(t *testing.T, c net.Conn, br *bufio.Reader) {
				if readHandshake(t, br) == nil {
					return
				}
				resp := fmt.Sprintf("HTTP/1.1 %d Moved\r\nLocation: ws://127.0.0.1:%d%s\r\nContent-Length: 0\r\n\r\n",
					code, otherPort, browserPath)
				writeAll(t, c, []byte(resp))
				holdOpen(t, c, br)
			})
			spy := &spyDialer{forward: &net.Dialer{}}
			c, err := cdploopback.New(srv.port, cdploopback.WithDialer(spy))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			conn, err := c.Dial(testCtx(t), browserPath)
			if conn != nil {
				_ = conn.Close()
			}
			if !errors.Is(err, cdploopback.ErrHandshake) {
				t.Fatalf("Dial err = %v, want ErrHandshake", err)
			}
			assertOnlyLoopbackDial(t, spy.Calls(), srv.port)
			if n := otherAccepts.Load(); n != 0 {
				t.Fatalf("redirect target contacted %d times, want 0", n)
			}
		})
	}
}

// Proxy environment variables are ignored: the real default dialer is used
// (no WithDialer) and the spy proxy must never see a connection. Not
// parallel: t.Setenv.
func TestDial_ProxyEnvIgnored(t *testing.T) {
	proxyPort, proxyAccepts := countingListener(t)
	proxy := "http://127.0.0.1:" + strconv.Itoa(proxyPort)
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(k, proxy)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	var got atomic.Value
	srv := startServer(t, func(t *testing.T, c net.Conn, br *bufio.Reader) {
		req := readHandshake(t, br)
		if req == nil {
			return
		}
		got.Store(req.Method + " " + req.RequestURI)
		upgrade(t, c, req)
		holdOpen(t, c, br)
	})
	c, err := cdploopback.New(srv.port) // default dialer
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := c.Dial(testCtx(t), browserPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if n := proxyAccepts.Load(); n != 0 {
		t.Fatalf("proxy contacted %d times, want 0", n)
	}
	if n := srv.accepts.Load(); n != 1 {
		t.Fatalf("server accepted %d connections, want 1", n)
	}
	if line, _ := got.Load().(string); line != "GET "+browserPath {
		t.Fatalf("request line = %q, want origin-form GET %s (no proxy absolute-form)", line, browserPath)
	}
}

// Errors returned to callers never echo what the peer sent (a CDP payload can
// carry typed credentials).
func TestDial_HandshakeErrorCarriesNoPeerBody(t *testing.T) {
	t.Parallel()
	const marker = "PEER-BODY-MARKER-7f3a"
	srv := startServer(t, func(t *testing.T, c net.Conn, br *bufio.Reader) {
		if readHandshake(t, br) == nil {
			return
		}
		writeAll(t, c, []byte("HTTP/1.1 403 "+marker+"\r\nX-Echo: "+marker+"\r\nContent-Length: 22\r\n\r\n"+marker+"-body!"))
		holdOpen(t, c, br)
	})
	c, err := cdploopback.New(srv.port)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Dial(testCtx(t), browserPath)
	if !errors.Is(err, cdploopback.ErrHandshake) {
		t.Fatalf("Dial err = %v, want ErrHandshake", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("error echoes peer data: %v", err)
	}
}
