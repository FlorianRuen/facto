// Test helpers for package cdploopback: an in-test fake CDP WebSocket server
// on a 127.0.0.1 test listener, a spying dialer and raw RFC 6455 framing.
//
// Expected API (T7.1, ADR 0008 "Windows (A4)", plan J1 Q1). Tests are written
// against this surface; nothing here is production code.
//
//	package cdploopback
//
//	// MaxMessageSize caps one reassembled message (ADR 0008: 16 MiB).
//	const MaxMessageSize = 16 << 20
//	// MaxHandshakeHeader caps the server handshake response (8 KiB).
//	const MaxHandshakeHeader = 8 << 10
//
//	var (
//		ErrInvalidPort     error // port outside 1..65535
//		ErrNotLoopback     error // target host is anything but the literal 127.0.0.1
//		ErrInvalidTarget   error // malformed ws URL or request path (scheme, userinfo, CR/LF…)
//		ErrHandshake       error // non-101, bad Sec-WebSocket-Accept, redirect, header over cap…
//		ErrProtocol        error // masked server frame, RSV bits, bad control frame, bad opcode…
//		ErrMessageTooLarge error // declared or cumulative length over MaxMessageSize
//		ErrClosed          error // peer sent a close frame or the Conn was closed
//	)
//
//	// Dialer is the consumer-side dial seam (net.Dialer satisfies it).
//	type Dialer interface {
//		DialContext(ctx context.Context, network, address string) (net.Conn, error)
//	}
//
//	type Option func(*Client)
//	func WithDialer(d Dialer) Option  // default: a plain net.Dialer, no proxy
//	func WithRand(r io.Reader) Option // default: crypto/rand.Reader (key and masks)
//
//	// Target is a parsed DevToolsActivePort / webSocketDebuggerUrl target.
//	type Target struct {
//		Port int
//		Path string
//	}
//	// ParseTarget accepts only ws://127.0.0.1:<port><path>.
//	func ParseTarget(raw string) (Target, error)
//
//	// New refuses ports outside 1..65535. It takes no host name.
//	func New(port int, opts ...Option) (*Client, error)
//	// Dial dials exactly "127.0.0.1:<port>" (network "tcp" or "tcp4") once,
//	// performs the client handshake for path, never follows redirects, never
//	// uses a proxy, never TLS.
//	func (c *Client) Dial(ctx context.Context, path string) (*Conn, error)
//
//	// ReadMessage returns the next reassembled text/binary message, answering
//	// pings transparently. Bounded by ctx.
//	func (c *Conn) ReadMessage(ctx context.Context) ([]byte, error)
//	// WriteMessage sends one unfragmented, masked text frame.
//	func (c *Conn) WriteMessage(ctx context.Context, p []byte) error
//	func (c *Conn) Close() error
package cdploopback_test

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // RFC 6455 4.2.2 mandates SHA-1 for Sec-WebSocket-Accept; test oracle only (Windows port fallback, https://github.com/FlorianRuen/facto/issues/3)
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/httpx/cdploopback"
)

// browserPath is a synthetic DevTools browser target path.
const browserPath = "/devtools/browser/00000000-0000-4000-8000-000000000000"

// wsGUID is the RFC 6455 handshake GUID.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// testTimeout bounds every test step; a hang means a guard is missing.
const testTimeout = 10 * time.Second

// errSpyRefused is returned by a spy dialer with no forward target.
var errSpyRefused = errors.New("spy dialer: refused")

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

// acceptFor computes Sec-WebSocket-Accept for key.
func acceptFor(key string) string {
	h := sha1.Sum([]byte(key + wsGUID)) //nolint:gosec // RFC 6455 test oracle (Windows port fallback, https://github.com/FlorianRuen/facto/issues/3)
	return base64.StdEncoding.EncodeToString(h[:])
}

// spyDialer records every dial and forwards to a real dialer when forward is
// set; otherwise it refuses.
type spyDialer struct {
	forward cdploopback.Dialer
	mu      sync.Mutex
	calls   []string // "network address"
}

func (s *spyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	s.mu.Lock()
	s.calls = append(s.calls, network+" "+address)
	s.mu.Unlock()
	if s.forward == nil {
		return nil, errSpyRefused
	}
	return s.forward.DialContext(ctx, network, address)
}

func (s *spyDialer) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// assertOnlyLoopbackDial fails unless calls is exactly one dial of
// 127.0.0.1:port over tcp or tcp4.
func assertOnlyLoopbackDial(t *testing.T, calls []string, port int) {
	t.Helper()
	want := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if len(calls) != 1 {
		t.Fatalf("dials = %q, want exactly one dial of %s", calls, want)
	}
	if calls[0] != "tcp "+want && calls[0] != "tcp4 "+want {
		t.Fatalf("dial = %q, want tcp/tcp4 %s", calls[0], want)
	}
}

// serverScript drives one accepted connection of the fake server.
type serverScript func(t *testing.T, c net.Conn, br *bufio.Reader)

// fakeServer is an in-test WebSocket peer on a 127.0.0.1 test listener.
type fakeServer struct {
	port    int
	accepts atomic.Int64
}

// startServer listens on 127.0.0.1:0 and runs script for every connection.
func startServer(t *testing.T, script serverScript) *fakeServer {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fs := &fakeServer{port: ln.Addr().(*net.TCPAddr).Port}
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		conns []net.Conn
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fs.accepts.Add(1)
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			_ = c.SetDeadline(time.Now().Add(2 * testTimeout))
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				if script != nil {
					script(t, c, bufio.NewReader(c))
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return fs
}

// countingListener accepts and counts connections, then closes them. It
// stands in for a proxy or a redirect target that must never be contacted.
func countingListener(t *testing.T) (port int, accepts *atomic.Int64) {
	t.Helper()
	fs := startServer(t, nil)
	return fs.port, &fs.accepts
}

// readHandshake reads the client's upgrade request. It returns nil without
// failing when the client sends nothing usable (a client refusing to dial or
// closing early is legitimate in several tests); tests asserting on the
// request detect its absence themselves.
func readHandshake(_ *testing.T, br *bufio.Reader) *http.Request {
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil
	}
	return req
}

// upgrade answers a valid 101 to req.
func upgrade(t *testing.T, c net.Conn, req *http.Request) {
	t.Helper()
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptFor(req.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"
	if _, err := io.WriteString(c, resp); err != nil {
		t.Errorf("server: write 101: %v", err)
	}
}

// acceptThen performs a valid handshake then runs then.
func acceptThen(then serverScript) serverScript {
	return func(t *testing.T, c net.Conn, br *bufio.Reader) {
		req := readHandshake(t, br)
		if req == nil {
			return
		}
		upgrade(t, c, req)
		if then != nil {
			then(t, c, br)
		}
	}
}

// holdOpen keeps the connection open until the client closes it.
func holdOpen(_ *testing.T, _ net.Conn, br *bufio.Reader) {
	_, _ = io.Copy(io.Discard, br)
}

// frameHeader encodes a server frame header. b0 carries FIN, RSV and opcode.
// The length always uses the 64-bit form when length > 65535 or force64.
func frameHeader(b0 byte, masked bool, length uint64, force64 bool) []byte {
	var b1 byte
	if masked {
		b1 = 0x80
	}
	switch {
	case !force64 && length <= 125:
		return []byte{b0, b1 | byte(length)}
	case !force64 && length <= 0xFFFF:
		h := []byte{b0, b1 | 126, 0, 0}
		binary.BigEndian.PutUint16(h[2:], uint16(length))
		return h
	default:
		h := make([]byte, 10)
		h[0], h[1] = b0, b1|127
		binary.BigEndian.PutUint64(h[2:], length)
		return h
	}
}

// frame encodes a complete server frame (unmasked unless mask is non-nil).
func frame(b0 byte, payload []byte, mask []byte) []byte {
	out := frameHeader(b0, mask != nil, uint64(len(payload)), false)
	if mask == nil {
		return append(out, payload...)
	}
	out = append(out, mask...)
	for i, b := range payload {
		out = append(out, b^mask[i%4])
	}
	return out
}

// Frame first bytes.
const (
	finText   = 0x81
	finBinary = 0x82
	finClose  = 0x88
	finPing   = 0x89
	finPong   = 0x8A
	fragText  = 0x01
	fragCont  = 0x00
	finCont   = 0x80
)

// clientFrame is a frame read by the fake server.
type clientFrame struct {
	b0      byte
	masked  bool
	mask    [4]byte
	payload []byte // unmasked
}

// readClientFrame reads one client frame (payloads up to 1 MiB).
func readClientFrame(br *bufio.Reader) (clientFrame, error) {
	var f clientFrame
	var h [2]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		return f, fmt.Errorf("frame header: %w", err)
	}
	f.b0 = h[0]
	f.masked = h[1]&0x80 != 0
	n := uint64(h[1] & 0x7F)
	switch n {
	case 126:
		var e [2]byte
		if _, err := io.ReadFull(br, e[:]); err != nil {
			return f, err
		}
		n = uint64(binary.BigEndian.Uint16(e[:]))
	case 127:
		var e [8]byte
		if _, err := io.ReadFull(br, e[:]); err != nil {
			return f, err
		}
		n = binary.BigEndian.Uint64(e[:])
	}
	if n > 1<<20 {
		return f, fmt.Errorf("client frame too large for the fake server: %d", n)
	}
	if f.masked {
		if _, err := io.ReadFull(br, f.mask[:]); err != nil {
			return f, err
		}
	}
	f.payload = make([]byte, n)
	if _, err := io.ReadFull(br, f.payload); err != nil {
		return f, err
	}
	if f.masked {
		for i := range f.payload {
			f.payload[i] ^= f.mask[i%4]
		}
	}
	return f, nil
}

// dialFake dials srv through a spy forwarding to a real dialer.
func dialFake(t *testing.T, srv *fakeServer, opts ...cdploopback.Option) (*cdploopback.Conn, *spyDialer) {
	t.Helper()
	spy := &spyDialer{forward: &net.Dialer{}}
	c, err := cdploopback.New(srv.port, append([]cdploopback.Option{cdploopback.WithDialer(spy)}, opts...)...)
	if err != nil {
		t.Fatalf("New(%d): %v", srv.port, err)
	}
	conn, err := c.Dial(testCtx(t), browserPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, spy
}

// writeAll writes chunks to c, reporting errors on t.
func writeAll(t *testing.T, c net.Conn, chunks ...[]byte) {
	t.Helper()
	for _, ch := range chunks {
		if _, err := c.Write(ch); err != nil {
			t.Errorf("server: write: %v", err)
			return
		}
	}
}
