package cdploopback_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/httpx/cdploopback"
)

func TestWS_LimitsMatchADR0008(t *testing.T) {
	t.Parallel()
	if cdploopback.MaxMessageSize != 16<<20 {
		t.Fatalf("MaxMessageSize = %d, want 16 MiB (ADR 0008)", cdploopback.MaxMessageSize)
	}
	if cdploopback.MaxHandshakeHeader != 8<<10 {
		t.Fatalf("MaxHandshakeHeader = %d, want 8 KiB (ADR 0008)", cdploopback.MaxHandshakeHeader)
	}
}

// readOne dials srv and returns the result of one ReadMessage.
func readOne(t *testing.T, srv *fakeServer) ([]byte, error) {
	t.Helper()
	conn, _ := dialFake(t, srv)
	return conn.ReadMessage(testCtx(t))
}

// assertRefused fails unless err matches want and is not a timeout (a timeout
// means the client waited for bytes instead of refusing the header).
func assertRefused(t *testing.T, msg []byte, err error, want ...error) {
	t.Helper()
	if err == nil {
		t.Fatalf("ReadMessage accepted %d bytes, want refusal %v", len(msg), want)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReadMessage timed out (%v): the frame must be refused from its header", err)
	}
	for _, w := range want {
		if errors.Is(err, w) {
			return
		}
	}
	t.Fatalf("ReadMessage err = %v, want one of %v", err, want)
}

// Not parallel: it measures process-wide allocation. The server sends only
// the frame header and keeps the connection open, so a client that allocates
// or waits for the payload is caught.
func TestWS_LengthOverCapRefusedBeforeAlloc(t *testing.T) {
	tests := []struct {
		name   string
		length uint64
		want   []error
	}{
		{name: "2^63 (MSB set)", length: 1 << 63, want: []error{cdploopback.ErrMessageTooLarge, cdploopback.ErrProtocol}},
		{name: "max uint64", length: ^uint64(0), want: []error{cdploopback.ErrMessageTooLarge, cdploopback.ErrProtocol}},
		{name: "2^63-1", length: 1<<63 - 1, want: []error{cdploopback.ErrMessageTooLarge}},
		{name: "4 GiB", length: 1 << 32, want: []error{cdploopback.ErrMessageTooLarge}},
		{name: "cap+1", length: cdploopback.MaxMessageSize + 1, want: []error{cdploopback.ErrMessageTooLarge}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t, acceptThen(func(t *testing.T, c net.Conn, br *bufio.Reader) {
				writeAll(t, c, frameHeader(finText, false, tt.length, true))
				holdOpen(t, c, br)
			}))
			conn, _ := dialFake(t, srv)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			msg, err := conn.ReadMessage(ctx)
			runtime.ReadMemStats(&after)

			assertRefused(t, msg, err, tt.want...)
			if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
				t.Fatalf("ReadMessage allocated %d bytes before refusing a %d-byte frame", grew, tt.length)
			}
		})
	}
}

func TestWS_MessageAtCapAccepted(t *testing.T) {
	t.Parallel()
	payload := bytes.Repeat([]byte{'a'}, cdploopback.MaxMessageSize)
	srv := startServer(t, acceptThen(func(t *testing.T, c net.Conn, br *bufio.Reader) {
		writeAll(t, c, frameHeader(finText, false, uint64(len(payload)), true), payload)
		holdOpen(t, c, br)
	}))
	msg, err := readOne(t, srv)
	if err != nil {
		t.Fatalf("ReadMessage at cap: %v", err)
	}
	if len(msg) != cdploopback.MaxMessageSize {
		t.Fatalf("len = %d, want %d", len(msg), cdploopback.MaxMessageSize)
	}
}

func TestWS_FragmentedTotalOverCapRefused(t *testing.T) {
	t.Parallel()
	half := bytes.Repeat([]byte{'b'}, cdploopback.MaxMessageSize/2)
	tests := []struct {
		name  string
		send  [][]byte
		wants []error
	}{
		{
			name: "continuation header pushes total over cap",
			send: [][]byte{
				frame(fragText, []byte("0123456789"), nil),
				frameHeader(finCont, false, cdploopback.MaxMessageSize-9, true),
			},
			wants: []error{cdploopback.ErrMessageTooLarge},
		},
		{
			name: "two full halves then one more byte",
			send: [][]byte{
				frameHeader(fragText, false, uint64(len(half)), true), half,
				frameHeader(fragCont, false, uint64(len(half)), true), half,
				frameHeader(finCont, false, 1, false),
			},
			wants: []error{cdploopback.ErrMessageTooLarge},
		},
		{
			name: "each fragment under cap, sum over cap",
			send: [][]byte{
				frameHeader(fragText, false, uint64(len(half)), true), half,
				frameHeader(fragCont, false, uint64(len(half)), true), half,
				frameHeader(fragCont, false, 125, false),
			},
			wants: []error{cdploopback.ErrMessageTooLarge},
		},
		{
			name:  "continuation without a start",
			send:  [][]byte{frame(finCont, []byte("x"), nil)},
			wants: []error{cdploopback.ErrProtocol},
		},
		{
			name: "new data frame inside a fragmented message",
			send: [][]byte{
				frame(fragText, []byte("x"), nil),
				frame(finText, []byte("y"), nil),
			},
			wants: []error{cdploopback.ErrProtocol},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, acceptThen(func(t *testing.T, c net.Conn, br *bufio.Reader) {
				writeAll(t, c, tt.send...)
				holdOpen(t, c, br)
			}))
			msg, err := readOne(t, srv)
			assertRefused(t, msg, err, tt.wants...)
		})
	}
}

func TestWS_FragmentedMessageReassembledAndPingAnswered(t *testing.T) {
	t.Parallel()
	pong := make(chan clientFrame, 1)
	srv := startServer(t, acceptThen(func(t *testing.T, c net.Conn, br *bufio.Reader) {
		writeAll(t, c,
			frame(fragText, []byte("hel"), nil),
			frame(finPing, []byte("pp"), nil), // control frames may interleave
			frame(finCont, []byte("lo"), nil),
		)
		f, err := readClientFrame(br)
		if err != nil {
			t.Errorf("server: read pong: %v", err)
			return
		}
		pong <- f
		holdOpen(t, c, br)
	}))
	msg, err := readOne(t, srv)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if string(msg) != "hello" {
		t.Fatalf("msg = %q, want hello", msg)
	}
	select {
	case f := <-pong:
		if f.b0 != finPong || !f.masked || string(f.payload) != "pp" {
			t.Fatalf("pong = b0 %#x masked %v payload %q, want masked FIN pong echoing pp", f.b0, f.masked, f.payload)
		}
	case <-time.After(testTimeout):
		t.Fatal("no pong received")
	}
}

func TestWS_MaskedServerFrameRefused(t *testing.T) {
	t.Parallel()
	mask := []byte{1, 2, 3, 4}
	tests := []struct {
		name string
		send []byte
	}{
		{name: "masked text", send: frame(finText, []byte(`{"id":1}`), mask)},
		{name: "masked binary", send: frame(finBinary, []byte("x"), mask)},
		{name: "masked ping", send: frame(finPing, []byte("x"), mask)},
		{name: "masked close", send: frame(finClose, []byte{0x03, 0xE8}, mask)},
		{name: "masked zero mask", send: frame(finText, []byte("x"), []byte{0, 0, 0, 0})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, acceptThen(func(t *testing.T, c net.Conn, br *bufio.Reader) {
				writeAll(t, c, tt.send)
				holdOpen(t, c, br)
			}))
			msg, err := readOne(t, srv)
			assertRefused(t, msg, err, cdploopback.ErrProtocol)
		})
	}
}

func TestWS_RSVBitsRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		b0   byte
	}{
		{name: "RSV1 text (compression not negotiated)", b0: finText | 0x40},
		{name: "RSV2 text", b0: finText | 0x20},
		{name: "RSV3 text", b0: finText | 0x10},
		{name: "all RSV", b0: finText | 0x70},
		{name: "RSV1 ping", b0: finPing | 0x40},
		{name: "RSV1 continuation start", b0: fragText | 0x40},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, acceptThen(func(t *testing.T, c net.Conn, br *bufio.Reader) {
				writeAll(t, c, frame(tt.b0, []byte("x"), nil))
				holdOpen(t, c, br)
			}))
			msg, err := readOne(t, srv)
			assertRefused(t, msg, err, cdploopback.ErrProtocol)
		})
	}
}

func TestWS_ReservedOpcodeRefused(t *testing.T) {
	t.Parallel()
	for _, op := range []byte{0x3, 0x7, 0xB, 0xF} {
		t.Run(strconv.Itoa(int(op)), func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, acceptThen(func(t *testing.T, c net.Conn, br *bufio.Reader) {
				writeAll(t, c, frame(0x80|op, []byte("x"), nil))
				holdOpen(t, c, br)
			}))
			msg, err := readOne(t, srv)
			assertRefused(t, msg, err, cdploopback.ErrProtocol)
		})
	}
}

func TestWS_ControlFrameOver125Refused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		send []byte
	}{
		{name: "ping 126 (16-bit length)", send: frame(finPing, bytes.Repeat([]byte{'p'}, 126), nil)},
		{name: "pong 126", send: frame(finPong, bytes.Repeat([]byte{'p'}, 126), nil)},
		{name: "close 126", send: frame(finClose, append([]byte{0x03, 0xE8}, bytes.Repeat([]byte{'c'}, 124)...), nil)},
		{name: "ping 64-bit length 200", send: frameHeader(finPing, false, 200, true)},
		{name: "ping 64-bit length 5 (non-minimal)", send: append(frameHeader(finPing, false, 5, true), "abcde"...)},
		{name: "fragmented ping", send: frame(0x09, []byte("abc"), nil)},
		{name: "fragmented close", send: frame(0x08, []byte{0x03, 0xE8}, nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, acceptThen(func(t *testing.T, c net.Conn, br *bufio.Reader) {
				writeAll(t, c, tt.send)
				holdOpen(t, c, br)
			}))
			msg, err := readOne(t, srv)
			assertRefused(t, msg, err, cdploopback.ErrProtocol)
		})
	}
}

func TestWS_ServerCloseEndsRead(t *testing.T) {
	t.Parallel()
	srv := startServer(t, acceptThen(func(t *testing.T, c net.Conn, br *bufio.Reader) {
		writeAll(t, c, frame(finClose, []byte{0x03, 0xE8}, nil))
		holdOpen(t, c, br)
	}))
	conn, _ := dialFake(t, srv)
	msg, err := conn.ReadMessage(testCtx(t))
	assertRefused(t, msg, err, cdploopback.ErrClosed)
	if err := conn.WriteMessage(testCtx(t), []byte("{}")); err == nil {
		t.Fatal("WriteMessage after peer close succeeded")
	}
}

func TestWS_ReadBoundedByContext(t *testing.T) {
	t.Parallel()
	srv := startServer(t, acceptThen(holdOpen)) // never sends a frame
	conn, _ := dialFake(t, srv)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := conn.ReadMessage(ctx)
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ReadMessage err = %v, want context.Canceled", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("ReadMessage ignored context cancellation")
	}
}

// Errors from a refused frame never carry the frame payload.
func TestWS_ProtocolErrorCarriesNoPayload(t *testing.T) {
	t.Parallel()
	const marker = "FRAME-PAYLOAD-MARKER-91c2"
	srv := startServer(t, acceptThen(func(t *testing.T, c net.Conn, br *bufio.Reader) {
		writeAll(t, c, frame(finText|0x40, []byte(marker), nil))
		holdOpen(t, c, br)
	}))
	msg, err := readOne(t, srv)
	assertRefused(t, msg, err, cdploopback.ErrProtocol)
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("error echoes the payload: %v", err)
	}
}

// dialWithResponse runs a fake server answering the handshake with
// respond(req) and returns Dial's error.
func dialWithResponse(t *testing.T, respond func(req *http.Request) string) error {
	t.Helper()
	srv := startServer(t, func(t *testing.T, c net.Conn, br *bufio.Reader) {
		req := readHandshake(t, br)
		if req == nil {
			return
		}
		// Unchecked: a client refusing an oversized response may close
		// before the whole response is written.
		_, _ = io.WriteString(c, respond(req))
		holdOpen(t, c, br)
	})
	c, err := cdploopback.New(srv.port)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := c.Dial(testCtx(t), browserPath)
	if conn != nil {
		_ = conn.Close()
	}
	return err
}

func assertHandshakeRefused(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial timed out (%v): the response must be refused, not waited on", err)
	}
	if !errors.Is(err, cdploopback.ErrHandshake) {
		t.Fatalf("Dial err = %v, want ErrHandshake", err)
	}
}

func TestWS_BadAcceptKeyRefused(t *testing.T) {
	t.Parallel()
	head := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
	tests := []struct {
		name    string
		respond func(req *http.Request) string
	}{
		{name: "missing accept", respond: func(*http.Request) string { return head + "\r\n" }},
		{name: "empty accept", respond: func(*http.Request) string { return head + "Sec-WebSocket-Accept: \r\n\r\n" }},
		{name: "wrong accept", respond: func(*http.Request) string {
			return head + "Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(make([]byte, 20)) + "\r\n\r\n"
		}},
		{name: "key echoed back", respond: func(r *http.Request) string {
			return head + "Sec-WebSocket-Accept: " + r.Header.Get("Sec-WebSocket-Key") + "\r\n\r\n"
		}},
		{name: "accept for another key", respond: func(*http.Request) string {
			return head + "Sec-WebSocket-Accept: " + acceptFor("dGhlIHNhbXBsZSBub25jZQ==") + "\r\n\r\n"
		}},
		{name: "two accept headers", respond: func(r *http.Request) string {
			ok := acceptFor(r.Header.Get("Sec-WebSocket-Key"))
			return head + "Sec-WebSocket-Accept: " + ok + "\r\nSec-WebSocket-Accept: " + ok + "\r\n\r\n"
		}},
		{name: "missing upgrade", respond: func(r *http.Request) string {
			return "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
				acceptFor(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"
		}},
		{name: "upgrade to another protocol", respond: func(r *http.Request) string {
			return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
				acceptFor(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"
		}},
		{name: "missing connection upgrade", respond: func(r *http.Request) string {
			return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: " +
				acceptFor(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"
		}},
		{name: "unrequested extension", respond: func(r *http.Request) string {
			return head + "Sec-WebSocket-Accept: " + acceptFor(r.Header.Get("Sec-WebSocket-Key")) +
				"\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
		}},
		{name: "unrequested subprotocol", respond: func(r *http.Request) string {
			return head + "Sec-WebSocket-Accept: " + acceptFor(r.Header.Get("Sec-WebSocket-Key")) +
				"\r\nSec-WebSocket-Protocol: chat\r\n\r\n"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertHandshakeRefused(t, dialWithResponse(t, tt.respond))
		})
	}
}

func TestWS_HandshakeHeaderOverCapRefused(t *testing.T) {
	t.Parallel()
	ok := func(r *http.Request) string {
		return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
			acceptFor(r.Header.Get("Sec-WebSocket-Key")) + "\r\n"
	}
	tests := []struct {
		name    string
		respond func(*http.Request) string
	}{
		{name: "one 9 KiB header, never terminated", respond: func(r *http.Request) string {
			return ok(r) + "X-Pad: " + strings.Repeat("a", 9<<10)
		}},
		{name: "one 9 KiB header, terminated", respond: func(r *http.Request) string {
			return ok(r) + "X-Pad: " + strings.Repeat("a", 9<<10) + "\r\n\r\n"
		}},
		{name: "many small headers over 8 KiB", respond: func(r *http.Request) string {
			return ok(r) + strings.Repeat("X-Pad: "+strings.Repeat("a", 90)+"\r\n", 100) + "\r\n"
		}},
		{name: "9 KiB status line without newline", respond: func(*http.Request) string {
			return "HTTP/1.1 101 " + strings.Repeat("S", 9<<10)
		}},
		{name: "endless header stream", respond: func(r *http.Request) string {
			return ok(r) + strings.Repeat("X-A: b\r\n", 64<<10/8)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertHandshakeRefused(t, dialWithResponse(t, tt.respond))
		})
	}
}

func TestWS_HandshakeHeaderUnderCapAccepted(t *testing.T) {
	t.Parallel()
	err := dialWithResponse(t, func(r *http.Request) string {
		return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
			acceptFor(r.Header.Get("Sec-WebSocket-Key")) + "\r\nX-Pad: " + strings.Repeat("a", 6<<10) + "\r\n\r\n"
	})
	if err != nil {
		t.Fatalf("Dial with a 6 KiB header: %v", err)
	}
}

func TestWS_Non101Refused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		resp string
	}{
		{name: "200", resp: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"},
		{name: "400", resp: "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"},
		{name: "403 host check", resp: "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"},
		{name: "426", resp: "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n"},
		{name: "500", resp: "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"},
		{name: "100 continue", resp: "HTTP/1.1 100 Continue\r\n\r\n"},
		{name: "1010 prefix", resp: "HTTP/1.1 1010 Switching Protocols\r\n\r\n"},
		{name: "HTTP/1.0 101", resp: "HTTP/1.0 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"},
		{name: "not http", resp: "SSH-2.0-OpenSSH_9.9\r\n\r\n"},
		{name: "empty then close", resp: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := startServer(t, func(t *testing.T, c net.Conn, br *bufio.Reader) {
				if readHandshake(t, br) == nil {
					return
				}
				writeAll(t, c, []byte(tt.resp))
				if tt.resp != "" {
					holdOpen(t, c, br)
				}
			})
			c, err := cdploopback.New(srv.port)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			conn, err := c.Dial(testCtx(t), browserPath)
			if conn != nil {
				_ = conn.Close()
			}
			assertHandshakeRefused(t, err)
		})
	}
}

// recordingReader hands out an incrementing byte sequence and records it.
type recordingReader struct {
	mu    sync.Mutex
	next  byte
	given []byte
	limit int // > 0: fail once this many bytes were handed out
}

var errRandExhausted = errors.New("rand: exhausted")

func (r *recordingReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.limit > 0 && len(r.given) >= r.limit {
		return 0, errRandExhausted
	}
	n := len(p)
	if r.limit > 0 && len(r.given)+n > r.limit {
		n = r.limit - len(r.given)
	}
	for i := range n {
		r.next++
		if r.next == 0 {
			r.next = 1
		}
		p[i] = r.next
	}
	r.given = append(r.given, p[:n]...)
	return n, nil
}

func (r *recordingReader) Given() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.given...)
}

func TestWS_ClientFramesMaskedWithCryptoRand(t *testing.T) {
	t.Parallel()
	rnd := &recordingReader{}
	keys := make(chan string, 1)
	frames := make(chan clientFrame, 2)
	srv := startServer(t, func(t *testing.T, c net.Conn, br *bufio.Reader) {
		req := readHandshake(t, br)
		if req == nil {
			return
		}
		keys <- req.Header.Get("Sec-WebSocket-Key")
		upgrade(t, c, req)
		for range 2 {
			f, err := readClientFrame(br)
			if err != nil {
				t.Errorf("server: read frame: %v", err)
				return
			}
			frames <- f
		}
		holdOpen(t, c, br)
	})
	conn, _ := dialFake(t, srv, cdploopback.WithRand(rnd))
	for _, m := range []string{`{"id":1}`, `{"id":2}`} {
		if err := conn.WriteMessage(testCtx(t), []byte(m)); err != nil {
			t.Fatalf("WriteMessage: %v", err)
		}
	}

	key, err := base64.StdEncoding.DecodeString(<-keys)
	if err != nil || len(key) != 16 {
		t.Fatalf("Sec-WebSocket-Key decodes to %d bytes (err %v), want 16", len(key), err)
	}
	given := rnd.Given()
	at := bytes.Index(given, key)
	if at < 0 {
		t.Fatalf("Sec-WebSocket-Key %x not drawn from the injected rand (%x)", key, given)
	}
	cursor := at + len(key)
	var masks [][4]byte
	for i, want := range []string{`{"id":1}`, `{"id":2}`} {
		var f clientFrame
		select {
		case f = <-frames:
		case <-time.After(testTimeout):
			t.Fatalf("frame %d not received", i)
		}
		if f.b0 != finText {
			t.Fatalf("frame %d b0 = %#x, want unfragmented FIN text %#x", i, f.b0, finText)
		}
		if !f.masked {
			t.Fatalf("frame %d is not masked", i)
		}
		if string(f.payload) != want {
			t.Fatalf("frame %d payload = %q, want %q", i, f.payload, want)
		}
		rel := bytes.Index(given[cursor:], f.mask[:])
		if rel < 0 {
			t.Fatalf("frame %d mask %x not drawn from the injected rand after the previous draw", i, f.mask)
		}
		cursor += rel + 4
		masks = append(masks, f.mask)
	}
	if masks[0] == masks[1] {
		t.Fatalf("mask reused across frames: %x", masks[0])
	}
}

func TestWS_RandFailureFailsClosed(t *testing.T) {
	t.Parallel()
	t.Run("handshake key", func(t *testing.T) {
		t.Parallel()
		srv := startServer(t, acceptThen(holdOpen))
		spy := &spyDialer{forward: &net.Dialer{}}
		c, err := cdploopback.New(srv.port, cdploopback.WithDialer(spy), cdploopback.WithRand(&recordingReader{limit: 4}))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		conn, err := c.Dial(testCtx(t), browserPath)
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil {
			t.Fatal("Dial succeeded with a failing rand (predictable key)")
		}
	})
	t.Run("frame mask", func(t *testing.T) {
		t.Parallel()
		got := make(chan error, 1)
		srv := startServer(t, acceptThen(func(_ *testing.T, _ net.Conn, br *bufio.Reader) {
			_, err := readClientFrame(br)
			got <- err
		}))
		conn, _ := dialFake(t, srv, cdploopback.WithRand(&recordingReader{limit: 16}))
		if err := conn.WriteMessage(testCtx(t), []byte(`{"id":1}`)); err == nil {
			t.Fatal("WriteMessage succeeded with a failing rand (predictable mask)")
		}
		_ = conn.Close()
		select {
		case err := <-got:
			if err == nil {
				t.Fatal("a frame was sent although no mask could be drawn")
			}
		case <-time.After(testTimeout):
			t.Fatal("server never saw the connection end")
		}
	})
}

func TestWS_DefaultRandMasksFrames(t *testing.T) {
	t.Parallel()
	const n = 8
	frames := make(chan clientFrame, n)
	srv := startServer(t, acceptThen(func(t *testing.T, c net.Conn, br *bufio.Reader) {
		for range n {
			f, err := readClientFrame(br)
			if err != nil {
				t.Errorf("server: read frame: %v", err)
				return
			}
			frames <- f
		}
		holdOpen(t, c, br)
	}))
	conn, _ := dialFake(t, srv)
	for i := range n {
		if err := conn.WriteMessage(testCtx(t), []byte(strconv.Itoa(i))); err != nil {
			t.Fatalf("WriteMessage: %v", err)
		}
	}
	seen := map[[4]byte]bool{}
	for i := range n {
		select {
		case f := <-frames:
			if !f.masked {
				t.Fatalf("frame %d not masked", i)
			}
			seen[f.mask] = true
		case <-time.After(testTimeout):
			t.Fatalf("frame %d not received", i)
		}
	}
	if len(seen) < 2 || seen[[4]byte{}] {
		t.Fatalf("masks look non-random: %v", seen)
	}
}

// ADR 0008: the handshake sends Host: 127.0.0.1:<port> and no Origin header,
// and nothing that would make Chrome or a proxy treat the request otherwise.
func TestWS_HandshakeSendsHostAndOriginForLoopbackOnly(t *testing.T) {
	t.Parallel()
	reqs := make(chan *http.Request, 1)
	srv := startServer(t, func(t *testing.T, c net.Conn, br *bufio.Reader) {
		req := readHandshake(t, br)
		if req == nil {
			return
		}
		reqs <- req
		upgrade(t, c, req)
		holdOpen(t, c, br)
	})
	_, _ = dialFake(t, srv)
	var req *http.Request
	select {
	case req = <-reqs:
	case <-time.After(testTimeout):
		t.Fatal("no handshake received")
	}

	wantHost := "127.0.0.1:" + strconv.Itoa(srv.port)
	checks := []struct {
		name string
		got  string
		want string
	}{
		{name: "method", got: req.Method, want: http.MethodGet},
		{name: "request target (origin-form)", got: req.RequestURI, want: browserPath},
		{name: "proto", got: req.Proto, want: "HTTP/1.1"},
		{name: "Host", got: req.Host, want: wantHost},
		{name: "Upgrade", got: strings.ToLower(req.Header.Get("Upgrade")), want: "websocket"},
		{name: "Sec-WebSocket-Version", got: req.Header.Get("Sec-WebSocket-Version"), want: "13"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if !strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade") {
		t.Errorf("Connection = %q, want Upgrade", req.Header.Get("Connection"))
	}
	if n := len(req.Header.Values("Host")) + len(req.Header.Values("Origin")); n != 0 {
		t.Errorf("extra Host/Origin header lines: %v", req.Header)
	}
	for _, h := range []string{
		"Origin", "Sec-WebSocket-Origin", "Sec-WebSocket-Extensions", "Sec-WebSocket-Protocol",
		"Cookie", "Authorization", "Proxy-Authorization", "Proxy-Connection",
		"Forwarded", "X-Forwarded-For", "X-Forwarded-Host",
	} {
		if v, ok := req.Header[http.CanonicalHeaderKey(h)]; ok {
			t.Errorf("handshake sends %s: %q", h, v)
		}
	}
}
