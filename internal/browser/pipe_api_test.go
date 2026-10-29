// Tests for the CDP transport and client (J1 T7, ADR 0008). This file builds
// on every OS; the process tests that need a real pipe are in
// pipe_unix_test.go (fake browser = this test binary re-executed, see
// fakebrowser_unix_test.go). No real Chrome is ever started.
//
// Expected API (internal/browser):
//
//	// pipe.go (all OSes): NUL-delimited JSON framing over any reader/writer.
//	const MaxMessageBytes = 16 << 20 // per message, pipe and WebSocket alike
//
//	var (
//		ErrMessageTooLarge = errors.New(...) // a frame over MaxMessageBytes; the browser is killed
//		ErrBadFrame        = errors.New(...) // an outgoing frame holding a raw NUL, or an incoming non-JSON frame
//		ErrBrowserGone     = errors.New(...) // the browser exited, was killed, or the transport is closed
//		ErrCDP             = errors.New(...) // the browser answered with a CDP error object
//	)
//
//	// Transport moves whole CDP messages. Send appends the NUL; Recv strips it.
//	type Transport interface {
//		Send(msg []byte) error   // refuses msg holding a raw 0x00 (ErrBadFrame), writes nothing then
//		Recv() ([]byte, error)   // ErrMessageTooLarge past MaxMessageBytes, before reading much further
//		Close() error
//	}
//	func NewPipeTransport(r io.Reader, w io.Writer) *PipeTransport // *PipeTransport implements Transport;
//	                                                              // Close closes r and w when they are io.Closers
//
//	// client.go (all OSes): ids, sessions, one mutex-guarded writer.
//	func NewClient(t Transport) *Client
//	// Call sends {"id":n,"method":method,"sessionId":sessionID (omitted if ""),"params":params}
//	// and returns the "result" of the response with the same id AND session id.
//	// Responses with an unknown id or another session id, and events, are dropped.
//	// Errors never quote a message, a parameter or a CDP error text.
//	func (c *Client) Call(ctx context.Context, sessionID, method string, params any) (json.RawMessage, error)
//	func (c *Client) Close() error
//
//	// pipe_unix.go (//go:build unix): the real StartFunc.
//	// StartPipe starts cmd.Path with cmd.Args and cmd.Env, Chrome's stdin and
//	// stdout on /dev/null, stderr to cmd.Stderr, and the CDP pipe as fds 3
//	// (browser reads) and 4 (browser writes) through ExtraFiles. The browser
//	// gets its own process group (Setpgid); on Linux Pdeathsig=SIGKILL is a
//	// backstop. Cancelling ctx, Close, an oversized message or a protocol
//	// violation kill the whole process group. Peer exit is noticed from the
//	// process exit, even if a grandchild still holds the pipe or stderr.
//	func StartPipe(ctx context.Context, cmd Command) (*PipeProcess, error)
//	func (p *PipeProcess) Client() *Client
//	func (p *PipeProcess) Pid() int
//	func (p *PipeProcess) Done() <-chan struct{} // closed once the browser process has exited and been reaped
//	func (p *PipeProcess) Close() error          // kills the process group, waits; idempotent, nil after a kill
//
//	// PipeStarter adapts StartPipe to the T6 StartFunc used by Launch.
//	type PipeStarter struct{ ... }
//	func (s *PipeStarter) Start(ctx context.Context, cmd Command) error // a StartFunc
//	func (s *PipeStarter) Process() *PipeProcess                       // nil before a successful Start
//
// Windows: no StartPipe yet (T7c, loopback port on top of T7.1); the
// package and its tests must still compile there.
package browser_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// Compile-time checks of the transport API.
var (
	_ browser.Transport = (*browser.PipeTransport)(nil)
	_                   = browser.NewClient
)

func TestPipe_Constants(t *testing.T) {
	t.Parallel()
	if browser.MaxMessageBytes != 16<<20 {
		t.Errorf("MaxMessageBytes = %d, want 16 MiB (ADR 0008)", browser.MaxMessageBytes)
	}
	errs := []error{browser.ErrMessageTooLarge, browser.ErrBadFrame, browser.ErrBrowserGone, browser.ErrCDP}
	for i, a := range errs {
		if a == nil {
			t.Fatalf("sentinel %d is nil", i)
		}
		for j, b := range errs {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinel %v matches %v: must be distinct", a, b)
			}
		}
	}
}

// countingReader counts the bytes the transport pulled from the browser.
type countingReader struct {
	mu sync.Mutex
	r  io.Reader
	n  int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.mu.Lock()
	c.n += int64(n)
	c.mu.Unlock()
	return n, err //nolint:wrapcheck // test double passes the reader error through
}

func (c *countingReader) count() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// endlessReader is a browser that never ends its message.
type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

// recvAll reads frames until io.EOF or an error.
func recvAll(tr browser.Transport) ([][]byte, error) {
	var out [][]byte
	for {
		m, err := tr.Recv()
		if err != nil {
			return out, err
		}
		out = append(out, bytes.Clone(m))
	}
}

// TestPipeTransport_FramingSplitAndCoalesced (in memory): frames split across reads,
// several frames in one read, and a frame cut by EOF.
func TestPipeTransport_FramingSplitAndCoalesced(t *testing.T) {
	t.Parallel()
	a := `{"id":1,"result":{}}`
	b := `{"method":"Page.loadEventFired","params":{"timestamp":1}}`
	c := `{"id":2,"result":{"value":"` + strings.Repeat("x", 70_000) + `"}}`
	stream := a + "\x00" + b + "\x00" + c + "\x00"

	tests := []struct {
		name    string
		r       io.Reader
		want    []string
		wantErr error // after the frames; io.EOF for a clean end
	}{
		{name: "coalesced in one read", r: strings.NewReader(stream), want: []string{a, b, c}, wantErr: io.EOF},
		{name: "split one byte per read", r: iotest.OneByteReader(strings.NewReader(stream)), want: []string{a, b, c}, wantErr: io.EOF},
		{name: "split in halves", r: iotest.HalfReader(strings.NewReader(stream)), want: []string{a, b, c}, wantErr: io.EOF},
		{name: "data error after last frame", r: iotest.DataErrReader(strings.NewReader(stream)), want: []string{a, b, c}, wantErr: io.EOF},
		// A frame cut by EOF is never delivered as a message.
		{name: "truncated last frame", r: strings.NewReader(a + "\x00" + `{"id":3,"res`), want: []string{a}, wantErr: browser.ErrBrowserGone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tr := browser.NewPipeTransport(tt.r, io.Discard)
			got, err := recvAll(tr)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d frames, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if string(got[i]) != tt.want[i] {
					t.Errorf("frame %d = %.80q..., want %.80q...", i, got[i], tt.want[i])
				}
				if bytes.IndexByte(got[i], 0) >= 0 {
					t.Errorf("frame %d still holds the NUL delimiter", i)
				}
			}
			// A clean end may surface as io.EOF or ErrBrowserGone.
			cleanEnd := errors.Is(tt.wantErr, io.EOF) && errors.Is(err, browser.ErrBrowserGone)
			if !errors.Is(err, tt.wantErr) && !cleanEnd {
				t.Errorf("end error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestPipeTransport_OversizedRefusedWhileReading (in memory): the cap is enforced while
// reading, not after buffering the whole message.
func TestPipeTransport_OversizedRefusedWhileReading(t *testing.T) {
	t.Parallel()
	const capB = browser.MaxMessageBytes
	tests := []struct {
		name    string
		size    int // bytes before the NUL
		nul     bool
		wantErr error
	}{
		{name: "exactly the cap", size: capB, nul: true},
		{name: "one over the cap", size: capB + 1, nul: true, wantErr: browser.ErrMessageTooLarge},
		{name: "endless message without NUL", size: -1, wantErr: browser.ErrMessageTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var src io.Reader = endlessReader{}
			if tt.size >= 0 {
				body := bytes.Repeat([]byte{'a'}, tt.size)
				if tt.nul {
					body = append(body, 0)
				}
				src = bytes.NewReader(body)
			}
			cr := &countingReader{r: src}
			tr := browser.NewPipeTransport(cr, io.Discard)
			msg, err := tr.Recv()
			if tt.wantErr == nil {
				if err != nil || len(msg) != tt.size {
					t.Fatalf("Recv = %d bytes, %v; want %d bytes, nil", len(msg), err, tt.size)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Recv error = %v, want %v", err, tt.wantErr)
			}
			if msg != nil {
				t.Errorf("Recv returned %d bytes with the error, want none", len(msg))
			}
			// Refused while reading: at most one read buffer past the cap.
			if n := cr.count(); n > int64(capB)+1<<20 {
				t.Errorf("transport read %d bytes before refusing, want <= cap + 1 MiB", n)
			}
			// A refused transport stays refused.
			if _, err := tr.Recv(); err == nil {
				t.Error("Recv after an oversized message succeeded, want an error")
			}
		})
	}
}

// TestPipeTransport_RawNULNeverWritten: a raw NUL can
// never reach the wire through Send.
func TestPipeTransport_RawNULNeverWritten(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	var wire bytes.Buffer
	tr := browser.NewPipeTransport(strings.NewReader(""), &wire)

	bad := []byte(`{"id":1,"method":"Input.insertText","params":{"text":"a` + "\x00" + `{\"id\":2}` + canary + `"}}`)
	err := tr.Send(bad)
	if !errors.Is(err, browser.ErrBadFrame) {
		t.Fatalf("Send(raw NUL) = %v, want ErrBadFrame", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Errorf("Send error echoes the payload: %q", err)
	}
	if wire.Len() != 0 {
		t.Errorf("Send wrote %d bytes for a refused frame, want 0", wire.Len())
	}

	good := []byte(`{"id":1,"method":"Fake.echo","params":{"text":"a\u0000b"}}`)
	if err := tr.Send(good); err != nil {
		t.Fatalf("Send(escaped NUL) = %v", err)
	}
	if want := string(good) + "\x00"; wire.String() != want {
		t.Errorf("wire = %q, want %q (one frame, one NUL)", wire.String(), want)
	}
}
