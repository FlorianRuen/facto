package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/FlorianRuen/facto/internal/httpx/cdploopback"
)

// handshakeID is the id of the Browser.getVersion request a PortTransport
// sends before anything else. Its response is consumed by the handshake,
// before any Client reads the transport.
const handshakeID = 1

// WSConn is the consumer-side view of *cdploopback.Conn.
type WSConn interface {
	ReadMessage(ctx context.Context) ([]byte, error)
	WriteMessage(ctx context.Context, p []byte) error
	Close() error
}

// DialLoopback dials t through internal/httpx/cdploopback only: the literal
// 127.0.0.1:<port>, tcp4, no resolver, no proxy, no redirect, no TLS. t is
// validated again first (port 1..65535, browser GUID path): nothing is
// dialled for an invalid t.
func DialLoopback(ctx context.Context, t DevToolsTarget, opts ...cdploopback.Option) (WSConn, error) {
	if !t.valid() {
		return nil, fmt.Errorf("%w: invalid devtools target", ErrPortFile)
	}
	c, err := cdploopback.New(t.Port, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial devtools: %w", err)
	}
	conn, err := c.Dial(ctx, t.Path)
	if err != nil {
		return nil, fmt.Errorf("dial devtools: %w", err)
	}
	return conn, nil
}

// PortTransport adapts a WSConn to Transport: one WebSocket message is one
// CDP message. Until Handshake has succeeded, Send and Recv fail with
// ErrNoHandshake and nothing is written to or read from the connection.
// Close closes the connection; it is idempotent.
type PortTransport struct {
	conn   WSConn
	ready  atomic.Bool
	ctx    context.Context // cancelled by Close: ends blocked reads and writes (Transport has no ctx)
	cancel context.CancelFunc

	hsMu sync.Mutex // one handshake at a time

	closeOnce sync.Once
	closeErr  error
}

var _ Transport = (*PortTransport)(nil)

// NewPortTransport wraps conn. Nothing is sent until Handshake.
func NewPortTransport(conn WSConn) *PortTransport {
	ctx, cancel := context.WithCancel(context.Background())
	return &PortTransport{conn: conn, ctx: ctx, cancel: cancel}
}

// Send writes msg as one WebSocket message.
func (t *PortTransport) Send(msg []byte) error {
	if !t.ready.Load() {
		return ErrNoHandshake
	}
	if err := t.conn.WriteMessage(t.ctx, msg); err != nil {
		return transportError("write", err)
	}
	return nil
}

// Recv returns the next WebSocket message.
func (t *PortTransport) Recv() ([]byte, error) {
	if !t.ready.Load() {
		return nil, ErrNoHandshake
	}
	msg, err := t.conn.ReadMessage(t.ctx)
	if err != nil {
		return nil, transportError("read", err)
	}
	return msg, nil
}

// transportError maps a WebSocket failure to the Transport sentinels. The
// cdploopback errors never quote a payload.
func transportError(op string, err error) error {
	if errors.Is(err, cdploopback.ErrMessageTooLarge) {
		return fmt.Errorf("%w: %s: %w", ErrMessageTooLarge, op, err)
	}
	return fmt.Errorf("%w: %s: %w", ErrBrowserGone, op, err)
}

// Close ends pending I/O and closes the connection. Idempotent.
func (t *PortTransport) Close() error {
	t.closeOnce.Do(func() {
		t.ready.Store(false)
		t.cancel()
		if err := t.conn.Close(); err != nil {
			t.closeErr = fmt.Errorf("close devtools websocket: %w", err)
		}
	})
	return t.closeErr
}

// versionResponse is the part of the Browser.getVersion response the
// handshake checks. SessionID and Method must be absent.
type versionResponse struct {
	ID        *int64           `json:"id"`
	SessionID *json.RawMessage `json:"sessionId"`
	Method    *json.RawMessage `json:"method"`
	Error     *json.RawMessage `json:"error"`
	Result    *struct {
		ProtocolVersion string `json:"protocolVersion"`
		Product         string `json:"product"`
	} `json:"result"`
}

// Handshake writes one Browser.getVersion request and requires the very next
// message to be its response (same id, no session) with non-empty string
// "protocolVersion" and "product". An event, another id, a CDP error, a
// non-JSON message, the peer closing or ctx ending: ErrHandshake, and the
// connection is closed. The error never quotes what the peer sent.
func (t *PortTransport) Handshake(ctx context.Context) error {
	t.hsMu.Lock()
	defer t.hsMu.Unlock()
	if t.ready.Load() {
		return nil
	}
	if err := t.handshake(ctx); err != nil {
		_ = t.Close() // the handshake error is the one reported
		return err
	}
	t.ready.Store(true)
	return nil
}

func (t *PortTransport) handshake(ctx context.Context) error {
	req, err := json.Marshal(request{ID: handshakeID, Method: "Browser.getVersion"})
	if err != nil {
		return fmt.Errorf("%w: encode request", ErrHandshake)
	}
	if err := t.conn.WriteMessage(ctx, req); err != nil {
		return fmt.Errorf("%w: write: %w", ErrHandshake, err)
	}
	msg, err := t.conn.ReadMessage(ctx)
	if err != nil {
		return fmt.Errorf("%w: read: %w", ErrHandshake, err)
	}
	var resp versionResponse
	if json.Unmarshal(msg, &resp) != nil {
		// Never quote the message nor the decoder error.
		return fmt.Errorf("%w: response is not a Browser.getVersion result", ErrHandshake)
	}
	switch {
	case resp.ID == nil || *resp.ID != handshakeID:
		return fmt.Errorf("%w: first message is not the getVersion response", ErrHandshake)
	case resp.SessionID != nil || resp.Method != nil:
		return fmt.Errorf("%w: response carries a session or a method", ErrHandshake)
	case resp.Error != nil:
		return fmt.Errorf("%w: browser answered with an error", ErrHandshake)
	case resp.Result == nil || resp.Result.ProtocolVersion == "" || resp.Result.Product == "":
		return fmt.Errorf("%w: protocolVersion or product missing", ErrHandshake)
	}
	return nil
}

// TCPListener is one listening TCP socket and its owner.
type TCPListener struct {
	Addr netip.AddrPort
	PID  int
}

// loopbackV4 is the only address the CDP port may listen on.
var loopbackV4 = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// LoopbackListenerPID returns the pid owning the socket listening on port.
// Exactly one listener may use that port, bound to 127.0.0.1 (IPv4 only):
// none, two, or one on any other address (0.0.0.0, ::, ::1, 127.0.0.2,
// v4-mapped…) is ErrListenerNotBrowser, as is a pid <= 0.
func LoopbackListenerPID(rows []TCPListener, port int) (int, error) {
	var found []TCPListener
	for _, r := range rows {
		if int(r.Addr.Port()) == port {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		return 0, fmt.Errorf("%w: %d listeners on the cdp port, want exactly 1", ErrListenerNotBrowser, len(found))
	}
	r := found[0]
	if r.Addr.Addr() != loopbackV4 {
		return 0, fmt.Errorf("%w: cdp port not bound to 127.0.0.1 only", ErrListenerNotBrowser)
	}
	if r.PID <= 0 {
		return 0, fmt.Errorf("%w: no owner pid", ErrListenerNotBrowser)
	}
	return r.PID, nil
}

// PortConnectConfig configures ConnectPort.
type PortConnectConfig struct {
	// PortFile was armed before the browser started.
	PortFile *PortFile
	// BrowserPID is the pid of the started browser.
	BrowserPID int
	// ListenerPID returns the pid owning the CDP port (windows:
	// GetExtendedTcpTable + LoopbackListenerPID). Nil, an error or a pid
	// other than BrowserPID: ErrListenerNotBrowser, nothing dialled.
	ListenerPID func(ctx context.Context, port int) (int, error)
	// Dial opens the WebSocket. Nil: DialLoopback.
	Dial func(ctx context.Context, t DevToolsTarget) (WSConn, error)
}

// ConnectPort reads the port file, checks the listener's pid, dials and
// handshakes, in that order. It returns a handshaken transport, or closes
// whatever it opened.
func ConnectPort(ctx context.Context, cfg PortConnectConfig) (*PortTransport, error) {
	if cfg.PortFile == nil {
		return nil, fmt.Errorf("%w: port file not armed", ErrPortFile)
	}
	tg, err := cfg.PortFile.Read(ctx)
	if err != nil {
		return nil, err
	}
	if cfg.ListenerPID == nil {
		return nil, fmt.Errorf("%w: no listener lookup", ErrListenerNotBrowser)
	}
	pid, err := cfg.ListenerPID(ctx, tg.Port)
	if err != nil {
		return nil, fmt.Errorf("%w: lookup: %w", ErrListenerNotBrowser, err)
	}
	if cfg.BrowserPID <= 0 || pid != cfg.BrowserPID {
		return nil, fmt.Errorf("%w: cdp port owned by another process", ErrListenerNotBrowser)
	}
	dial := cfg.Dial
	if dial == nil {
		dial = func(ctx context.Context, t DevToolsTarget) (WSConn, error) { return DialLoopback(ctx, t) }
	}
	conn, err := dial(ctx, tg)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLaunchFailed, err)
	}
	if conn == nil {
		return nil, fmt.Errorf("%w: dial returned no connection", ErrLaunchFailed)
	}
	tr := NewPortTransport(conn)
	if err := tr.Handshake(ctx); err != nil {
		return nil, err
	}
	return tr, nil
}
