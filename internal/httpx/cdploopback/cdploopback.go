// Package cdploopback is a minimal RFC 6455 WebSocket client that can only
// reach the Chrome DevTools endpoint on the literal address 127.0.0.1.
//
// It exists for the Windows build (ADR 0008 "Windows (A4)", plan J1 Q1 and
// T7.1), where Chrome cannot be driven over a pipe and listens on a random
// loopback port instead. The client takes a port, never a host name, so no
// resolver is ever consulted; it never uses a proxy, never follows a
// redirect, never speaks TLS and bounds every message it reads.
//
// Only internal/browser may import it (depguard rule "cdploopback" and
// callers_test.go). Errors never carry a frame payload or anything the peer
// sent: a CDP message can hold typed credentials.
package cdploopback

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6455 4.2.2 mandates SHA-1 for Sec-WebSocket-Accept, not used for security; the handshake exists only for the Windows port fallback tracked by https://github.com/FlorianRuen/facto/issues/3
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// MaxMessageSize caps one reassembled message (ADR 0008: 16 MiB).
const MaxMessageSize = 16 << 20

// MaxHandshakeHeader caps the server handshake response, status line and
// headers included (ADR 0008: 8 KiB).
const MaxHandshakeHeader = 8 << 10

// loopbackHost is the only host this package ever dials.
const loopbackHost = "127.0.0.1"

// wsGUID is the RFC 6455 handshake GUID.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// maxPathLen bounds a request path; DevTools paths are about 60 bytes.
const maxPathLen = 2048

var (
	// ErrInvalidPort is returned for a port outside 1..65535.
	ErrInvalidPort = errors.New("cdploopback: invalid port")
	// ErrNotLoopback is returned when a target host is anything but the
	// literal 127.0.0.1.
	ErrNotLoopback = errors.New("cdploopback: target is not 127.0.0.1")
	// ErrInvalidTarget is returned for a malformed ws URL or request path.
	ErrInvalidTarget = errors.New("cdploopback: invalid target")
	// ErrHandshake is returned when the opening handshake fails.
	ErrHandshake = errors.New("cdploopback: handshake refused")
	// ErrProtocol is returned for a frame violating RFC 6455 or this
	// client's restrictions.
	ErrProtocol = errors.New("cdploopback: protocol violation")
	// ErrMessageTooLarge is returned when a message exceeds MaxMessageSize.
	ErrMessageTooLarge = errors.New("cdploopback: message too large")
	// ErrClosed is returned once the peer sent a close frame or the Conn
	// was closed.
	ErrClosed = errors.New("cdploopback: connection closed")
)

// pastDeadline unblocks pending I/O at once when set as a deadline.
var pastDeadline = time.Unix(1, 0)

// Dialer is the consumer-side dial seam; *net.Dialer satisfies it.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Option configures a Client.
type Option func(*Client)

// WithDialer replaces the default dialer (a plain net.Dialer, which never
// uses a proxy). A nil d is ignored.
func WithDialer(d Dialer) Option {
	return func(c *Client) {
		if d != nil {
			c.dialer = d
		}
	}
}

// WithRand replaces crypto/rand.Reader as the source of the handshake key and
// frame masks. A nil r is ignored.
func WithRand(r io.Reader) Option {
	return func(c *Client) {
		if r != nil {
			c.rand = r
		}
	}
}

// Target is a parsed DevToolsActivePort / webSocketDebuggerUrl target.
type Target struct {
	Port int
	Path string
}

// ParseTarget accepts only ws://127.0.0.1:<port><path>, the authority
// starting with the literal "127.0.0.1:": no other host or notation (host
// name, brackets, short or octal forms), no userinfo, no TLS, a decimal port
// in 1..65535 without leading zeros and an origin-form path.
func ParseTarget(raw string) (Target, error) {
	const scheme = "ws://"
	if !strings.HasPrefix(raw, scheme) {
		return Target{}, fmt.Errorf("%w: scheme must be ws", ErrInvalidTarget)
	}
	rest := raw[len(scheme):]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return Target{}, fmt.Errorf("%w: missing path", ErrInvalidTarget)
	}
	authority, path := rest[:slash], rest[slash:]
	if strings.ContainsAny(authority, "@") {
		return Target{}, fmt.Errorf("%w: userinfo refused", ErrInvalidTarget)
	}
	// The authority must spell the literal itself: no brackets, no other
	// notation that a parser could normalise to 127.0.0.1.
	portStr, ok := strings.CutPrefix(authority, loopbackHost+":")
	if !ok {
		if authority == loopbackHost {
			return Target{}, fmt.Errorf("%w: missing port", ErrInvalidTarget)
		}
		return Target{}, ErrNotLoopback
	}
	port, err := parsePort(portStr)
	if err != nil {
		return Target{}, err
	}
	if err := validPath(path); err != nil {
		return Target{}, err
	}
	return Target{Port: port, Path: path}, nil
}

// parsePort parses a decimal port without sign or leading zeros.
func parsePort(s string) (int, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("%w: malformed port", ErrInvalidTarget)
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("%w: malformed port", ErrInvalidTarget)
		}
	}
	if len(s) > 5 {
		return 0, ErrInvalidPort
	}
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%w: malformed port", ErrInvalidTarget)
	}
	if !validPort(p) {
		return 0, ErrInvalidPort
	}
	return p, nil
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

// validPath accepts an origin-form request target made of visible ASCII: it
// must start with a single "/", and carries no fragment, space, control
// character or non-ASCII byte, so it can neither name another host nor
// inject a header.
func validPath(p string) error {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") || len(p) > maxPathLen {
		return fmt.Errorf("%w: path must be origin-form", ErrInvalidTarget)
	}
	for i := range len(p) {
		if b := p[i]; b <= ' ' || b >= 0x7F || b == '#' {
			return fmt.Errorf("%w: forbidden byte in path", ErrInvalidTarget)
		}
	}
	return nil
}

// Client dials the DevTools WebSocket on 127.0.0.1:<port>.
type Client struct {
	port   int
	dialer Dialer
	rand   io.Reader
}

// New returns a client for 127.0.0.1:port. It refuses ports outside
// 1..65535 and takes no host name.
func New(port int, opts ...Option) (*Client, error) {
	if !validPort(port) {
		return nil, ErrInvalidPort
	}
	c := &Client{port: port, dialer: &net.Dialer{}, rand: rand.Reader}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// addr is the only address this client ever dials.
func (c *Client) addr() string {
	return net.JoinHostPort(loopbackHost, strconv.Itoa(c.port))
}

// Dial dials exactly 127.0.0.1:<port> over tcp4 once and performs the client
// handshake for path. It never follows redirects, never uses a proxy and
// never speaks TLS. The path is validated before any dial.
func (c *Client) Dial(ctx context.Context, path string) (*Conn, error) {
	if err := validPath(path); err != nil {
		return nil, err
	}
	var key [16]byte
	if _, err := io.ReadFull(c.rand, key[:]); err != nil {
		return nil, fmt.Errorf("cdploopback: draw handshake key: %w", err)
	}
	keyStr := base64.StdEncoding.EncodeToString(key[:])

	nc, err := c.dialer.DialContext(ctx, "tcp4", c.addr())
	if err != nil {
		return nil, fmt.Errorf("cdploopback: dial %s: %w", c.addr(), err)
	}
	br, err := c.handshake(ctx, nc, path, keyStr)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	return &Conn{nc: nc, br: br, rand: c.rand}, nil
}

// handshake sends the upgrade request and checks the response. The returned
// reader holds any frame bytes the server sent right after the headers.
func (c *Client) handshake(ctx context.Context, nc net.Conn, path, key string) (*bufio.Reader, error) {
	release := bindContext(ctx, nc.SetDeadline)
	defer release()

	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + c.addr() + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := io.WriteString(nc, req); err != nil {
		return nil, ioError(ctx, ErrHandshake, "write request", err)
	}
	br := bufio.NewReaderSize(nc, 4096)
	lines, err := readHeader(br)
	if err != nil {
		return nil, ioError(ctx, ErrHandshake, "read response", err)
	}
	if err := checkResponse(lines, acceptFor(key)); err != nil {
		return nil, err
	}
	return br, nil
}

// errHeaderTooLarge is internal: the cap is reported as ErrHandshake.
var errHeaderTooLarge = errors.New("response header over 8 KiB")

// errBadLineEnding is internal: a bare LF or CR in the response header.
var errBadLineEnding = errors.New("malformed line ending")

// readHeader reads CRLF-terminated lines up to the empty line, at most
// MaxHandshakeHeader bytes in all, and returns them without the empty line.
func readHeader(br *bufio.Reader) ([]string, error) {
	var (
		lines []string
		line  []byte
		total int
	)
	for {
		b, err := br.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("read response header: %w", err)
		}
		total++
		if total > MaxHandshakeHeader {
			return nil, errHeaderTooLarge
		}
		if b != '\n' {
			line = append(line, b)
			continue
		}
		if len(line) == 0 || line[len(line)-1] != '\r' {
			return nil, errBadLineEnding
		}
		s := string(line[:len(line)-1])
		line = line[:0]
		if strings.ContainsAny(s, "\r\x00") {
			return nil, errBadLineEnding
		}
		if s == "" {
			return lines, nil
		}
		lines = append(lines, s)
	}
}

// checkResponse verifies the status line and the upgrade headers. Error
// messages name the failed check only, never a value sent by the peer.
func checkResponse(lines []string, wantAccept string) error {
	if len(lines) == 0 {
		return fmt.Errorf("%w: empty response", ErrHandshake)
	}
	status := lines[0]
	if status != "HTTP/1.1 101" && !strings.HasPrefix(status, "HTTP/1.1 101 ") {
		return fmt.Errorf("%w: status is not HTTP/1.1 101", ErrHandshake)
	}
	var upgrade, accept []string
	connUpgrade := false
	for _, l := range lines[1:] {
		name, value, ok := strings.Cut(l, ":")
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			return fmt.Errorf("%w: malformed header line", ErrHandshake)
		}
		value = strings.Trim(value, " \t")
		switch strings.ToLower(name) {
		case "upgrade":
			upgrade = append(upgrade, value)
		case "connection":
			for tok := range strings.SplitSeq(value, ",") {
				if strings.EqualFold(strings.Trim(tok, " \t"), "upgrade") {
					connUpgrade = true
				}
			}
		case "sec-websocket-accept":
			accept = append(accept, value)
		case "sec-websocket-extensions", "sec-websocket-protocol":
			return fmt.Errorf("%w: unrequested extension or subprotocol", ErrHandshake)
		}
	}
	if len(upgrade) != 1 || !strings.EqualFold(upgrade[0], "websocket") {
		return fmt.Errorf("%w: missing Upgrade: websocket", ErrHandshake)
	}
	if !connUpgrade {
		return fmt.Errorf("%w: missing Connection: Upgrade", ErrHandshake)
	}
	if len(accept) != 1 || accept[0] != wantAccept {
		return fmt.Errorf("%w: bad Sec-WebSocket-Accept", ErrHandshake)
	}
	return nil
}

// acceptFor computes Sec-WebSocket-Accept for key (RFC 6455 4.2.2).
func acceptFor(key string) string {
	h := sha1.Sum([]byte(key + wsGUID)) // #nosec G401 -- RFC 6455 mandates SHA-1 for Sec-WebSocket-Accept, not used for security; Windows port fallback, https://github.com/FlorianRuen/facto/issues/3
	return base64.StdEncoding.EncodeToString(h[:])
}

// bindContext applies ctx's deadline through set and unblocks pending I/O
// when ctx is cancelled. The returned release clears the deadline; it waits
// for a concurrent cancellation callback so a later call starts clean.
func bindContext(ctx context.Context, set func(time.Time) error) func() {
	if d, ok := ctx.Deadline(); ok {
		_ = set(d)
	}
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(fired)
		_ = set(pastDeadline)
	})
	return func() {
		if !stop() {
			<-fired
		}
		_ = set(time.Time{})
	}
}

// ioError wraps an I/O failure under sentinel. When ctx ended, its error is
// joined so callers can test errors.Is(err, context.Canceled).
func ioError(ctx context.Context, sentinel error, op string, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("%w: %s: %w", sentinel, op, cerr)
	}
	return fmt.Errorf("%w: %s: %w", sentinel, op, err)
}
