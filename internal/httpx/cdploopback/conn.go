package cdploopback

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

// Opcodes (RFC 6455 5.2).
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// maxControlPayload is the RFC 6455 5.5 limit on control frame payloads.
const maxControlPayload = 125

// readChunk bounds each payload allocation step, so a peer declaring a large
// frame and sending nothing does not make the client allocate the whole of it.
const readChunk = 64 << 10

// closeNormal is the payload of a 1000 (normal closure) close frame.
var closeNormal = []byte{0x03, 0xE8}

// Conn is an established DevTools WebSocket connection. ReadMessage must not
// be called concurrently with itself; WriteMessage and Close are safe to call
// from any goroutine.
type Conn struct {
	nc   net.Conn
	br   *bufio.Reader
	rand io.Reader

	rmu sync.Mutex // serialises readers
	wmu sync.Mutex // serialises frame writes (messages and pongs)

	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

// frameHeader is a decoded frame header.
type frameHeader struct {
	fin    bool
	opcode byte
	length int
}

// ReadMessage returns the next reassembled text or binary message, answering
// pings transparently. It is bounded by ctx. Any protocol violation closes
// the connection.
func (c *Conn) ReadMessage(ctx context.Context) ([]byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.closed.Load() {
		return nil, ErrClosed
	}
	release := bindContext(ctx, c.nc.SetReadDeadline)
	defer release()

	msg, err := c.readMessage(ctx)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return msg, nil
}

func (c *Conn) readMessage(ctx context.Context) ([]byte, error) {
	var (
		msg        []byte
		inMessage  bool
		textOpcode bool
	)
	for {
		h, err := c.readHeader(ctx)
		if err != nil {
			return nil, err
		}
		switch h.opcode {
		case opPing, opPong, opClose:
			if err := c.handleControl(ctx, h); err != nil {
				return nil, err
			}
			continue
		case opText, opBinary:
			if inMessage {
				return nil, fmt.Errorf("%w: data frame inside a fragmented message", ErrProtocol)
			}
			inMessage, textOpcode = true, h.opcode == opText
		case opContinuation:
			if !inMessage {
				return nil, fmt.Errorf("%w: continuation without a start", ErrProtocol)
			}
		}
		// Cumulative cap, checked before any allocation. msg is at most
		// MaxMessageSize here, so the subtraction cannot underflow.
		if h.length > MaxMessageSize-len(msg) {
			return nil, fmt.Errorf("%w: over %d bytes", ErrMessageTooLarge, MaxMessageSize)
		}
		if msg, err = c.readPayload(ctx, msg, h.length); err != nil {
			return nil, err
		}
		if h.fin {
			if textOpcode && !utf8.Valid(msg) {
				return nil, fmt.Errorf("%w: text message is not UTF-8", ErrProtocol)
			}
			if msg == nil {
				msg = []byte{}
			}
			return msg, nil
		}
	}
}

// readHeader reads and validates one frame header. Every check runs before
// the payload is read or allocated.
func (c *Conn) readHeader(ctx context.Context) (frameHeader, error) {
	var b [8]byte
	if _, err := io.ReadFull(c.br, b[:2]); err != nil {
		return frameHeader{}, ioError(ctx, ErrClosed, "read frame", err)
	}
	h := frameHeader{fin: b[0]&0x80 != 0, opcode: b[0] & 0x0F}
	if b[0]&0x70 != 0 {
		return h, fmt.Errorf("%w: RSV bits set", ErrProtocol)
	}
	if b[1]&0x80 != 0 {
		return h, fmt.Errorf("%w: masked server frame", ErrProtocol)
	}
	control := h.opcode&0x8 != 0
	switch h.opcode {
	case opContinuation, opText, opBinary, opClose, opPing, opPong:
	default:
		return h, fmt.Errorf("%w: reserved opcode", ErrProtocol)
	}
	n := uint64(b[1] & 0x7F)
	if control && (!h.fin || n > maxControlPayload) {
		return h, fmt.Errorf("%w: fragmented or oversized control frame", ErrProtocol)
	}
	switch n {
	case 126:
		if _, err := io.ReadFull(c.br, b[:2]); err != nil {
			return h, ioError(ctx, ErrClosed, "read frame length", err)
		}
		n = uint64(binary.BigEndian.Uint16(b[:2]))
		if n <= maxControlPayload {
			return h, fmt.Errorf("%w: non-minimal length", ErrProtocol)
		}
	case 127:
		if _, err := io.ReadFull(c.br, b[:8]); err != nil {
			return h, ioError(ctx, ErrClosed, "read frame length", err)
		}
		n = binary.BigEndian.Uint64(b[:8])
		if n>>63 != 0 {
			return h, fmt.Errorf("%w: length MSB set", ErrProtocol)
		}
		if n <= 0xFFFF {
			return h, fmt.Errorf("%w: non-minimal length", ErrProtocol)
		}
	}
	if n > MaxMessageSize {
		return h, fmt.Errorf("%w: over %d bytes", ErrMessageTooLarge, MaxMessageSize)
	}
	h.length = int(n)
	return h, nil
}

// readPayload appends n payload bytes to buf, growing it in readChunk steps.
func (c *Conn) readPayload(ctx context.Context, buf []byte, n int) ([]byte, error) {
	for n > 0 {
		k := min(n, readChunk)
		buf = slices.Grow(buf, k)
		start := len(buf)
		buf = buf[:start+k]
		if _, err := io.ReadFull(c.br, buf[start:]); err != nil {
			return nil, ioError(ctx, ErrClosed, "read frame payload", err)
		}
		n -= k
	}
	return buf, nil
}

// handleControl consumes one control frame: a ping is answered with a pong
// carrying the same payload, a pong is dropped, a close is echoed and ends
// the connection with ErrClosed.
func (c *Conn) handleControl(ctx context.Context, h frameHeader) error {
	var buf [maxControlPayload]byte
	p := buf[:h.length]
	if _, err := io.ReadFull(c.br, p); err != nil {
		return ioError(ctx, ErrClosed, "read control frame", err)
	}
	switch h.opcode {
	case opPing:
		return c.writeFrame(ctx, opPong, p)
	case opClose:
		c.closed.Store(true)
		// Best effort: the connection ends whatever the peer does next.
		_ = c.writeFrame(ctx, opClose, closeNormal)
		return fmt.Errorf("%w: peer sent close", ErrClosed)
	default:
		return nil
	}
}

// WriteMessage sends p as one unfragmented, masked text frame. It is bounded
// by ctx. Nothing is sent when no mask can be drawn.
func (c *Conn) WriteMessage(ctx context.Context, p []byte) error {
	if c.closed.Load() {
		return ErrClosed
	}
	if len(p) > MaxMessageSize {
		return fmt.Errorf("%w: over %d bytes", ErrMessageTooLarge, MaxMessageSize)
	}
	return c.writeFrame(ctx, opText, p)
}

// writeFrame masks and writes one final frame with a fresh mask.
func (c *Conn) writeFrame(ctx context.Context, opcode byte, p []byte) error {
	var mask [4]byte
	if _, err := io.ReadFull(c.rand, mask[:]); err != nil {
		return fmt.Errorf("cdploopback: draw frame mask: %w", err)
	}
	n := len(p)
	out := make([]byte, 0, 14+n)
	out = append(out, 0x80|opcode)
	switch {
	case n <= maxControlPayload:
		out = append(out, 0x80|byte(n))
	case n <= 0xFFFF:
		out = append(out, 0x80|126)
		out = binary.BigEndian.AppendUint16(out, uint16(n))
	default:
		out = append(out, 0x80|127)
		out = binary.BigEndian.AppendUint64(out, uint64(n))
	}
	out = append(out, mask[:]...)
	for i, b := range p {
		out = append(out, b^mask[i%4])
	}

	c.wmu.Lock()
	defer c.wmu.Unlock()
	release := bindContext(ctx, c.nc.SetWriteDeadline)
	defer release()
	if _, err := c.nc.Write(out); err != nil {
		return ioError(ctx, ErrClosed, "write frame", err)
	}
	return nil
}

// Close closes the underlying connection. It is idempotent. No close frame is
// sent: the TCP close ends the DevTools session and cannot block.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		if err := c.nc.Close(); err != nil {
			c.closeErr = fmt.Errorf("cdploopback: close: %w", err)
		}
	})
	return c.closeErr
}
