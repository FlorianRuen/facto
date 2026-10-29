package browser

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// MaxMessageBytes caps one CDP message, pipe and WebSocket alike (ADR 0008).
// The NUL delimiter is not counted.
const MaxMessageBytes = 16 << 20

// readChunk is the read buffer of a PipeTransport: a message over the cap is
// refused at most one chunk past MaxMessageBytes.
const readChunk = 64 << 10

// Transport sentinel errors, errors.Is targets. Their wrapped messages never
// quote a CDP message, a parameter, a session id or a CDP error text.
var (
	// ErrMessageTooLarge: an incoming message is over MaxMessageBytes. The
	// browser is killed.
	ErrMessageTooLarge = errors.New("browser: cdp message too large")
	// ErrBadFrame: an outgoing frame holds a raw NUL (nothing is written),
	// or an incoming frame is not a JSON message (the browser is killed).
	ErrBadFrame = errors.New("browser: bad cdp frame")
	// ErrBrowserGone: the browser exited, was killed, or the transport is
	// closed.
	ErrBrowserGone = errors.New("browser: browser gone")
	// ErrCDP: the browser answered with a CDP error object. Only its
	// numeric code is kept.
	ErrCDP = errors.New("browser: cdp error")
)

// Transport moves whole CDP messages. Send appends the delimiter, Recv
// strips it. Send may be called concurrently; Recv has a single consumer.
type Transport interface {
	Send(msg []byte) error
	Recv() ([]byte, error)
	Close() error
}

// PipeTransport is the --remote-debugging-pipe framing: JSON messages, each
// ended by one NUL byte.
type PipeTransport struct {
	r  io.Reader
	w  io.Writer
	br *bufio.Reader

	wmu sync.Mutex // one writer at a time: frames never interleave

	rmu  sync.Mutex
	rerr error // sticky Recv error

	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

// NewPipeTransport frames messages read from r (the browser's output) and
// written to w (the browser's input). Close closes r and w when they are
// io.Closers.
func NewPipeTransport(r io.Reader, w io.Writer) *PipeTransport {
	return &PipeTransport{r: r, w: w, br: bufio.NewReaderSize(r, readChunk)}
}

// Send writes msg and its NUL in a single write, under a mutex. A msg holding
// a raw NUL would end the frame early and let the rest be read as another
// command: it is refused with ErrBadFrame and nothing is written.
func (t *PipeTransport) Send(msg []byte) error {
	if bytes.IndexByte(msg, 0) >= 0 {
		return fmt.Errorf("%w: outgoing message holds a raw NUL", ErrBadFrame)
	}
	frame := make([]byte, len(msg)+1)
	copy(frame, msg)
	// The frame may hold a value exposed at the last call site: cleared once
	// written (best effort, like the client's request buffer).
	defer clear(frame)
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if t.closed.Load() {
		return fmt.Errorf("%w: transport closed", ErrBrowserGone)
	}
	if _, err := t.w.Write(frame); err != nil {
		return fmt.Errorf("%w: write: %w", ErrBrowserGone, err)
	}
	return nil
}

// Recv returns the next message without its NUL. The size cap is enforced
// while reading: a message over MaxMessageBytes is refused at most one read
// chunk past the cap, and every later Recv fails too. A message cut by the
// end of the stream is never returned.
func (t *PipeTransport) Recv() ([]byte, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()
	if t.rerr != nil {
		return nil, t.rerr
	}
	msg, err := t.readFrame()
	if err != nil {
		t.rerr = err
		return nil, err
	}
	return msg, nil
}

func (t *PipeTransport) readFrame() ([]byte, error) {
	var acc []byte
	for {
		chunk, err := t.br.ReadSlice(0)
		switch {
		case err == nil:
			chunk = chunk[:len(chunk)-1]
			if len(acc)+len(chunk) > MaxMessageBytes {
				return nil, tooLarge()
			}
			return appendCapped(acc, chunk), nil
		case errors.Is(err, bufio.ErrBufferFull):
			if len(acc)+len(chunk) > MaxMessageBytes {
				return nil, tooLarge()
			}
			acc = appendCapped(acc, chunk)
		case errors.Is(err, io.EOF) && len(acc)+len(chunk) == 0:
			return nil, fmt.Errorf("%w: %w", ErrBrowserGone, io.EOF)
		case errors.Is(err, io.EOF):
			return nil, fmt.Errorf("%w: message cut by end of stream", ErrBrowserGone)
		default:
			return nil, fmt.Errorf("%w: read: %w", ErrBrowserGone, err)
		}
	}
}

func tooLarge() error {
	return fmt.Errorf("%w: over %d bytes", ErrMessageTooLarge, MaxMessageBytes)
}

// Close makes later Sends fail with ErrBrowserGone and closes the reader and
// the writer when they are io.Closers, which unblocks a pending Recv or Send
// on an *os.File pipe. It is idempotent.
func (t *PipeTransport) Close() error {
	t.closeOnce.Do(func() {
		t.closed.Store(true)
		var errs []error
		if c, ok := t.w.(io.Closer); ok {
			errs = append(errs, c.Close())
		}
		if c, ok := t.r.(io.Closer); ok {
			errs = append(errs, c.Close())
		}
		if err := errors.Join(errs...); err != nil {
			t.closeErr = fmt.Errorf("close cdp pipe: %w", err)
		}
	})
	return t.closeErr
}

// appendCapped appends chunk to acc, growing the buffer itself so that its
// capacity never exceeds MaxMessageBytes (append alone may reserve ~25%
// more). Callers check len(acc)+len(chunk) <= MaxMessageBytes first.
func appendCapped(acc, chunk []byte) []byte {
	need := len(acc) + len(chunk)
	if need > cap(acc) {
		grown := make([]byte, len(acc), min(max(2*cap(acc), need, readChunk), MaxMessageBytes))
		copy(grown, acc)
		acc = grown
	}
	return append(acc, chunk...)
}
