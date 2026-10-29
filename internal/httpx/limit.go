package httpx

import (
	"errors"
	"fmt"
	"io"
)

// LimitBody returns a ReadCloser yielding at most limit bytes of rc. If rc
// holds more, the read that would exceed limit returns ErrBodyTooLarge, and
// so does every later read: a body is never silently truncated (a cut PDF
// must not be stored). A negative limit counts as 0. Close closes rc.
func LimitBody(rc io.ReadCloser, limit int64) io.ReadCloser {
	limit = max(limit, 0)
	return &limitedBody{rc: rc, left: limit, limit: limit}
}

type limitedBody struct {
	rc    io.ReadCloser
	left  int64 // bytes still allowed
	limit int64
	err   error // sticky ErrBodyTooLarge
}

func (l *limitedBody) Read(p []byte) (int, error) {
	if l.err != nil {
		return 0, l.err
	}
	// Ask for one byte more than allowed to detect an overflow.
	if int64(len(p)) > l.left+1 {
		p = p[:l.left+1]
	}
	n, err := l.rc.Read(p)
	if int64(n) > l.left {
		n = int(l.left)
		l.left = 0
		l.err = fmt.Errorf("%w: limit %d bytes", ErrBodyTooLarge, l.limit)
		return n, l.err
	}
	l.left -= int64(n)
	switch {
	case err == nil:
		return n, nil
	case errors.Is(err, io.EOF):
		return n, io.EOF // must stay unwrapped: callers compare with ==
	default:
		return n, fmt.Errorf("httpx: read body: %w", err)
	}
}

func (l *limitedBody) Close() error {
	if err := l.rc.Close(); err != nil {
		return fmt.Errorf("httpx: close body: %w", err)
	}
	return nil
}
