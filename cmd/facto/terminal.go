package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// terminal is the controlling-terminal seam: the isTerminal check plus a
// no-echo line read.
type terminal interface {
	// IsTerminal reports whether r is an interactive terminal (isTerminal
	// in production).
	IsTerminal(r io.Reader) bool
	// ReadNoEcho reads one line from r with terminal echo off and returns
	// it without its line terminator. The caller owns the bytes (wraps them
	// in a secret.Secret).
	ReadNoEcho(r io.Reader) ([]byte, error)
}

var (
	// errNotTerminal reports a no-echo read on something that is not a
	// terminal file.
	errNotTerminal = errors.New("not a terminal")
	// errAborted reports a no-echo read after abort.
	errAborted = errors.New("terminal input aborted")
	// errAnswerTooLong reports an answer over maxAnswerLen bytes: it is
	// refused rather than cut, so a truncated code is never submitted.
	errAnswerTooLong = errors.New("answer too long")
)

// osTerminal is the production terminal. While a no-echo read is in
// progress it remembers how to turn echo back on, so that a run canceled
// at the prompt (Ctrl-C, SIGTERM) does not leave the user's terminal
// without echo: see abort.
type osTerminal struct {
	mu      sync.Mutex
	restore func() // set while echo is off; nil otherwise
	aborted bool
}

var _ terminal = (*osTerminal)(nil)

// IsTerminal is isTerminal.
func (*osTerminal) IsTerminal(r io.Reader) bool { return isTerminal(r) }

// ReadNoEcho turns echo off on r (a terminal *os.File), reads one line of
// at most maxAnswerLen bytes (the rest of a longer line is discarded) and
// turns echo back on. The line terminator ("\n", and a "\r" before it) is
// not returned.
func (t *osTerminal) ReadNoEcho(r io.Reader) ([]byte, error) {
	f, ok := r.(*os.File)
	if !ok || !isTerminal(r) {
		return nil, errNotTerminal
	}
	// Echo goes off under the lock: abort either sees the restore function
	// or has already refused this read, never neither.
	t.mu.Lock()
	if t.aborted {
		t.mu.Unlock()
		return nil, errAborted
	}
	restore, err := echoOff(f)
	if err != nil {
		t.mu.Unlock()
		return nil, fmt.Errorf("turn terminal echo off: %w", err)
	}
	t.restore = restore
	t.mu.Unlock()
	defer t.restoreEcho()
	return readSecretLine(f)
}

// abort turns echo back on now if a no-echo read turned it off, and makes
// every later ReadNoEcho fail with errAborted. The prompter calls it when
// its ctx is done while a read is still blocked on the terminal.
func (t *osTerminal) abort() {
	t.mu.Lock()
	t.aborted = true
	t.mu.Unlock()
	t.restoreEcho()
}

// restoreEcho turns echo back on if a no-echo read turned it off and has
// not restored it yet. It is safe to call at any time, more than once.
func (t *osTerminal) restoreEcho() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.restore != nil {
		t.restore()
		t.restore = nil
	}
}

// readSecretLine reads r one byte at a time up to "\n" or the end of
// input, so nothing past the line is consumed. A trailing "\r" is removed.
// A line over maxAnswerLen bytes (terminator excluded) is read to its end,
// wiped and refused with errAnswerTooLong. The end of input before any
// byte is io.EOF.
func readSecretLine(r io.Reader) ([]byte, error) {
	// One spare byte for a "\r" before the "\n".
	buf := make([]byte, 0, maxAnswerLen+1)
	var one [1]byte
	n := 0
	tooLong := false
	for {
		k, err := r.Read(one[:])
		if k == 1 {
			n++
			if one[0] == '\n' {
				break
			}
			if len(buf) <= maxAnswerLen {
				buf = append(buf, one[0])
			} else {
				tooLong = true
			}
		}
		if errors.Is(err, io.EOF) {
			if n == 0 {
				return nil, io.EOF
			}
			break
		}
		if err != nil {
			clear(buf)
			return nil, fmt.Errorf("read answer: %w", err)
		}
	}
	one[0] = 0
	if l := len(buf); l > 0 && buf[l-1] == '\r' {
		buf[l-1] = 0
		buf = buf[:l-1]
	}
	if tooLong || len(buf) > maxAnswerLen {
		clear(buf)
		return nil, errAnswerTooLong
	}
	return buf, nil
}
