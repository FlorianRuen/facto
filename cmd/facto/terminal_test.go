// Tests for the production terminal seam and the line reader shared by the
// no-echo and e2e prompts (J1 task T19). All input is synthetic.
package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestReadSecretLine(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("7", maxAnswerLen+40)
	tests := []struct {
		name    string
		in      string
		want    string
		rest    string // input left unread
		wantErr error
	}{
		{name: "one line", in: "123456\nnext\n", want: "123456", rest: "next\n"},
		{name: "crlf", in: "123456\r\n", want: "123456"},
		{name: "last line without newline", in: "123456", want: "123456"},
		{name: "empty line", in: "\nnext", want: "", rest: "next"},
		{name: "longest accepted line", in: long[:maxAnswerLen] + "\nnext", want: long[:maxAnswerLen], rest: "next"},
		{name: "longest accepted line with crlf", in: long[:maxAnswerLen] + "\r\nnext", want: long[:maxAnswerLen], rest: "next"},
		{name: "too long refused and drained", in: long + "\nnext", rest: "next", wantErr: errAnswerTooLong},
		{name: "too long without newline", in: long, wantErr: errAnswerTooLong},
		{name: "end of input", in: "", wantErr: io.EOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := strings.NewReader(tt.in)
			got, err := readSecretLine(r)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("readSecretLine error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil && got != nil {
				t.Errorf("readSecretLine returned %d bytes with an error, want none", len(got))
			}
			if string(got) != tt.want {
				t.Errorf("readSecretLine = %q, want %q", got, tt.want)
			}
			if rest, _ := io.ReadAll(r); string(rest) != tt.rest {
				t.Errorf("left unread %q, want %q", rest, tt.rest)
			}
		})
	}

	t.Run("read error", func(t *testing.T) {
		t.Parallel()
		errSynth := errors.New("synthetic read failure")
		got, err := readSecretLine(io.MultiReader(strings.NewReader("12"), iotest.ErrReader(errSynth)))
		if !errors.Is(err, errSynth) || got != nil {
			t.Fatalf("readSecretLine = %q, %v; want nil, the read error", got, err)
		}
	})
}

// TestOSTerminal_RefusesNonTerminal: the production terminal never reads
// from something that is not a terminal, and an aborted terminal never
// turns echo off again.
func TestOSTerminal_RefusesNonTerminal(t *testing.T) {
	t.Parallel()
	term := &osTerminal{}
	in := bytes.NewBufferString("123456\n")
	if term.IsTerminal(in) {
		t.Fatal("an in-memory reader is a terminal")
	}
	if _, err := term.ReadNoEcho(in); !errors.Is(err, errNotTerminal) {
		t.Fatalf("ReadNoEcho on a buffer: %v, want errNotTerminal", err)
	}
	if in.Len() != len("123456\n") {
		t.Errorf("ReadNoEcho read a non-terminal")
	}
	term.abort()
	term.abort() // idempotent
}
