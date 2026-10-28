//go:build unix

// Extra hardening tests for package fsx (J0 task T2), beyond the T2 contract.
package fsx_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A FIFO planted at the target name must not make AppendPrivate block forever.
func TestAppendPrivate_RefusesFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	if err := syscall.Mkfifo(filepath.Join(dir, "run.log"), 0o600); err != nil {
		t.Fatalf("setup Mkfifo: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- r.AppendPrivate("run.log", []byte("x")) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("AppendPrivate on a FIFO: err = nil, want an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AppendPrivate on a FIFO blocked")
	}
}

// cancelingReader cancels its context after the first chunk.
type cancelingReader struct {
	cancel context.CancelFunc
	reads  int
}

func (c *cancelingReader) Read(p []byte) (int, error) {
	c.reads++
	if c.reads == 1 {
		c.cancel()
	}
	return copy(p, strings.Repeat("y", len(p))), nil
}

// Cancellation in the middle of a stream stops the copy and leaves nothing.
func TestWriteAtomicFrom_CanceledMidStream(t *testing.T) {
	t.Parallel()

	r, dir := openRoot(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := r.WriteAtomicFrom(ctx, "t.pdf", &cancelingReader{cancel: cancel})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if got := entries(t, dir); !slices.Equal(got, []string{}) {
		t.Fatalf("entries = %v, want none", got)
	}
}
