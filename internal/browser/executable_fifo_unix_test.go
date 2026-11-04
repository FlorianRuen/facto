//go:build unix

package browser_test

import (
	"path/filepath"
	"syscall"
	"testing"
)

// fifo creates a named pipe with exec bits: not a regular file.
func fifo(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "chrome")
	if err := syscall.Mkfifo(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}
