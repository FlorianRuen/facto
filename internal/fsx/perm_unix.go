//go:build !windows

package fsx

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// nonBlock makes AppendPrivate fail (ENXIO) instead of hanging forever when a
// FIFO without a reader was planted at the target name. It has no effect on
// regular files.
const nonBlock = syscall.O_NONBLOCK

// insecure reports whether mode grants any group or world permission.
func insecure(mode fs.FileMode) bool { return mode.Perm()&0o077 != 0 }

// syncDir fsyncs dir so that a completed rename survives a crash.
func syncDir(root *os.Root, dir string) (err error) {
	d, err := root.Open(dir)
	if err != nil {
		return fmt.Errorf("fsx sync dir: %w", err)
	}
	defer func() {
		if cerr := d.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("fsx sync dir: close: %w", cerr)
		}
	}()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsx sync dir: %w", err)
	}
	return nil
}
