//go:build unix

package browser

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

var _ Process = (*PipeProcess)(nil)

// StartPipeProcess is the production Starter: StartPipe.
func StartPipeProcess(ctx context.Context, cmd Command) (Process, error) {
	p, err := StartPipe(ctx, cmd)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// defaultStarter is the Starter used when PoolConfig.Start is nil.
var defaultStarter Starter = StartPipeProcess

// pidAlive is the default stale-profile probe: signal 0. EPERM means the
// pid runs under another user: alive.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return true
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// checkRuntimeDir requires XDG_RUNTIME_DIR to be a real directory (Lstat:
// a symlink is refused, never followed) without any group or world bit,
// owned by h.Geteuid(). Anything else, or a failed lookup, is
// ErrUnsafeProfileDir: the pool never falls back to <StateDir>/tmp then.
func checkRuntimeDir(h Host, dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%w: XDG_RUNTIME_DIR: %w", ErrUnsafeProfileDir, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%w: XDG_RUNTIME_DIR is not a real directory", ErrUnsafeProfileDir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: XDG_RUNTIME_DIR has mode %#o, want 0700", ErrUnsafeProfileDir, fi.Mode().Perm())
	}
	return checkOwnedByEuid(h, dir, "XDG_RUNTIME_DIR")
}

// checkBaseOwner requires the pool base (already vetted as a real private
// directory) to be owned by h.Geteuid() exactly.
func checkBaseOwner(h Host, base string) error {
	return checkOwnedByEuid(h, base, "pool base")
}

// checkOwnedByEuid compares the owner of path with h.Geteuid(); root is
// foreign too. An unknown euid or a failed lookup fails closed.
func checkOwnedByEuid(h Host, path, what string) error {
	if h.Geteuid == nil {
		return fmt.Errorf("%w: effective uid unknown", ErrUnsafeProfileDir)
	}
	euid := h.Geteuid()
	uid, err := h.owner()(path)
	if err != nil {
		return fmt.Errorf("%w: owner of the %s: %w", ErrUnsafeProfileDir, what, err)
	}
	if uid != euid {
		return fmt.Errorf("%w: the %s is owned by uid %d, not the current user", ErrUnsafeProfileDir, what, uid)
	}
	return nil
}
