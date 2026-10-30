//go:build unix

package browser

import (
	"context"
	"errors"
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
