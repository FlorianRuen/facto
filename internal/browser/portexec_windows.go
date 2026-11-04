//go:build windows

package browser

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// portExecWaitDelay bounds how long reaping waits for Chrome's stderr once
// the browser exited (a child may still hold the handle).
const portExecWaitDelay = 2 * time.Second

// portKillWait bounds the wait for the reap after a failed kill.
const portKillWait = 5 * time.Second

// winProcess is an ExecProcess over os/exec.
type winProcess struct {
	cmd  *exec.Cmd
	done chan struct{}

	killOnce sync.Once
	killErr  error
}

// startPortExec starts cmd.Path with cmd.Args and exactly cmd.Env (an empty
// Env gives an empty environment, never facto's), stdin and stdout on the
// null device, stderr copied to cmd.Stderr (discarded when nil). The
// process is reaped from its own goroutine; Done is closed then. ctx is not
// bound here: the port Starter kills the browser when it ends.
func startPortExec(_ context.Context, cmd Command) (ExecProcess, error) {
	if cmd.Path == "" {
		return nil, fmt.Errorf("%w: no browser path", ErrLaunchFailed)
	}
	stderr := cmd.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	c := &exec.Cmd{
		Path:      cmd.Path,
		Args:      append([]string{cmd.Path}, cmd.Args...),
		Env:       append([]string{}, cmd.Env...),
		Stderr:    stderr,
		WaitDelay: portExecWaitDelay,
	}
	if err := c.Start(); err != nil {
		return nil, fmt.Errorf("start browser: %w", err)
	}
	p := &winProcess{cmd: c, done: make(chan struct{})}
	go func() {
		_ = c.Wait() // the exit status says nothing facto acts on
		close(p.done)
	}()
	return p, nil
}

func (p *winProcess) Pid() int              { return p.cmd.Process.Pid }
func (p *winProcess) Done() <-chan struct{} { return p.done }

// Kill terminates the browser and waits until it is reaped. Idempotent.
// When TerminateProcess fails (anything but "already finished"), the wait
// for the reap is bounded by portKillWait and the error is returned: the
// caller then does not wait on Done.
func (p *winProcess) Kill() error {
	p.killOnce.Do(func() {
		err := p.cmd.Process.Kill()
		if err == nil || errors.Is(err, os.ErrProcessDone) {
			<-p.done
			return
		}
		wait := time.NewTimer(portKillWait)
		defer wait.Stop()
		select {
		case <-p.done:
		case <-wait.C:
			p.killErr = fmt.Errorf("kill browser: %w", err)
		}
	})
	return p.killErr
}

// TCP table constants (iphlpapi.h).
const (
	tcpTableOwnerPIDListener = 3 // TCP_TABLE_OWNER_PID_LISTENER
	// maxTCPTableBytes caps the table buffer the OS may ask for.
	maxTCPTableBytes = 16 << 20
	tcpTableAttempts = 4
)

var (
	modIPHlpAPI             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = modIPHlpAPI.NewProc("GetExtendedTcpTable")
)

// tableListenerPID returns the pid owning the only socket listening on
// port, from the IPv4 and IPv6 listener tables (LoopbackListenerPID: a
// wildcard or IPv6 listener on the port is refused).
func tableListenerPID(ctx context.Context, port int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("tcp table: %w", err)
	}
	b4, err := extendedTCPTable(windows.AF_INET)
	if err != nil {
		return 0, err
	}
	rows, err := parseTCPTableOwnerPID(b4)
	if err != nil {
		return 0, err
	}
	b6, err := extendedTCPTable(windows.AF_INET6)
	if err != nil {
		return 0, err
	}
	rows6, err := parseTCP6TableOwnerPID(b6)
	if err != nil {
		return 0, err
	}
	return LoopbackListenerPID(append(rows, rows6...), port)
}

// extendedTCPTable calls GetExtendedTcpTable(TCP_TABLE_OWNER_PID_LISTENER)
// for family, growing the buffer as the OS asks, within maxTCPTableBytes.
func extendedTCPTable(family uint32) ([]byte, error) {
	if err := procGetExtendedTCPTable.Find(); err != nil {
		return nil, fmt.Errorf("tcp table: %w", err)
	}
	size := uint32(4096)
	for range tcpTableAttempts {
		if size > maxTCPTableBytes {
			return nil, errors.New("tcp table: over the size cap")
		}
		buf := make([]byte, size)
		n := size
		// #nosec G103 -- the documented iphlpapi call needs the buffer address; bounds are the length passed with it. Windows port fallback, https://github.com/FlorianRuen/facto/issues/3
		r, _, _ := procGetExtendedTCPTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&n)),
			0, // unsorted
			uintptr(family),
			tcpTableOwnerPIDListener,
			0,
		)
		errno := windows.Errno(r)
		if errno == 0 {
			if n > size {
				return nil, errors.New("tcp table: size grew past the buffer")
			}
			return buf[:n], nil
		}
		if errno != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, fmt.Errorf("tcp table: %w", errno)
		}
		// Checked before the addition, so it can neither overflow nor ask
		// for more than the cap.
		if n > maxTCPTableBytes {
			return nil, errors.New("tcp table: over the size cap")
		}
		size = n + 4096 // the table may grow between two calls
	}
	return nil, errors.New("tcp table: kept growing")
}
