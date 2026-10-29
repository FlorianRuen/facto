//go:build unix

package browser

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// stderrDrain bounds how long teardown waits for Chrome's stderr to reach
// EOF once the process group is killed (a process that left the group may
// still hold it).
const stderrDrain = 2 * time.Second

// PipeProcess is a browser started by StartPipe, driven over fds 3/4.
type PipeProcess struct {
	client *Client
	pid    int
	done   chan struct{}

	mu     sync.Mutex
	reaped bool

	closeOnce sync.Once
}

// StartPipe starts cmd.Path with cmd.Args and exactly cmd.Env (an empty Env
// gives an empty environment, never facto's), stdin and stdout on
// /dev/null, stderr copied to cmd.Stderr (discarded when nil), and the CDP
// pipe as fds 3 (browser reads) and 4 (browser writes).
//
// cmd.Stderr must never block (Launch's capWriter does not): a blocked
// writer stalls the copy, Chrome then blocks on a full stderr pipe, and
// teardown waits up to stderrDrain for it.
//
// ctx bounds the browser's whole lifetime, not only the start: when it
// ends, the browser's process group is killed. Pass the context of the
// login, not a start timeout.
//
// Teardown: the browser leads its own process group (Setpgid), and
// cancelling ctx, Close, an oversized or non-JSON message, or a failed
// write SIGKILL the whole group. When the browser exits by itself, the
// leftovers of its group are killed too. Exit is noticed from the process
// (wait), not from the pipe, which a grandchild may still hold. On Linux
// Pdeathsig=SIGKILL is a backstop for a SIGKILLed facto; see
// sysProcAttr and startCmd.
func StartPipe(ctx context.Context, cmd Command) (*PipeProcess, error) {
	if cmd.Path == "" {
		return nil, fmt.Errorf("%w: no browser path", ErrLaunchFailed)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("start browser: %w", err)
	}
	f, err := openPipes()
	if err != nil {
		return nil, err
	}
	c := &exec.Cmd{
		Path:        cmd.Path,
		Args:        append([]string{cmd.Path}, cmd.Args...),
		Env:         append([]string{}, cmd.Env...),
		Stderr:      f.errW,
		ExtraFiles:  []*os.File{f.childR, f.childW},
		SysProcAttr: sysProcAttr(),
	}
	done := make(chan struct{})
	if err := startCmd(c, done); err != nil {
		f.closeAll()
		return nil, fmt.Errorf("%w: start: %w", ErrLaunchFailed, err)
	}
	// The child holds its own copies now: without closing ours, EOF
	// would never come.
	f.closeChildEnds()

	p := &PipeProcess{pid: c.Process.Pid, done: done}
	p.client = newClient(NewPipeTransport(f.parentR, f.parentW), p.kill)

	copied := make(chan struct{})
	go func() {
		defer close(copied)
		dst := cmd.Stderr
		if dst == nil {
			dst = io.Discard
		}
		_, _ = io.Copy(dst, f.errR)
	}()
	go p.wait(c, f.errR, copied)
	go func() {
		select {
		case <-ctx.Done():
			p.kill()
		case <-p.done:
		}
	}()
	return p, nil
}

// startCmd forks from a goroutine locked to its OS thread, which stays
// parked, locked, until done is closed (the browser is reaped): one thread
// per running browser. Pdeathsig fires when the thread that forked exits,
// not the process, and the Go runtime may end an idle thread; parking a
// locked thread keeps the forking thread alive exactly as long as the
// browser, so Pdeathsig fires only when facto itself dies.
func startCmd(c *exec.Cmd, done <-chan struct{}) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := c.Start()
		errc <- err
		if err == nil {
			<-done
		}
	}()
	return <-errc
}

// wait reaps the browser, kills what is left of its group, fails the client
// and lets stderr drain (bounded) before closing Done.
//
// Where awaitExit can wait without reaping (Linux, waitid WNOWAIT), the
// leftovers are killed while the browser is still a zombie: its pid, the
// group id, cannot be reused, so the kill never reaches another group.
// Elsewhere (macOS) the leftovers are killed just after the reap; the group
// id is still reserved while a member lives, so the residual risk is only a
// new group taking that id in the microseconds after the group emptied, and
// then a SIGKILL to it.
func (p *PipeProcess) wait(c *exec.Cmd, errR *os.File, copied <-chan struct{}) {
	exited := awaitExit(p.pid)
	if exited {
		p.cleanGroup()
	}
	_ = c.Wait() // the exit status says nothing facto acts on
	if !exited {
		p.cleanGroup()
	}
	p.client.fail(fmt.Errorf("%w: browser exited", ErrBrowserGone))

	t := time.NewTimer(stderrDrain)
	select {
	case <-copied:
	case <-t.C:
	}
	t.Stop()
	_ = errR.Close()
	<-copied
	close(p.done)
}

// cleanGroup kills the leftovers of the browser's group once the browser
// has exited, and marks it reaped so kill stops signalling the group.
func (p *PipeProcess) cleanGroup() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reaped = true
	_ = syscall.Kill(-p.pid, syscall.SIGKILL) // ESRCH once the group is empty
}

// kill SIGKILLs the browser's process group, unless the browser has
// exited (wait then did it).
func (p *PipeProcess) kill() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.reaped {
		_ = syscall.Kill(-p.pid, syscall.SIGKILL)
	}
}

// Client returns the CDP client bound to the browser.
func (p *PipeProcess) Client() *Client { return p.client }

// Pid returns the browser's pid, which is also its process group id.
func (p *PipeProcess) Pid() int { return p.pid }

// Done is closed once the browser has exited and been reaped.
func (p *PipeProcess) Done() <-chan struct{} { return p.done }

// Close kills the browser's process group, fails pending calls with
// ErrBrowserGone and waits until the browser is reaped. It is idempotent
// and returns nil after a kill.
func (p *PipeProcess) Close() error {
	p.closeOnce.Do(func() {
		p.kill()
		_ = p.client.Close()
	})
	<-p.done
	return nil
}

// PipeStarter adapts StartPipe to the StartFunc used by Launch.
type PipeStarter struct {
	mu sync.Mutex
	p  *PipeProcess
}

// Start is a StartFunc: it starts the browser with StartPipe and keeps the
// process for Process. A second Start is refused.
func (s *PipeStarter) Start(ctx context.Context, cmd Command) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.p != nil {
		return fmt.Errorf("%w: browser already started", ErrLaunchFailed)
	}
	p, err := StartPipe(ctx, cmd)
	if err != nil {
		return err
	}
	s.p = p
	return nil
}

// Process returns the started browser, nil before a successful Start.
func (s *PipeStarter) Process() *PipeProcess {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.p
}

// pipeFiles are the three pipes of a browser: CDP in (parent writes, child
// reads on fd 3), CDP out (child writes on fd 4, parent reads) and stderr.
type pipeFiles struct {
	childR, parentW *os.File
	parentR, childW *os.File
	errR, errW      *os.File
}

func openPipes() (*pipeFiles, error) {
	var f pipeFiles
	var err error
	if f.childR, f.parentW, err = os.Pipe(); err != nil {
		return nil, fmt.Errorf("%w: cdp pipe: %w", ErrLaunchFailed, err)
	}
	if f.parentR, f.childW, err = os.Pipe(); err != nil {
		f.closeAll()
		return nil, fmt.Errorf("%w: cdp pipe: %w", ErrLaunchFailed, err)
	}
	if f.errR, f.errW, err = os.Pipe(); err != nil {
		f.closeAll()
		return nil, fmt.Errorf("%w: stderr pipe: %w", ErrLaunchFailed, err)
	}
	return &f, nil
}

func (f *pipeFiles) closeChildEnds() {
	closeFiles(f.childR, f.childW, f.errW)
}

func (f *pipeFiles) closeAll() {
	closeFiles(f.childR, f.parentW, f.parentR, f.childW, f.errR, f.errW)
}

func closeFiles(files ...*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}
