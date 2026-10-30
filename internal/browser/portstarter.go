package browser

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// portConnectTimeout bounds the wait for the port file, the listener check,
// the dial and the handshake after the browser started. The browser's
// lifetime itself is the Starter's ctx.
const portConnectTimeout = 30 * time.Second

// ExecProcess is a started OS process (windows: os/exec).
type ExecProcess interface {
	Pid() int
	Done() <-chan struct{} // closed once the process exited and was reaped
	Kill() error           // kill and reap; idempotent
}

// PortStarterConfig configures NewPortStarter.
type PortStarterConfig struct {
	// Exec starts cmd.Path with cmd.Args and cmd.Env unchanged, stderr to
	// cmd.Stderr (windows: startPortExec).
	Exec func(ctx context.Context, cmd Command) (ExecProcess, error)
	// ListenerPID returns the pid owning the CDP port, as in
	// PortConnectConfig.
	ListenerPID func(ctx context.Context, port int) (int, error)
	// Dial opens the WebSocket. Nil: DialLoopback.
	Dial func(ctx context.Context, t DevToolsTarget) (WSConn, error)
	// PortFile holds the port file seams.
	PortFile PortFileConfig
}

// NewPortStarter returns the windows Starter (ADR 0008 "Windows (A4)"):
// defaultStarter on windows, with the windows Exec and ListenerPID. Each
// start:
//  1. requires argv to hold exactly one --remote-debugging-port, valued "0",
//     no --remote-debugging-pipe nor --remote-debugging-io-pipes
//     (ErrForbiddenFlag), exactly one --user-data-dir (ErrNoProfileDir when
//     missing), and to pass CheckFlags for windows;
//  2. ArmPortFile on that profile (empty, no port file yet);
//  3. Exec with the argv unchanged (nothing added, nothing removed);
//  4. ConnectPort with BrowserPID = the exec'd pid, bounded by
//     portConnectTimeout and by the process' exit;
//  5. NewClient over the handshaken transport.
//
// Any failure after Exec kills and reaps the process before returning a nil
// Process. A failed Exec returns an error wrapping ErrLaunchFailed. ctx is
// the browser's lifetime: when it ends, the browser is killed. The
// Process' Close closes the client (and so the WebSocket), then kills and
// reaps the browser; Done follows the process.
func NewPortStarter(cfg PortStarterConfig) Starter {
	return func(ctx context.Context, cmd Command) (Process, error) {
		return startPort(ctx, cfg, cmd)
	}
}

func startPort(ctx context.Context, cfg PortStarterConfig, cmd Command) (Process, error) {
	profile, err := portArgvProfile(cmd.Args, cmd.checkArgs)
	if err != nil {
		return nil, err
	}
	pf, err := ArmPortFile(profile, cfg.PortFile)
	if err != nil {
		return nil, err
	}
	if cfg.Exec == nil {
		return nil, fmt.Errorf("%w: no process starter", ErrLaunchFailed)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("start browser: %w", err)
	}
	ep, err := cfg.Exec(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("%w: start: %w", ErrLaunchFailed, err)
	}
	if ep == nil {
		return nil, fmt.Errorf("%w: start returned no process", ErrLaunchFailed)
	}
	tr, err := connectStarted(ctx, cfg, pf, ep)
	if err != nil {
		return nil, errors.Join(err, killQuiet(ep))
	}
	p := &PortProcess{ep: ep}
	p.client = newClient(tr, p.kill)
	// ctx bounds the browser's whole lifetime; the client dies with the
	// process.
	go func() {
		select {
		case <-ctx.Done():
			p.kill()
		case <-ep.Done():
		}
		_ = p.client.Close() // the browser is gone: only fails pending calls
	}()
	return p, nil
}

// connectStarted runs ConnectPort for the started process, giving up when
// the process exits or portConnectTimeout elapses.
func connectStarted(ctx context.Context, cfg PortStarterConfig, pf *PortFile, ep ExecProcess) (*PortTransport, error) {
	cctx, cancel := context.WithTimeout(ctx, portConnectTimeout)
	defer cancel()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ep.Done():
			cancel()
		case <-stop:
		}
	}()
	tr, err := ConnectPort(cctx, PortConnectConfig{
		PortFile:    pf,
		BrowserPID:  ep.Pid(),
		ListenerPID: cfg.ListenerPID,
		Dial:        cfg.Dial,
	})
	if err != nil {
		return nil, err
	}
	return tr, nil
}

// killQuiet kills and reaps ep. A kill error is reported only when the
// process is still not done afterwards.
func killQuiet(ep ExecProcess) error {
	err := ep.Kill()
	select {
	case <-ep.Done():
		return nil
	default:
	}
	if err != nil {
		return fmt.Errorf("kill browser: %w", err)
	}
	return nil
}

// portArgvProfile vets the transport switches of a windows argv and returns
// the --user-data-dir value. check vets the whole argv; nil is the release
// CheckFlags (only the e2e build's argvPolicy sets one, Command.checkArgs).
func portArgvProfile(args []string, check func([]string) error) (string, error) {
	ports, profiles := 0, 0
	profile := ""
	for _, a := range args {
		name, value, hasValue, ok := parseSwitch(goosWindows, a)
		if !ok {
			continue // CheckFlags below refuses it
		}
		switch name {
		case "remote-debugging-port":
			ports++
			if !hasValue || value != "0" {
				return "", fmt.Errorf("%w: --remote-debugging-port must be 0", ErrForbiddenFlag)
			}
		case "remote-debugging-pipe", "remote-debugging-io-pipes":
			return "", fmt.Errorf("%w: --%s with the port transport", ErrForbiddenFlag, name)
		case "user-data-dir":
			profiles++
			profile = value
		}
	}
	if ports != 1 {
		return "", fmt.Errorf("%w: want exactly one --remote-debugging-port=0, got %d", ErrForbiddenFlag, ports)
	}
	switch {
	case profiles == 0 || (profiles == 1 && profile == ""):
		return "", fmt.Errorf("%w: no --user-data-dir", ErrNoProfileDir)
	case profiles > 1:
		return "", fmt.Errorf("%w: --user-data-dir given twice", ErrForbiddenFlag)
	}
	if check == nil {
		check = func(a []string) error { return CheckFlags(goosWindows, a) }
	}
	if err := check(args); err != nil {
		return "", err
	}
	return profile, nil
}

// PortProcess is a browser started by a port Starter, driven over the
// loopback WebSocket.
type PortProcess struct {
	ep     ExecProcess
	client *Client

	closeOnce sync.Once
	closeErr  error
}

var _ Process = (*PortProcess)(nil)

// Client returns the CDP client, usable once the handshake succeeded (it
// has, when the Starter returned).
func (p *PortProcess) Client() *Client { return p.client }

// Pid returns the browser's pid.
func (p *PortProcess) Pid() int { return p.ep.Pid() }

// Done is closed once the browser exited and was reaped.
func (p *PortProcess) Done() <-chan struct{} { return p.ep.Done() }

// kill kills and reaps the browser (client fatal hook and ctx end).
func (p *PortProcess) kill() { _ = p.ep.Kill() }

// Close closes the client (and so the WebSocket), then kills and reaps the
// browser. Idempotent. It returns nil once the browser is reaped; when the
// kill fails (ExecProcess.Kill bounds its own wait) that error is returned
// and Done is not waited for.
func (p *PortProcess) Close() error {
	p.closeOnce.Do(func() {
		_ = p.client.Close() // closes the WebSocket; the browser is killed next
		if err := p.ep.Kill(); err != nil {
			p.closeErr = fmt.Errorf("close browser: %w", err)
			return
		}
		<-p.ep.Done()
	})
	return p.closeErr
}
