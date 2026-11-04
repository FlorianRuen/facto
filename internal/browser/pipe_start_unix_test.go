//go:build unix

package browser_test

import (
	"context"
	"errors"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

func TestStartPipe_Refusals(t *testing.T) {
	t.Parallel()
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	missing := filepath.Join(t.TempDir(), "no-such-chrome")
	tests := []struct {
		name    string
		ctx     context.Context
		cmd     browser.Command
		wantErr error
	}{
		{name: "no path", ctx: t.Context(), cmd: browser.Command{}, wantErr: browser.ErrLaunchFailed},
		{name: "missing executable", ctx: t.Context(), cmd: browser.Command{Path: missing}, wantErr: browser.ErrLaunchFailed},
		{name: "cancelled context", ctx: cancelled, cmd: browser.Command{Path: missing}, wantErr: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := browser.StartPipe(tt.ctx, tt.cmd)
			if !errors.Is(err, tt.wantErr) || p != nil {
				t.Errorf("StartPipe = %v, %v; want nil, %v", p, err, tt.wantErr)
			}
		})
	}
}

func TestPipeStarter_SecondStartRefused(t *testing.T) {
	t.Parallel()
	var s browser.PipeStarter
	cmd, err := selfCommand(modeCDP, nil) // nil Stderr: discarded
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(t.Context(), cmd); err != nil {
		t.Fatalf("Start: %v", err)
	}
	p := s.Process()
	pid := p.Pid()
	t.Cleanup(func() { _ = p.Close(); _ = syscall.Kill(-pid, syscall.SIGKILL) })
	if err := s.Start(t.Context(), cmd); !errors.Is(err, browser.ErrLaunchFailed) {
		t.Errorf("second Start = %v, want ErrLaunchFailed", err)
	}
	if s.Process() != p {
		t.Error("second Start replaced the process")
	}
}
