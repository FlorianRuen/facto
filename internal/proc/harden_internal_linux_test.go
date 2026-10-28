//go:build linux

package proc

import (
	"errors"
	"syscall"
	"testing"
)

// TestHarden_Steps checks the order, the arguments and the error wrapping
// with fake system calls; TestHarden_DisablesCoreDumps checks the real effect
// in a child process.
func TestHarden_Steps(t *testing.T) {
	t.Parallel()
	errLimit := errors.New("setrlimit failed")
	errDump := errors.New("prctl failed")
	tests := []struct {
		name       string
		limitErr   error
		dumpErr    error
		wantErr    error
		wantUndump bool
	}{
		{name: "both succeed", wantUndump: true},
		{name: "setrlimit fails", limitErr: errLimit, wantErr: errLimit},
		{name: "prctl fails", dumpErr: errDump, wantErr: errDump, wantUndump: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var gotRes int
			var gotLim *syscall.Rlimit
			undumped := false
			err := harden(
				func(res int, lim *syscall.Rlimit) error {
					gotRes, gotLim = res, lim
					return tt.limitErr
				},
				func() error {
					undumped = true
					return tt.dumpErr
				},
			)
			if !errors.Is(err, tt.wantErr) || (tt.wantErr == nil && err != nil) {
				t.Fatalf("harden() = %v, want %v", err, tt.wantErr)
			}
			if gotRes != syscall.RLIMIT_CORE || gotLim == nil || gotLim.Cur != 0 || gotLim.Max != 0 {
				t.Errorf("setrlimit(%d, %+v), want RLIMIT_CORE with soft and hard 0", gotRes, gotLim)
			}
			if undumped != tt.wantUndump {
				t.Errorf("dumpable cleared = %v, want %v", undumped, tt.wantUndump)
			}
		})
	}
}
