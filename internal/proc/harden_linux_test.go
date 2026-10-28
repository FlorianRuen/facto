//go:build linux

package proc_test

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/FlorianRuen/facto/internal/proc"
)

const (
	// childEnv switches the test binary into "hardened child" mode.
	childEnv = "FACTO_PROC_HARDEN_CHILD"
	// childOK is logged by the child once every probe succeeded. The parent
	// requires it so that a child that ran zero tests cannot look green.
	childOK = "FACTO_PROC_HARDEN_CHILD_OK"

	prGetDumpable = 3 // PR_GET_DUMPABLE from <linux/prctl.h>
)

func getDumpable(t *testing.T) uintptr {
	t.Helper()
	r, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0)
	if errno != 0 {
		t.Fatalf("prctl(PR_GET_DUMPABLE): %v", errno)
	}
	return r
}

func getCoreLimit(t *testing.T) syscall.Rlimit {
	t.Helper()
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim); err != nil {
		t.Fatalf("Getrlimit(RLIMIT_CORE): %v", err)
	}
	return lim
}

// TestHarden_DisablesCoreDumps runs Harden in a re-executed child so the
// irreversible process-wide changes never touch the parent test process.
func TestHarden_DisablesCoreDumps(t *testing.T) {
	if os.Getenv(childEnv) == "1" {
		hardenedChild(t)
		return
	}

	before := getDumpable(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// /proc/self/exe is the running test binary; a constant argv keeps gosec
	// G204 quiet without a #nosec.
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestHarden_DisablesCoreDumps$", "-test.v", "-test.count=1")
	// Under -cover, the child writes its counters to the same directory so
	// the real Harden path counts towards the package coverage.
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
		cmd.Args = append(cmd.Args, "-test.gocoverdir="+f.Value.String())
	}
	cmd.Env = append(os.Environ(), childEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("hardened child failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), childOK) {
		t.Fatalf("hardened child did not report success (marker %q missing):\n%s", childOK, out)
	}

	if after := getDumpable(t); after != before {
		t.Errorf("parent dumpable changed from %d to %d: Harden leaked out of the child", before, after)
	}
}

func hardenedChild(t *testing.T) {
	// Make the probes meaningful: raise the soft core limit to the hard limit
	// so Harden has something to lower. Dumpable is normally 1 for a
	// non-setuid test binary.
	lim := getCoreLimit(t)
	if lim.Max > 0 {
		raised := syscall.Rlimit{Cur: lim.Max, Max: lim.Max}
		if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &raised); err != nil {
			t.Fatalf("pre-raise RLIMIT_CORE: %v", err)
		}
	}
	if got := getDumpable(t); got == 0 {
		t.Fatalf("precondition: process already non-dumpable, test would prove nothing")
	}

	for i := range 2 { // second call proves idempotence
		if err := proc.Harden(); err != nil {
			t.Fatalf("Harden() call %d: %v", i+1, err)
		}
	}

	if lim.Max == 0 {
		t.Log("note: hard RLIMIT_CORE was already 0 in this environment; rlimit probes are weak here")
	}

	tests := []struct {
		name string
		get  func(t *testing.T) uint64
		want uint64
	}{
		{"rlimit core soft is zero", func(t *testing.T) uint64 { return getCoreLimit(t).Cur }, 0},
		{"rlimit core hard is zero", func(t *testing.T) uint64 { return getCoreLimit(t).Max }, 0},
		{"process is not dumpable", func(t *testing.T) uint64 { return uint64(getDumpable(t)) }, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.get(t); got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}

	// Negative: raising the core limit again must be refused (hard limit 0,
	// unprivileged). Not asserted as root, where the kernel allows raising
	// the hard limit.
	if os.Geteuid() != 0 {
		up := syscall.Rlimit{Cur: 1 << 20, Max: 1 << 20}
		if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &up); err == nil {
			t.Errorf("Setrlimit(RLIMIT_CORE, 1MiB) succeeded after Harden: hard limit not locked to 0")
		}
	}

	if !t.Failed() {
		t.Log(childOK)
	}
}
