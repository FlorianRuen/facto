// Red-team attack test for process hardening (J0 task T30). The previous
// tests check the flags Harden sets; this one plays the other local program
// of the threat model: a process of the same user that tries to read a
// hardened facto's environment and memory through /proc, or to attach with
// ptrace. A test passes when the attack is defeated. Everything is
// synthetic.
package proc_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/proc"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

const (
	// atkChildEnv switches the test binary into "hardened target" mode;
	// atkValueEnv carries a canary the target holds in its environment and
	// in memory.
	atkChildEnv = "FACTO_ATK_PROC_TARGET"
	atkValueEnv = "FACTO_ATK_PROC_VALUE"
	atkReady    = "FACTO_ATK_PROC_READY"
)

// atkHeld keeps the canary reachable in the target's heap.
var atkHeld []byte

// TestAttack_HardenedProcessUnreadableBySameUser starts a hardened target
// holding a canary, then from the parent (same user, and its ptrace parent,
// which Yama scope 1 would otherwise allow) reads /proc/<pid>/environ,
// /proc/<pid>/mem and /proc/<pid>/maps, and tries PTRACE_ATTACH. Every
// attempt must fail; the canary must never be read. Assertions need a
// non-root parent: root holds CAP_SYS_PTRACE, out of the threat model.
func TestAttack_HardenedProcessUnreadableBySameUser(t *testing.T) {
	if os.Getenv(atkChildEnv) == "1" {
		atkTarget(t)
		return
	}
	canary := testsecrets.Canary(t, testsecrets.Session)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestAttack_HardenedProcessUnreadableBySameUser$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), atkChildEnv+"=1", atkValueEnv+"="+canary, "FACTO_CANARY=0")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start target: %v", err)
	}
	pid := cmd.Process.Pid
	var transcript bytes.Buffer
	sc := bufio.NewScanner(io.TeeReader(stdout, &transcript))
	ready := false
	for sc.Scan() {
		if strings.Contains(sc.Text(), atkReady) {
			ready = true
			break
		}
	}
	if !ready {
		_ = stdin.Close()
		_ = cmd.Wait()
		t.Fatalf("target never became ready:\n%s", transcript.String())
	}

	procDir, err := os.OpenRoot(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		t.Fatalf("open /proc/<pid>: %v", err)
	}
	defer func() { _ = procDir.Close() }()
	var leaks []string
	for _, f := range []string{"environ", "mem", "maps", "auxv", "stack"} {
		var data []byte
		var rerr error
		if f == "mem" {
			// Opening is the access check; reading needs offsets.
			var fh *os.File
			fh, rerr = procDir.Open(f)
			if rerr == nil {
				_ = fh.Close()
				data = []byte("opened")
			}
		} else {
			data, rerr = procDir.ReadFile(f)
		}
		if os.Geteuid() == 0 {
			t.Logf("running as root: %s readable=%v (not asserted)", f, rerr == nil)
			continue
		}
		if rerr == nil && len(data) > 0 {
			leaks = append(leaks, f)
		}
		if bytes.Contains(data, []byte(canary)) {
			t.Errorf("/proc/<pid>/%s exposes the canary", f)
		}
	}

	attachErr := atkPtraceAttach(pid)
	if os.Geteuid() != 0 && attachErr == nil {
		t.Error("PTRACE_ATTACH to the hardened process succeeded")
	}

	_ = stdin.Close()
	rest, _ := io.ReadAll(stdout)
	transcript.Write(rest)
	if err := cmd.Wait(); err != nil {
		t.Errorf("target failed: %v\n%s", err, transcript.String())
	}
	if len(leaks) > 0 {
		t.Errorf("same-user process read the hardened target's %q", leaks)
	}
	if strings.Contains(transcript.String(), canary) {
		t.Error("target printed the canary")
	}
}

// atkPtraceAttach tries to attach to pid from a locked OS thread and
// detaches if the attach succeeded.
func atkPtraceAttach(pid int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := syscall.PtraceAttach(pid); err != nil {
		return err
	}
	var ws syscall.WaitStatus
	_, _ = syscall.Wait4(pid, &ws, syscall.WALL, nil)
	_ = syscall.PtraceDetach(pid)
	return nil
}

// atkTarget hardens itself, keeps the canary in memory (it is also in its
// initial environment, /proc/<pid>/environ), reports ready and waits for
// stdin to close.
func atkTarget(t *testing.T) {
	atkHeld = []byte(os.Getenv(atkValueEnv))
	if len(atkHeld) == 0 {
		t.Fatal("target: no secret")
	}
	if err := proc.Harden(); err != nil {
		t.Fatalf("target: Harden: %v", err)
	}
	t.Log(atkReady) // streamed to stdout at once under -test.v
	_, err := io.Copy(io.Discard, os.Stdin)
	if err != nil && !errors.Is(err, os.ErrClosed) {
		t.Fatalf("target: stdin: %v", err)
	}
	runtime.KeepAlive(atkHeld)
}
