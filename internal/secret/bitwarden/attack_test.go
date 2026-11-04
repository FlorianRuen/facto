//go:build unix

// Red-team attack tests for the real ExecRunner (J0 task T30). The "CLI" is
// /bin/sh running a synthetic one-liner, or the test binary in its fake-CLI
// mode (TestMain in exec_test.go): the real Bitwarden CLI is never run.
// Attacks: an endless output, a grandchild keeping the output pipes open, a
// hostile parent environment (loader, shell, Node, proxy and Bitwarden API
// variables), and an executable planted in the working directory and
// reached through a relative PATH entry. Uses runHelper, envMap,
// newProvider, bwRef and writeArtifact from the other test files. A test
// passes when the attack is defeated.
package bitwarden_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/bitwarden"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// atkShell runs every command as `/bin/sh -c script` through the real
// ExecRunner, whatever subcommand the provider asked for.
type atkShell struct{ script string }

func (r atkShell) Run(ctx context.Context, cmd bitwarden.Command) error {
	cmd.Args = []string{"-c", r.script}
	return bitwarden.ExecRunner{Path: "/bin/sh"}.Run(ctx, cmd)
}

// atkWithin runs f and fails if it takes longer than d.
func atkWithin(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not finish within %v", what, d)
	}
}

// TestAttack_ExecRunnerFloodIsCutAndBounded makes the CLI print a canary
// without end, on stdout then on stderr, through the provider. Resolve must
// fail quickly (ErrOutputTooLarge for stdout) and neither the error nor the
// Close error may carry the flooded canary.
func TestAttack_ExecRunnerFloodIsCutAndBounded(t *testing.T) {
	t.Parallel()
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			t.Parallel()
			canary := testsecrets.Canary(t, testsecrets.Session)
			redirect := ""
			if stream == "stderr" {
				redirect = " 1>&2"
			}
			p := newProvider(t, bitwarden.Options{
				Runner:  atkShell{script: "while :; do echo '" + canary + "'" + redirect + "; done"},
				Session: secret.FromString("synthetic-session"),
			})
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			var err error
			atkWithin(t, 15*time.Second, "Resolve under an output flood", func() {
				var s secret.Secret
				s, err = p.Resolve(ctx, bwRef("password"))
				if err == nil {
					t.Errorf("Resolve under a flood: nil error (%d bytes)", len(s.Expose()))
				}
			})
			if err == nil {
				return
			}
			if stream == "stdout" && !errors.Is(err, bitwarden.ErrOutputTooLarge) {
				t.Errorf("error = %v, want ErrOutputTooLarge", err)
			}
			var closeErr error
			atkWithin(t, 15*time.Second, "Close under an output flood", func() { closeErr = p.Close() })
			out := fmt.Sprintf("%v\n%+v\n%#v\n%v\n", err, err, err, closeErr)
			writeArtifact(t, "flood-"+stream+".txt", out)
			if strings.Contains(out, canary) {
				t.Errorf("flooded output reached the error: %s", out)
			}
		})
	}
}

// TestAttack_ExecRunnerGrandchildHoldingPipesIsBounded makes the CLI exit
// at once but leave a background grandchild holding stdout and stderr open:
// Run must not wait for the grandchild. The grandchild never exits on its
// own (sleep 3600); the test kills it only after Run returned, so Run
// returning at all proves it gave up on the pipes, whatever the machine
// load (no wall-clock window to race). ErrWaitDelay proves it gave up
// through the WaitDelay bound, not because the pipes closed. A watchdog
// kills the grandchild shortly before the test deadline so a regression
// fails with a message instead of a go test timeout. The bound itself:
// WaitDelay must stay within the 10 s this test historically allowed, and
// Run within WaitDelay plus a generous 60 s for start-up under load.
func TestAttack_ExecRunnerGrandchildHoldingPipesIsBounded(t *testing.T) {
	t.Parallel()
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	var killed atomic.Bool
	killGrandchild := func() {
		raw, err := os.ReadFile(pidFile) // #nosec G304 -- test-owned temp file
		if err != nil {
			return // the shell never started the grandchild
		}
		if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	t.Cleanup(killGrandchild)
	if deadline, ok := t.Deadline(); ok {
		watchdog := time.AfterFunc(time.Until(deadline)*9/10, func() {
			killed.Store(true)
			killGrandchild()
		})
		t.Cleanup(func() { watchdog.Stop() })
	}

	if bitwarden.WaitDelay <= 0 || bitwarden.WaitDelay > 10*time.Second {
		t.Fatalf("WaitDelay = %v, want in (0, 10s]", bitwarden.WaitDelay)
	}

	budget := bitwarden.WaitDelay + 60*time.Second
	var overBudget atomic.Bool
	overTimer := time.AfterFunc(budget, func() { overBudget.Store(true) })
	defer overTimer.Stop()

	var stdout, stderr bytes.Buffer
	err := bitwarden.ExecRunner{Path: "/bin/sh"}.Run(t.Context(), bitwarden.Command{
		Args:   []string{"-c", `sleep 3600 & echo $! > '` + pidFile + `'; echo '{"status":"unlocked"}'`},
		Stdout: &stdout, Stderr: &stderr,
	})
	tooSlow := overBudget.Load()
	if killed.Load() {
		t.Fatalf("Run returned only once the grandchild was killed: it waited for the pipes (err = %v)", err)
	}
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("Run with a grandchild holding the pipes: err = %v, want exec.ErrWaitDelay", err)
	}
	if tooSlow {
		t.Fatalf("Run took over %v with a grandchild holding the pipes, want at most WaitDelay (%v) + 60s", budget, bitwarden.WaitDelay)
	}
}

// TestAttack_ExecRunnerHostileParentEnvironmentNotInherited sets variables
// that would let the parent environment inject code into, or redirect the
// traffic of, the CLI subprocess (dynamic loader, shell startup, Node
// options and module paths, TLS bypass, proxies, Bitwarden API keys). None
// may reach the subprocess. Not parallel: t.Setenv.
func TestAttack_ExecRunnerHostileParentEnvironmentNotInherited(t *testing.T) {
	canary := testsecrets.Canary(t, testsecrets.Token)
	hostile := []string{
		"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "DYLD_INSERT_LIBRARIES",
		"BASH_ENV", "ENV", "SHELLOPTS", "IFS", "PS4",
		"NODE_OPTIONS", "NODE_PATH", "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_DEBUG", "NODE_V8_COVERAGE",
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "NO_PROXY",
		"BW_SESSION", "BW_PASSWORD", "BW_CLIENTID", "BW_CLIENTSECRET", "BITWARDENCLI_DEBUG",
		"FACTO_BW_MASTER_PASSWORD", "GODEBUG", "GOTRACEBACK",
	}
	for _, k := range hostile {
		v := canary
		if strings.HasPrefix(k, "LD_") || k == "DYLD_INSERT_LIBRARIES" {
			v = "/nonexistent/" + canary + ".so"
		}
		t.Setenv(k, v)
	}
	rep, err := runHelper(t.Context(), t, nil, "status")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	env := envMap(rep.Env)
	for _, k := range hostile {
		if _, ok := env[k]; ok {
			t.Errorf("%s inherited by the subprocess", k)
		}
	}
	if strings.Contains(strings.Join(rep.Env, "\n"), canary) {
		t.Error("a parent-environment canary reached the subprocess")
	}
	if env["BW_NOINTERACTION"] != "true" {
		t.Error("BW_NOINTERACTION missing: the fake CLI did not report its environment")
	}
}

// TestAttack_ExecRunnerRelativePathEntryRefused plants an executable named
// like the configured CLI in the working directory (a link to true(1)) and
// puts a relative entry in PATH. Run must refuse the relative match
// (exec.ErrDot) rather than execute the planted file. Not parallel:
// t.Chdir, t.Setenv.
func TestAttack_ExecRunnerRelativePathEntryRefused(t *testing.T) {
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Fatalf("setup: true(1) not found: %v", err)
	}
	dir := t.TempDir()
	if err := os.Symlink(truePath, filepath.Join(dir, "facto-fake-cli")); err != nil {
		t.Fatalf("setup planted binary: %v", err)
	}
	t.Chdir(dir)
	for _, path := range []string{":/usr/bin:/bin", ".:/usr/bin:/bin", "/usr/bin:/bin:"} {
		t.Setenv("PATH", path)
		var out bytes.Buffer
		err := bitwarden.ExecRunner{Path: "facto-fake-cli"}.Run(t.Context(), bitwarden.Command{
			Args: []string{"status"}, Stdout: &out, Stderr: &out,
		})
		if !errors.Is(err, exec.ErrDot) {
			t.Errorf("PATH %q: Run error = %v, want exec.ErrDot (nil means the planted binary ran)", path, err)
		}
	}
}
