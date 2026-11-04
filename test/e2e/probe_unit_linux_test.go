//go:build e2e && linux

package e2e

// Self-tests of the browser probes (J1 T22): the probe must find a real
// listener and a real --user-data-dir in a descendant process, so that "no
// listening CDP port" and "profile removed" are never vacuous.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const probeHelperEnv = "FACTO_E2E_PROBE_HELPER"

// TestProbeHelperProcess is the child of the probe self-tests: with
// FACTO_E2E_PROBE_HELPER=listen it opens a TCP listener on 127.0.0.1:0,
// prints its port and blocks until stdin closes; with "idle" it only
// blocks. Without the variable it returns at once (the regular test run).
func TestProbeHelperProcess(_ *testing.T) {
	mode := os.Getenv(probeHelperEnv)
	if mode == "" {
		return
	}
	switch mode {
	case "hardened":
		hardenedHelper("", "")
	case "hardened-listen":
		hardenedHelper("tcp4", "127.0.0.1:0")
	case "hardened-listen6":
		// [::1] when the host has it; else [::] with IPV6_V6ONLY (Go sets
		// it for "tcp6"), which binds even where IPv6 is disabled and
		// cannot collide with the site's 127.0.0.1 socket. Either is a
		// tcp6 row on the site's port.
		addr := net.JoinHostPort("::1", os.Getenv(probePortEnv))
		if !canListen("tcp6", addr) {
			addr = net.JoinHostPort("::", os.Getenv(probePortEnv))
		}
		hardenedHelper("tcp6", addr)
	}
	if mode == "listen" {
		var lc net.ListenConfig
		ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
		if err != nil {
			os.Exit(3)
		}
		_, _ = fmt.Fprintf(os.Stdout, "port %d\n", ln.Addr().(*net.TCPAddr).Port)
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		_ = ln.Close()
		os.Exit(0)
	}
	_, _ = fmt.Fprintln(os.Stdout, "ready")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	os.Exit(0)
}

// probeProfileEnv carries the --user-data-dir of the hardened helper's child.
const probeProfileEnv = "FACTO_E2E_PROBE_PROFILE"

// canListen reports whether netw/addr can be bound (the probe listener
// is closed at once).
func canListen(netw, addr string) bool {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), netw, addr)
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// probePortEnv carries the port the "hardened-listen6" helper listens on
// in tcp6.
const probePortEnv = "FACTO_E2E_PROBE_PORT"

// hardenedHelper plays facto: it sets PR_SET_DUMPABLE=0 like
// internal/proc Harden (its fd and ns entries become unreadable to the
// test), optionally listens on addr (network netw, "" for none) in the
// host network namespace, then starts an idle Chrome-like child (exec
// makes it dumpable again) and prints "ready". Closing stdin ends both.
func hardenedHelper(netw, addr string) {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		os.Exit(4)
	}
	var ln net.Listener
	if netw != "" {
		var lc net.ListenConfig
		var err error
		if ln, err = lc.Listen(context.Background(), netw, addr); err != nil {
			os.Exit(3)
		}
	}
	// #nosec G204 G702 -- re-executes the test binary itself with fixed arguments (J1 T22, SEC-J0-14 tracking issue (BLOCKED H1))
	child := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestProbeHelperProcess$", "--",
		"--remote-debugging-pipe", "--user-data-dir="+os.Getenv(probeProfileEnv))
	child.Env = append(os.Environ(), probeHelperEnv+"=idle")
	in, err := child.StdinPipe()
	if err != nil {
		os.Exit(5)
	}
	out, err := child.StdoutPipe()
	if err != nil {
		os.Exit(5)
	}
	if err := child.Start(); err != nil {
		os.Exit(5)
	}
	if _, err := bufio.NewReader(out).ReadString('\n'); err != nil {
		os.Exit(6)
	}
	_, _ = fmt.Fprintln(os.Stdout, "ready")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	_ = in.Close()
	_ = child.Wait()
	if ln != nil {
		_ = ln.Close()
	}
	os.Exit(0)
}

// startProbeChild runs the helper with a fake Chrome-like command line and
// returns its pid once it is ready. The child ends with the test.
func startProbeChild(t *testing.T, mode, profile string, extraEnv ...string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	// #nosec G204 G702 -- re-executes the test binary itself with fixed arguments (J1 T22, SEC-J0-14 tracking issue (BLOCKED H1))
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProbeHelperProcess$", "--",
		"--remote-debugging-pipe", "--user-data-dir="+profile)
	cmd.Env = append(os.Environ(), probeHelperEnv+"="+mode, probeProfileEnv+"="+profile)
	cmd.Env = append(cmd.Env, extraEnv...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
		cancel()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("helper not ready: %v", err)
	}
	if mode == "listen" && !strings.HasPrefix(line, "port ") {
		t.Fatalf("helper said %q", line)
	}
	return cmd.Process.Pid
}

func TestBrowserProbe_FindsListenerInDescendant(t *testing.T) {
	t.Parallel()
	profile := filepath.Join(t.TempDir(), "profile-1")
	// Probe the child's own tree: the test process itself runs fake sites
	// (listeners) and would make the check trivially true.
	pid := startProbeChild(t, "listen", profile)
	p := probeBrowserTree(pid, probeOptions{})
	if p.Err != nil {
		t.Fatalf("probe: %v", p.Err)
	}
	if len(p.Listeners) == 0 {
		t.Fatalf("probe found no listener, but a descendant listens on 127.0.0.1 (probe is vacuous): %+v", p)
	}
	if !containsProfile(p, profile) {
		t.Errorf("probe profiles = %q, want %q", p.Profiles, profile)
	}
	t.Logf("probe detects a real listener: %q", p.Listeners)
}

func TestBrowserProbe_NoListenerInIdleTree(t *testing.T) {
	t.Parallel()
	profile := filepath.Join(t.TempDir(), "profile-2")
	pid := startProbeChild(t, "idle", profile)
	p := probeBrowserTree(pid, probeOptions{})
	if p.Err != nil {
		t.Fatalf("probe: %v", p.Err)
	}
	if len(p.Listeners) != 0 {
		t.Errorf("idle helper: listeners %q, want none", p.Listeners)
	}
	if !containsProfile(p, profile) || len(p.BrowserPIDs) != 1 || p.BrowserPIDs[0] != pid {
		t.Errorf("probe = %+v, want the helper as the only browser process with its profile", p)
	}
}

func TestBrowserProbe_FlagsDebugPortArgument(t *testing.T) {
	t.Parallel()
	// A command line asking for a TCP debugging port is a finding even
	// before the port is bound.
	if got := debugPortArgs([]string{"chrome", "--remote-debugging-port=0", "--user-data-dir=/x"}); len(got) != 1 {
		t.Errorf("debugPortArgs = %q, want the port flag", got)
	}
	if got := debugPortArgs([]string{"chrome", "--remote-debugging-pipe", "--user-data-dir=/x"}); len(got) != 0 {
		t.Errorf("debugPortArgs(pipe) = %q, want none", got)
	}
}

func TestBrowserProbe_EmptyTreeIsAnError(t *testing.T) {
	t.Parallel()
	// A tree whose only process has an empty --user-data-dir holds no
	// browser profile: the probe must say so instead of passing.
	pid := startProbeChild(t, "idle", "")
	p := probeBrowserTree(pid, probeOptions{})
	if err := p.requireBrowser(); err == nil {
		t.Error("requireBrowser on a tree without a profile: nil error, want one (never vacuous)")
	}
}

// TestBrowserProbe_DetectsRealChromeDebugPort is the real-browser control
// of "no listening CDP port": Chrome for Testing started with a TCP
// debugging port must be flagged (listener and argument), and its sandboxed
// process tree must be fully readable (no probe error).
func TestBrowserProbe_DetectsRealChromeDebugPort(t *testing.T) {
	t.Parallel()
	profile := filepath.Join(t.TempDir(), "profile-chrome")
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	// #nosec G204 -- FACTO_E2E_CHROME is the pinned Chrome for Testing installed by make chrome (J1 T22, SEC-J0-14 tracking issue (BLOCKED H1))
	cmd := exec.CommandContext(ctx, chromePath(t), "--headless", "--no-first-run",
		"--user-data-dir="+profile, "--remote-debugging-port=0", "about:blank")
	cmd.Env = []string{"HOME=" + t.TempDir()}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start chrome: %v", err)
	}
	defer func() {
		// Kill the whole group: Chrome children would keep writing the
		// profile and race the TempDir cleanup.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
	}()
	sc := bufio.NewScanner(stderr)
	listening := false
	for sc.Scan() {
		if strings.Contains(sc.Text(), "DevTools listening on ws://127.0.0.1:") {
			listening = true
			break
		}
	}
	if !listening {
		t.Fatal("chrome never reported its DevTools listener")
	}
	go func() {
		for sc.Scan() { // drain: chrome must never block on stderr
		}
	}()
	p := probeBrowserTree(cmd.Process.Pid, probeOptions{})
	if p.Err != nil {
		t.Fatalf("probe of a real Chrome tree: %v (the probe must see every process)", p.Err)
	}
	if len(p.Listeners) == 0 || len(p.DebugPortArgs) == 0 || p.clean() == nil {
		t.Fatalf("probe missed the real debugging port: %+v", p)
	}
	if !containsProfile(p, profile) {
		t.Errorf("profiles = %q, want %q", p.Profiles, profile)
	}
	t.Logf("probe flags a real Chrome debugging port: %q (%d processes)", p.Listeners, p.Processes)
}

// The two hardened-root tests are not parallel: their host-namespace check
// counts every new listener nobody readable holds, so they must not overlap
// each other (Go runs non-parallel tests before resuming parallel ones).

// TestBrowserProbe_HardenedRootNotRequired: facto (the root) is
// non-dumpable and unreadable; its Chrome-like child is fully inspected.
// The probe passes with HardenedRoot and fails without it, proving the
// root really was unreadable.
func TestBrowserProbe_HardenedRootNotRequired(t *testing.T) {
	base, err := snapshotHostListeners()
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	profile := filepath.Join(t.TempDir(), "profile-hardened")
	pid := startProbeChild(t, "hardened", profile)

	strict := probeBrowserTree(pid, probeOptions{})
	if strict.Err == nil {
		t.Fatalf("probe without HardenedRoot read the non-dumpable root (test is vacuous): %+v", strict)
	}

	p := probeBrowserTree(pid, probeOptions{HardenedRoot: true, HostBaseline: base})
	if p.Err != nil {
		t.Fatalf("hardened probe: %v", p.Err)
	}
	if !p.RootHardened {
		t.Error("RootHardened = false, want the unreadable root recorded")
	}
	if p.Inspected != 1 || p.InspectedBrowsers != 1 || !containsProfile(p, profile) {
		t.Errorf("probe = %+v, want the one Chrome-like child fully inspected with %s", p, profile)
	}
	if err := p.clean(); err != nil {
		t.Errorf("clean() = %v, want nil (no listener anywhere)", err)
	}
}

// TestBrowserProbe_NewHostListenerDetected: the hardened root opens a
// listener in the host network namespace during the run. Its fds are
// unreadable, so only the host diff can see it: the probe must fail. The
// fake site's port, when allowed, is the only exception.
func TestBrowserProbe_NewHostListenerDetected(t *testing.T) {
	base, err := snapshotHostListeners()
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	site := unitSite(t, ModePassword) // a listener opened after the baseline, held by this readable process
	profile := filepath.Join(t.TempDir(), "profile-hardened-listen")
	pid := startProbeChild(t, "hardened-listen", profile)

	if blind := probeBrowserTree(pid, probeOptions{HardenedRoot: true}); len(blind.Listeners) != 0 {
		t.Fatalf("without a baseline the hardened listener is visible (test is vacuous): %q", blind.Listeners)
	}
	p := probeBrowserTree(pid, probeOptions{HardenedRoot: true, HostBaseline: base, AllowListeners: []string{siteListener(site.Addr().Port())}})
	if p.Err != nil {
		t.Fatalf("probe: %v", p.Err)
	}
	if err := p.clean(); err == nil {
		t.Fatalf("clean() = nil, want the hardened root's host listener reported: %+v", p)
	}
	if len(p.Listeners) != 1 || !strings.Contains(p.Listeners[0], "host netns") {
		t.Errorf("Listeners = %q, want exactly the hardened root's host listener", p.Listeners)
	}
	t.Logf("hardened listener reported: %q", p.Listeners)
}

// TestBrowserProbe_SitePortOnOtherAddressDetected: the exemption is the
// fake site's exact tcp4 127.0.0.1 listener only. A hardened root
// listening in tcp6 on the very same port is a new host listener: the
// probe must fail. The helper binds [::1], or [::] (IPV6_V6ONLY) on hosts
// where IPv6 is disabled and [::1] does not exist: any tcp6 row on the
// port exercises the same rule.
func TestBrowserProbe_SitePortOnOtherAddressDetected(t *testing.T) {
	base, err := snapshotHostListeners()
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	site := unitSite(t, ModePassword)
	port := site.Addr().Port()
	profile := filepath.Join(t.TempDir(), "profile-hardened-listen6")
	pid := startProbeChild(t, "hardened-listen6", profile, probePortEnv+"="+strconv.Itoa(int(port)))

	p := probeBrowserTree(pid, probeOptions{HardenedRoot: true, HostBaseline: base, AllowListeners: []string{siteListener(port)}})
	if p.Err != nil {
		t.Fatalf("probe: %v", p.Err)
	}
	if err := p.clean(); err == nil {
		t.Fatalf("clean() = nil, want the tcp6 port %d listener of the hardened root reported: %+v", port, p)
	}
	want := fmt.Sprintf(":%04X", port)
	if len(p.Listeners) != 1 || !strings.Contains(p.Listeners[0], "host netns") || !strings.Contains(p.Listeners[0], "tcp6") || !strings.HasSuffix(p.Listeners[0], want) {
		t.Errorf("Listeners = %q, want exactly the hardened root's tcp6 listener on port %d", p.Listeners, port)
	}
	t.Logf("site port in tcp6 reported: %q", p.Listeners)
}

func containsProfile(p browserProbe, dir string) bool {
	for _, d := range p.Profiles {
		if d == dir {
			return true
		}
	}
	return false
}
