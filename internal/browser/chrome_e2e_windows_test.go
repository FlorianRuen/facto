//go:build e2e && chrome && windows

// Real-Chrome checks of the Windows port-0 transport (J1 T13/T32, ADR 0008
// "Windows (A4)", accepted MEDIUM finding). Chrome is launched through the
// production Pool (the Windows Starter of T7c: --remote-debugging-port=0,
// port read from DevToolsActivePort, dialled through cdploopback) and the
// tests check what other local processes can reach:
//
//   - exactly one LISTENING row for the CDP port in `netstat -ano -p TCP`
//     and `-p TCPv6`, bound to 127.0.0.1, never 0.0.0.0 or [::];
//   - the probe is never vacuous: a wildcard control listener is flagged;
//   - the listening PID is the Chrome facto started on that profile;
//   - Chrome refuses a WebSocket handshake carrying a foreign Origin or a
//     non-loopback Host header (DNS rebinding);
//   - the profile is removed on Close and the port closes right after the
//     login step.
//
// Chrome: FACTO_E2E_CHROME (T32 uses the Chrome preinstalled on
// windows-latest). The tests fail, never skip, when it is unset. Run with
// `make e2e-browser-windows`, the exact command of the T32 CI job.
//
// Expected production API: none beyond T7c (Pool's default Starter on
// Windows; today it is nil and Launch fails with ErrLaunchFailed).
package browser_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/connector"
)

const (
	winChromeEnv = "FACTO_E2E_CHROME"
	winTimeout   = 90 * time.Second
	winWait      = 20 * time.Second
	winDomain    = "login.supplier.example"
)

// winChrome returns FACTO_E2E_CHROME; unset fails the test.
func winChrome(t *testing.T) string {
	t.Helper()
	v := os.Getenv(winChromeEnv)
	if v == "" {
		t.Fatalf("%s is not set: the Windows real-Chrome checks need a Chrome binary (this test fails, never skips)", winChromeEnv)
	}
	if !filepath.IsAbs(v) {
		t.Fatalf("%s must be absolute", winChromeEnv)
	}
	return filepath.Clean(v) // the pool's CheckExecutable vets it
}

// winLaunch builds a pool on a private state dir and leases a headless
// browser. Close is registered as cleanup.
func winLaunch(ctx context.Context, t *testing.T) *browser.PoolBrowser {
	t.Helper()
	exe := winChrome(t)
	root := t.TempDir()
	env := map[string]string{}
	for _, k := range []string{"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH", "USERPROFILE", "LOCALAPPDATA", "APPDATA"} {
		if v, ok := os.LookupEnv(k); ok {
			env[k] = v
		}
	}
	p, err := browser.NewPool(ctx, browser.PoolConfig{
		Host: browser.Host{
			Executable: exe,
			Geteuid:    func() int { return -1 },
			LookupEnv:  mapLookup(env),
			Log:        slog.New(slog.DiscardHandler),
		},
		StateDir: root,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	winCloseAtCleanup(t, p)
	b, err := p.Launch(ctx, connector.LaunchOptions{AllowedDomains: []string{winDomain}})
	if err != nil {
		t.Fatalf("Launch real Chrome: %v", err)
	}
	pb, ok := b.(*browser.PoolBrowser)
	if !ok {
		t.Fatalf("Launch returned %T, want *browser.PoolBrowser", b)
	}
	winCloseAtCleanup(t, pb)
	return pb
}

// winCloseAtCleanup closes c when the test ends (Close takes no context).
func winCloseAtCleanup(t *testing.T, c io.Closer) {
	t.Helper()
	t.Cleanup(func() { _ = c.Close() })
}

var winWSPath = regexp.MustCompile(`^/devtools/browser/[0-9a-f-]{36}$`)

// winPortFile reads <profile>/DevToolsActivePort with the ADR 0008 rules:
// at most 256 bytes, port 1-65535, browser WebSocket path.
func winPortFile(t *testing.T, profile string) (int, string) {
	t.Helper()
	root, err := os.OpenRoot(profile)
	if err != nil {
		t.Fatalf("open profile: %v", err)
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open("DevToolsActivePort")
	if err != nil {
		t.Fatalf("DevToolsActivePort: %v", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 256 {
		t.Fatalf("DevToolsActivePort is %d+ bytes, want <= 256", len(b))
	}
	lines := strings.Split(strings.TrimRight(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("DevToolsActivePort has %d lines, want 2", len(lines))
	}
	port, err := strconv.Atoi(lines[0])
	if err != nil || port < 1 || port > 65535 {
		t.Fatalf("DevToolsActivePort port line is not a port")
	}
	if !winWSPath.MatchString(lines[1]) {
		t.Fatalf("DevToolsActivePort path line does not match %s", winWSPath)
	}
	return port, lines[1]
}

// netstatRow is one row of `netstat -ano -p TCP|TCPv6`.
type netstatRow struct {
	proto, host string
	port        int
	state       string
	pid         int
}

func (r netstatRow) String() string {
	return fmt.Sprintf("%s %s:%d %s pid %d", r.proto, r.host, r.port, r.state, r.pid)
}

// parseNetstat parses netstat -ano output: "TCP  127.0.0.1:49717  0.0.0.0:0
// LISTENING  1234", IPv6 local addresses as "[::1]:49717".
func parseNetstat(out string) []netstatRow {
	var rows []netstatRow
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 5 || !strings.EqualFold(f[0], "TCP") {
			continue
		}
		i := strings.LastIndexByte(f[1], ':')
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(f[1][i+1:])
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(f[4])
		if err != nil {
			continue
		}
		rows = append(rows, netstatRow{
			proto: f[0], host: strings.Trim(f[1][:i], "[]"), port: port, state: f[3], pid: pid,
		})
	}
	return rows
}

// winNetstat returns the TCP and TCPv6 rows of netstat -ano.
func winNetstat(t *testing.T) []netstatRow {
	t.Helper()
	tcp4, err := exec.CommandContext(t.Context(), "netstat", "-ano", "-p", "TCP").Output()
	if err != nil {
		t.Fatalf("netstat -ano -p TCP: %v", err)
	}
	tcp6, err := exec.CommandContext(t.Context(), "netstat", "-ano", "-p", "TCPv6").Output()
	if err != nil {
		t.Fatalf("netstat -ano -p TCPv6: %v", err)
	}
	return append(parseNetstat(string(tcp4)), parseNetstat(string(tcp6))...)
}

// listeningOn returns the LISTENING rows for port.
func listeningOn(rows []netstatRow, port int) []netstatRow {
	var out []netstatRow
	for _, r := range rows {
		if r.port == port && r.state == "LISTENING" {
			out = append(out, r)
		}
	}
	return out
}

// loopbackViolations returns the LISTENING rows for port not bound to
// 127.0.0.1 (wildcard, IPv6, LAN address).
func loopbackViolations(rows []netstatRow, port int) []netstatRow {
	var bad []netstatRow
	for _, r := range listeningOn(rows, port) {
		if r.host != "127.0.0.1" {
			bad = append(bad, r)
		}
	}
	return bad
}

// winHandshake sends a WebSocket upgrade for path to 127.0.0.1:port with
// the given Host (and Origin when not empty) and returns the HTTP status.
func winHandshake(t *testing.T, port int, path, host, origin string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("dial CDP port: %v", err)
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() }) // bounds the exchange
	defer stop()
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key) + "\r\nSec-WebSocket-Version: 13\r\n"
	if origin != "" {
		req += "Origin: " + origin + "\r\n"
	}
	if _, err := io.WriteString(conn, req+"\r\n"); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read handshake status: %v", err)
	}
	f := strings.Fields(line)
	if len(f) < 2 {
		t.Fatalf("handshake status line malformed")
	}
	code, err := strconv.Atoi(f[1])
	if err != nil {
		t.Fatalf("handshake status code malformed")
	}
	return code
}

// winProcessScript prints the executable path and the command line of the
// process $env:FACTO_E2E_PID, nothing when it does not exist.
const winProcessScript = "$p = Get-CimInstance Win32_Process -Filter ('ProcessId=' + [int]$env:FACTO_E2E_PID); " +
	"if ($p) { $p.ExecutablePath; $p.CommandLine }"

// winProcess returns the executable path and command line of pid.
func winProcess(t *testing.T, pid int) (exe, cmdline string, alive bool) {
	t.Helper()
	// The pid travels in the environment: the script itself is constant.
	c := exec.CommandContext(t.Context(), "powershell", "-NoProfile", "-NonInteractive", "-Command", winProcessScript)
	c.Env = append(os.Environ(), "FACTO_E2E_PID="+strconv.Itoa(pid))
	out, err := c.Output()
	if err != nil {
		t.Fatalf("query process %d: %v", pid, err)
	}
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(string(out), "\r\n", "\n")), "\n")
	if len(lines) < 2 {
		return "", "", false
	}
	return strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1]), true
}

// winPoll polls cond every 100 ms until it holds or winWait passes.
func winPoll(cond func() bool) bool {
	deadline := time.After(winWait)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for !cond() {
		select {
		case <-deadline:
			return false
		case <-tick.C:
		}
	}
	return true
}

// TestChromeWindows_DebugPortLoopbackOnly (A4): the CDP port Chrome
// reports has exactly one LISTENING row, on 127.0.0.1; no 0.0.0.0, [::] or
// other row for it in TCP or TCPv6.
func TestChromeWindows_DebugPortLoopbackOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), winTimeout)
	defer cancel()
	b := winLaunch(ctx, t)
	port, _ := winPortFile(t, b.ProfileDir())
	rows := winNetstat(t)
	l := listeningOn(rows, port)
	if len(l) != 1 {
		t.Fatalf("LISTENING rows for the CDP port %d = %v, want exactly one", port, l)
	}
	if bad := loopbackViolations(rows, port); len(bad) != 0 {
		t.Fatalf("CDP port %d bound beyond 127.0.0.1: %v", port, bad)
	}
	t.Log("CDP port bound to 127.0.0.1 only")
}

// TestChromeWindows_ProbeDetectsWildcardListener: the netstat probe is not
// vacuous: control listeners on 0.0.0.0 and [::] are flagged, one on
// 127.0.0.1 is not.
func TestChromeWindows_ProbeDetectsWildcardListener(t *testing.T) {
	tests := []struct {
		name, network, addr string
		flagged             bool
	}{
		{name: "tcp4 wildcard", network: "tcp4", addr: "0.0.0.0:0", flagged: true},
		{name: "tcp6 wildcard", network: "tcp6", addr: "[::]:0", flagged: true},
		{name: "tcp4 loopback", network: "tcp4", addr: "127.0.0.1:0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var lc net.ListenConfig
			ln, err := lc.Listen(t.Context(), tt.network, tt.addr)
			if err != nil {
				t.Fatalf("control listener: %v", err)
			}
			defer func() { _ = ln.Close() }()
			port := ln.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // a TCP listener
			rows := winNetstat(t)
			if len(listeningOn(rows, port)) == 0 {
				t.Fatalf("probe found no LISTENING row for the control listener on %d", port)
			}
			if got := len(loopbackViolations(rows, port)) > 0; got != tt.flagged {
				t.Errorf("control listener %s flagged = %v, want %v", tt.addr, got, tt.flagged)
			}
		})
	}
}

// TestChromeWindows_ListenerPIDIsChrome: the PID listening on the CDP port
// is the Chrome executable facto started, on the lease's profile.
func TestChromeWindows_ListenerPIDIsChrome(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), winTimeout)
	defer cancel()
	b := winLaunch(ctx, t)
	port, _ := winPortFile(t, b.ProfileDir())
	l := listeningOn(winNetstat(t), port)
	if len(l) != 1 {
		t.Fatalf("LISTENING rows for the CDP port = %v, want one", l)
	}
	exe, cmd, alive := winProcess(t, l[0].pid)
	if !alive {
		t.Fatalf("listener pid %d not found", l[0].pid)
	}
	if !strings.EqualFold(filepath.Clean(exe), filepath.Clean(winChrome(t))) {
		t.Errorf("listener pid %d runs %q, want %s", l[0].pid, exe, winChromeEnv)
	}
	if !strings.Contains(cmd, "--user-data-dir="+b.ProfileDir()) {
		t.Errorf("listener pid %d is not the browser on the lease's profile", l[0].pid)
	}
	if !strings.Contains(cmd, "--remote-debugging-port=0") {
		t.Errorf("listener pid %d was not started with --remote-debugging-port=0", l[0].pid)
	}
}

// TestChromeWindows_OriginHeaderRejected: a web page cannot drive the CDP
// port: a handshake with a foreign Origin is refused (no
// --remote-allow-origins), while the same handshake without Origin, as
// cdploopback sends it, is accepted (control).
func TestChromeWindows_OriginHeaderRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), winTimeout)
	defer cancel()
	b := winLaunch(ctx, t)
	port, path := winPortFile(t, b.ProfileDir())
	host := "127.0.0.1:" + strconv.Itoa(port)
	for _, origin := range []string{"https://evil.example", "http://127.0.0.1:" + strconv.Itoa(port), "null"} {
		if code := winHandshake(t, port, path, host, origin); code == 101 {
			t.Errorf("handshake with Origin %q accepted (101), want refused", origin)
		}
	}
	if code := winHandshake(t, port, path, host, ""); code != 101 {
		t.Errorf("handshake without Origin = %d, want 101 (control)", code)
	}
}

// TestChromeWindows_NonLoopbackHostHeaderRejected: DNS rebinding cannot
// reach the CDP port: a handshake whose Host is not a loopback IP is
// refused; Host 127.0.0.1:<port> is accepted (control).
func TestChromeWindows_NonLoopbackHostHeaderRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), winTimeout)
	defer cancel()
	b := winLaunch(ctx, t)
	port, path := winPortFile(t, b.ProfileDir())
	p := strconv.Itoa(port)
	for _, host := range []string{"evil.example:" + p, winDomain + ":" + p, "rebind.example"} {
		if code := winHandshake(t, port, path, host, ""); code == 101 {
			t.Errorf("handshake with Host %q accepted (101), want refused", host)
		}
	}
	if code := winHandshake(t, port, path, "127.0.0.1:"+p, ""); code != 101 {
		t.Errorf("handshake with Host 127.0.0.1:%s = %d, want 101 (control)", p, code)
	}
}

// TestChromeWindows_ProfileRemoved: after Close the profile directory is
// gone and Done is closed.
func TestChromeWindows_ProfileRemoved(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), winTimeout)
	defer cancel()
	b := winLaunch(ctx, t)
	profile := b.ProfileDir()
	if _, err := os.Stat(profile); err != nil {
		t.Fatalf("profile while running: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-b.Done():
	default:
		t.Error("Done not closed when Close returned")
	}
	if _, err := os.Lstat(profile); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("profile still present after Close (Lstat err = %v)", err)
	}
	if !t.Failed() {
		t.Log("profile removed")
	}
}

// TestChromeWindows_ClosedAfterLogin (A4): once the login step is over
// (a Navigate on the allowlist, then Close as the orchestrator does) the
// CDP port stops listening and the Chrome process is gone.
func TestChromeWindows_ClosedAfterLogin(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), winTimeout)
	defer cancel()
	b := winLaunch(ctx, t)
	port, _ := winPortFile(t, b.ProfileDir())
	l := listeningOn(winNetstat(t), port)
	if len(l) != 1 {
		t.Fatalf("LISTENING rows for the CDP port = %v, want one", l)
	}
	pid := l[0].pid
	_ = b.Navigate(ctx, "https://"+winDomain+"/") // the host does not resolve: only the step matters
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !winPoll(func() bool { return len(listeningOn(winNetstat(t), port)) == 0 }) {
		t.Errorf("CDP port %d still listening %v after Close", port, winWait)
	}
	if !winPoll(func() bool { _, _, alive := winProcess(t, pid); return !alive }) {
		t.Errorf("Chrome pid %d still running %v after Close", pid, winWait)
	}
}
