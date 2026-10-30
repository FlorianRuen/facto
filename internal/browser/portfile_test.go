// Windows port-0 transport, platform-neutral part (J1 T7c, ADR 0008
// "Windows (A4)", decision A4). Everything here runs on every OS: only the
// process start (os/exec on windows) and the TCP-table lookup
// (GetExtendedTcpTable) are windows-tagged, behind the seams below.
//
// Expected API (internal/browser), files without build tags unless noted:
//
//	// PortFileName is the file Chrome writes in --user-data-dir once its
//	// DevTools listener is up.
//	const PortFileName = "DevToolsActivePort"
//
//	// MaxPortFileBytes caps the port file (ADR 0008: at most 256 bytes).
//	const MaxPortFileBytes = 256
//
//	var (
//		// ErrPortFile: DevToolsActivePort is malformed, oversized, present
//		// before the browser started, not a regular file, or unreadable.
//		ErrPortFile = errors.New("browser: bad DevToolsActivePort file")
//		// ErrListenerNotBrowser: the socket listening on the CDP port is
//		// not owned by the started browser, is not bound to 127.0.0.1
//		// only, or the owner lookup failed (fail closed).
//		ErrListenerNotBrowser = errors.New("browser: cdp port listener is not the browser")
//		// ErrHandshake: the Browser.getVersion handshake failed.
//		ErrHandshake = errors.New("browser: cdp handshake failed")
//		// ErrNoHandshake: a message was sent or read on a PortTransport
//		// before its handshake succeeded. Nothing reached the browser.
//		ErrNoHandshake = errors.New("browser: cdp handshake not done")
//	)
//
//	// DevToolsTarget is a parsed DevToolsActivePort.
//	type DevToolsTarget struct {
//		Port int    // 1..65535
//		Path string // ^/devtools/browser/[0-9a-f-]{36}$
//	}
//
//	// ParseDevToolsActivePort accepts exactly "<port>\n<path>" with an
//	// optional single trailing "\n": port decimal ASCII digits, no sign, no
//	// leading zero, 1..65535; path matching ^/devtools/browser/[0-9a-f-]{36}$.
//	// Anything else (CR anywhere, NUL, BOM, spaces, extra or empty lines,
//	// more than MaxPortFileBytes) is ErrPortFile. Errors never quote the
//	// file.
//	func ParseDevToolsActivePort(data []byte) (DevToolsTarget, error)
//
//	// PortFileConfig holds the PortFile seams.
//	type PortFileConfig struct {
//		// Open opens a path for reading. Nil: open under the profile
//		// without following a symlink (fsx / os.Root). fs.ErrNotExist
//		// means "not written yet".
//		Open func(path string) (io.ReadCloser, error)
//		// Wait pauses between two attempts while the file is missing and
//		// returns ctx's error when ctx ends. Nil: a short timer.
//		Wait func(ctx context.Context) error
//	}
//
//	// ArmPortFile runs BEFORE the browser starts. profile must be an
//	// absolute, existing, empty directory (a fresh MkdirTemp profile):
//	// any entry in it is ErrUnsafeProfileDir. Open(<profile>/
//	// DevToolsActivePort) must then fail with fs.ErrNotExist: a file that
//	// opens (planted, symlink or not) or any other error is ErrPortFile.
//	func ArmPortFile(profile string, cfg PortFileConfig) (*PortFile, error)
//
//	// Read runs AFTER the browser started. It opens <profile>/
//	// DevToolsActivePort with cfg.Open; while it is missing (fs.ErrNotExist)
//	// it calls cfg.Wait and retries, until ctx ends. Once the file opens it
//	// reads at most MaxPortFileBytes+1 bytes (never more, whatever the
//	// reader offers), closes it and parses it once: over the cap or
//	// malformed is ErrPortFile, never retried.
//	func (p *PortFile) Read(ctx context.Context) (DevToolsTarget, error)
//
//	// WSConn is the consumer-side view of *cdploopback.Conn.
//	type WSConn interface {
//		ReadMessage(ctx context.Context) ([]byte, error)
//		WriteMessage(ctx context.Context, p []byte) error
//		Close() error
//	}
//
//	// DialLoopback dials t through internal/httpx/cdploopback only
//	// (cdploopback.New(t.Port, opts...).Dial(ctx, t.Path)): the literal
//	// 127.0.0.1:<port>, tcp4, no resolver, no proxy. t is validated again
//	// first (port 1..65535, browser GUID path): nothing is dialled for an
//	// invalid t.
//	func DialLoopback(ctx context.Context, t DevToolsTarget, opts ...cdploopback.Option) (WSConn, error)
//
//	// PortTransport adapts a WSConn to Transport (one WebSocket message =
//	// one CDP message). Until Handshake has succeeded, Send and Recv fail
//	// with ErrNoHandshake and nothing is written to or read from conn.
//	// Close closes conn; it is idempotent.
//	type PortTransport struct{ ... }
//	func NewPortTransport(conn WSConn) *PortTransport
//	func (t *PortTransport) Send(msg []byte) error
//	func (t *PortTransport) Recv() ([]byte, error)
//	func (t *PortTransport) Close() error
//
//	// Handshake writes one Browser.getVersion request and requires the
//	// very next message to be its response (same id) with non-empty string
//	// "protocolVersion" and "product". An event, another id, a CDP error,
//	// a non-JSON message, the peer closing or ctx ending: ErrHandshake, and
//	// conn is closed.
//	func (t *PortTransport) Handshake(ctx context.Context) error
//
//	// TCPListener is one listening TCP socket and its owner.
//	type TCPListener struct {
//		Addr netip.AddrPort
//		PID  int
//	}
//
//	// LoopbackListenerPID returns the pid owning the socket listening on
//	// port. Exactly one listener may use that port, bound to 127.0.0.1
//	// (IPv4 only): none, two, or one on any other address (0.0.0.0, ::,
//	// ::1, 127.0.0.2…) is ErrListenerNotBrowser.
//	func LoopbackListenerPID(rows []TCPListener, port int) (int, error)
//
//	type PortConnectConfig struct {
//		PortFile *PortFile // armed before the browser started
//		BrowserPID int     // pid of the started browser
//		// ListenerPID returns the pid owning the CDP port (windows:
//		// GetExtendedTcpTable + LoopbackListenerPID). Nil, an error or a
//		// pid other than BrowserPID: ErrListenerNotBrowser, nothing dialled.
//		ListenerPID func(ctx context.Context, port int) (int, error)
//		// Dial opens the WebSocket. Nil: DialLoopback.
//		Dial func(ctx context.Context, t DevToolsTarget) (WSConn, error)
//	}
//
//	// ConnectPort: PortFile.Read, listener pid check, Dial, Handshake, in
//	// that order. It returns a handshaken transport, or closes whatever it
//	// opened.
//	func ConnectPort(ctx context.Context, cfg PortConnectConfig) (*PortTransport, error)
//
//	// ExecProcess is a started OS process (windows: os/exec).
//	type ExecProcess interface {
//		Pid() int
//		Done() <-chan struct{} // closed once the process exited and was reaped
//		Kill() error           // kill and reap; idempotent
//	}
//
//	type PortStarterConfig struct {
//		// Exec starts cmd.Path with cmd.Args and cmd.Env unchanged, stderr
//		// to cmd.Stderr (windows: startPortExec, windows-tagged).
//		Exec func(ctx context.Context, cmd Command) (ExecProcess, error)
//		ListenerPID func(ctx context.Context, port int) (int, error) // as PortConnectConfig
//		Dial        func(ctx context.Context, t DevToolsTarget) (WSConn, error) // nil: DialLoopback
//		PortFile    PortFileConfig
//	}
//
//	// NewPortStarter returns the windows Starter (defaultStarter on
//	// windows, with the windows Exec and ListenerPID). Each start:
//	//  1. requires argv to hold exactly one --remote-debugging-port, valued
//	//     "0", and no --remote-debugging-pipe / --remote-debugging-io-pipes
//	//     (ErrForbiddenFlag), and one --user-data-dir (ErrNoProfileDir);
//	//  2. ArmPortFile on that profile;
//	//  3. Exec with the argv unchanged (nothing added, nothing removed);
//	//  4. ConnectPort with BrowserPID = the exec'd pid;
//	//  5. NewClient over the transport.
//	// Any failure after Exec kills and reaps the process before returning
//	// a nil Process. A failed Exec returns an error wrapping ErrLaunchFailed.
//	// The Process' Close closes the client (and so the WebSocket), then
//	// kills and reaps the browser; Done follows the process.
//	func NewPortStarter(cfg PortStarterConfig) Starter
//
// Windows-tagged (export_windows_test.go hooks, see port_windows_test.go):
// parseTCPTableOwnerPID (MIB_TCPTABLE_OWNER_PID rows → []TCPListener) and
// pidAliveVia (OpenProcess seam: access denied = alive).
package browser_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// Synthetic DevTools browser GUIDs (random-looking, not from any browser).
const (
	testGUID     = "0f3c1a2b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
	testGUIDPath = "/devtools/browser/" + testGUID
)

// portOpener is a PortFileConfig.Open double over an in-memory file.
type portOpener struct {
	mu      sync.Mutex
	content []byte // nil: missing (fs.ErrNotExist)
	err     error  // returned instead of the file when set
	reader  func() io.ReadCloser
	paths   []string
	opened  int // successful opens
}

func (o *portOpener) open(path string) (io.ReadCloser, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.paths = append(o.paths, path)
	if o.err != nil {
		return nil, o.err
	}
	if o.reader != nil {
		o.opened++
		return o.reader(), nil
	}
	if o.content == nil {
		return nil, fs.ErrNotExist
	}
	o.opened++
	return io.NopCloser(bytes.NewReader(o.content)), nil
}

func (o *portOpener) set(content []byte) {
	o.mu.Lock()
	o.content = content
	o.mu.Unlock()
}

func (o *portOpener) openedCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.opened
}

// endlessPortFile serves fill forever and counts what was read.
type endlessPortFile struct {
	mu     sync.Mutex
	fill   byte
	read   int
	closed bool
}

func (r *endlessPortFile) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range p {
		p[i] = r.fill
	}
	r.read += len(p)
	return len(p), nil
}

func (r *endlessPortFile) Close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return nil
}

func emptyProfile(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func armed(t *testing.T, o *portOpener, wait func(context.Context) error) *browser.PortFile {
	t.Helper()
	pf, err := browser.ArmPortFile(emptyProfile(t), browser.PortFileConfig{Open: o.open, Wait: wait})
	if err != nil {
		t.Fatalf("ArmPortFile(empty profile) = %v", err)
	}
	return pf
}

func TestPortFile_ParsesDevToolsActivePort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data string
		want browser.DevToolsTarget
	}{
		{"chrome layout", "9222\n" + testGUIDPath, browser.DevToolsTarget{Port: 9222, Path: testGUIDPath}},
		{"trailing newline", "51234\n" + testGUIDPath + "\n", browser.DevToolsTarget{Port: 51234, Path: testGUIDPath}},
		{"lowest port", "1\n" + testGUIDPath, browser.DevToolsTarget{Port: 1, Path: testGUIDPath}},
		{"highest port", "65535\n" + testGUIDPath, browser.DevToolsTarget{Port: 65535, Path: testGUIDPath}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := browser.ParseDevToolsActivePort([]byte(tc.data))
			if err != nil {
				t.Fatalf("ParseDevToolsActivePort(%q) = %v", tc.data, err)
			}
			if got != tc.want {
				t.Errorf("ParseDevToolsActivePort(%q) = %+v, want %+v", tc.data, got, tc.want)
			}
		})
	}

	t.Run("Read waits for the file then parses it", func(t *testing.T) {
		t.Parallel()
		o := &portOpener{}
		waits := 0
		pf := armed(t, o, func(ctx context.Context) error {
			waits++
			if waits == 2 {
				o.set([]byte("40123\n" + testGUIDPath))
			}
			return ctx.Err()
		})
		got, err := pf.Read(testCtx(t))
		if err != nil {
			t.Fatalf("Read = %v", err)
		}
		if want := (browser.DevToolsTarget{Port: 40123, Path: testGUIDPath}); got != want {
			t.Errorf("Read = %+v, want %+v", got, want)
		}
		if waits != 2 {
			t.Errorf("Wait called %d times, want 2 (once per missing attempt)", waits)
		}
		for _, p := range o.paths {
			if filepath.Base(p) != browser.PortFileName || !filepath.IsAbs(p) {
				t.Errorf("opened %q, want <profile>/%s", p, browser.PortFileName)
			}
		}
	})

	t.Run("Read bounded by ctx while missing", func(t *testing.T) {
		t.Parallel()
		o := &portOpener{}
		ctx, cancel := context.WithCancel(testCtx(t))
		pf := armed(t, o, func(ctx context.Context) error {
			cancel()
			return ctx.Err()
		})
		if _, err := pf.Read(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("Read with the file never written = %v, want context.Canceled", err)
		}
	})
}

func TestPortFile_RefusesMalformed(t *testing.T) {
	t.Parallel()
	p := testGUIDPath
	tests := []struct{ name, data string }{
		{"empty", ""},
		{"newline only", "\n"},
		{"port only", "9222"},
		{"port and newline only", "9222\n"},
		{"port 0", "0\n" + p},
		{"port 65536", "65536\n" + p},
		{"port overflow", "99999999999999999999\n" + p},
		{"leading zero", "09222\n" + p},
		{"plus sign", "+9222\n" + p},
		{"minus sign", "-9222\n" + p},
		{"hex port", "0x2406\n" + p},
		{"leading space", " 9222\n" + p},
		{"trailing space after port", "9222 \n" + p},
		{"trailing space after path", "9222\n" + p + " "},
		{"tab", "9222\t\n" + p},
		{"fullwidth digits", "\uff19\uff12\uff12\uff12\n" + p},
		{"BOM", "\ufeff9222\n" + p},
		{"NUL in port", "92\x0022\n" + p},
		{"NUL after path", "9222\n" + p + "\x00"},
		{"CRLF after port", "9222\r\n" + p},
		{"CRLF at end", "9222\n" + p + "\r\n"},
		{"lone CR at end", "9222\n" + p + "\r"},
		{"CR as separator", "9222\r" + p},
		{"empty line between", "9222\n\n" + p},
		{"two trailing newlines", "9222\n" + p + "\n\n"},
		{"extra line", "9222\n" + p + "\n/devtools/browser/" + testGUID},
		{"extra line after newline", "9222\n" + p + "\nextra"},
		{"swapped lines", p + "\n9222"},
		{"ws url instead of path", "9222\nws://127.0.0.1:9222" + p},
		{"page target", "9222\n/devtools/page/" + testGUID},
		{"path suffix", "9222\n" + p + "/x"},
		{"query", "9222\n" + p + "?a=b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := browser.ParseDevToolsActivePort([]byte(tc.data))
			if !errors.Is(err, browser.ErrPortFile) {
				t.Fatalf("ParseDevToolsActivePort(%q) = %+v, %v; want ErrPortFile", tc.data, got, err)
			}
			if got != (browser.DevToolsTarget{}) {
				t.Errorf("ParseDevToolsActivePort(%q) returned %+v with the error, want the zero target", tc.data, got)
			}
		})
	}

	t.Run("Read refuses a malformed file without retrying", func(t *testing.T) {
		t.Parallel()
		o := &portOpener{}
		pf := armed(t, o, func(ctx context.Context) error {
			t.Error("Wait called for a file that exists")
			return ctx.Err()
		})
		o.set([]byte("9222\r\n" + p))
		if _, err := pf.Read(testCtx(t)); !errors.Is(err, browser.ErrPortFile) {
			t.Errorf("Read(CRLF file) = %v, want ErrPortFile", err)
		}
		if n := o.openedCount(); n != 1 {
			t.Errorf("file opened %d times, want 1 (a bad file is never re-read)", n)
		}
	})

	t.Run("error never quotes the file", func(t *testing.T) {
		t.Parallel()
		const marker = "facto-port-file-marker"
		_, err := browser.ParseDevToolsActivePort([]byte("9222\n/devtools/browser/" + marker))
		if err == nil || strings.Contains(err.Error(), marker) {
			t.Errorf("ParseDevToolsActivePort error = %v, want ErrPortFile without the file content", err)
		}
	})
}

func TestPortFile_PathMustMatchBrowserGUID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		ok   bool
	}{
		{"guid", "/devtools/browser/" + testGUID, true},
		{"digits and dashes only", "/devtools/browser/" + strings.Repeat("0", 8) + "-" + strings.Repeat("1", 4) + "-" + strings.Repeat("2", 4) + "-" + strings.Repeat("3", 4) + "-" + strings.Repeat("4", 12), true},
		{"uppercase hex", "/devtools/browser/" + strings.ToUpper(testGUID), false},
		{"35 characters", "/devtools/browser/" + testGUID[:35], false},
		{"37 characters", "/devtools/browser/" + testGUID + "a", false},
		{"non-hex letter", "/devtools/browser/" + strings.Replace(testGUID, "f", "g", 1), false},
		{"braces", "/devtools/browser/{" + testGUID[1:35] + "}", false},
		{"percent encoded", "/devtools/browser/" + strings.Replace(testGUID, "-", "%2d", 1)[:36], false},
		{"dot segment", "/devtools/browser/../page/" + testGUID[:30], false},
		{"double slash", "//devtools/browser/" + testGUID, false},
		{"no leading slash", "devtools/browser/" + testGUID, false},
		{"uppercase prefix", "/DevTools/browser/" + testGUID, false},
		{"page kind", "/devtools/page/" + testGUID, false},
		{"json endpoint", "/json/version", false},
		{"trailing slash", "/devtools/browser/" + testGUID + "/", false},
		{"backslash", `\devtools\browser\` + testGUID, false},
		{"empty guid", "/devtools/browser/", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := browser.ParseDevToolsActivePort([]byte("9222\n" + tc.path))
			if tc.ok {
				if err != nil || got.Path != tc.path {
					t.Errorf("ParseDevToolsActivePort(path %q) = %+v, %v; want accepted", tc.path, got, err)
				}
				return
			}
			if !errors.Is(err, browser.ErrPortFile) {
				t.Errorf("ParseDevToolsActivePort(path %q) = %+v, %v; want ErrPortFile", tc.path, got, err)
			}
		})
	}
}

func TestPortFile_PreexistingFileRefused(t *testing.T) {
	t.Parallel()
	valid := []byte("9222\n" + testGUIDPath)

	t.Run("planted file on disk", func(t *testing.T) {
		t.Parallel()
		prof := emptyProfile(t)
		writeTestFile(t, prof, browser.PortFileName, valid)
		pf, err := browser.ArmPortFile(prof, browser.PortFileConfig{})
		if pf != nil || err == nil {
			t.Fatalf("ArmPortFile(profile with %s) = %v, %v; want refused", browser.PortFileName, pf, err)
		}
		if !errors.Is(err, browser.ErrPortFile) && !errors.Is(err, browser.ErrUnsafeProfileDir) {
			t.Errorf("ArmPortFile error = %v, want ErrPortFile or ErrUnsafeProfileDir", err)
		}
	})

	t.Run("profile not empty", func(t *testing.T) {
		t.Parallel()
		prof := emptyProfile(t)
		writeTestFile(t, prof, "Local State", []byte("{}"))
		if pf, err := browser.ArmPortFile(prof, browser.PortFileConfig{}); pf != nil || !errors.Is(err, browser.ErrUnsafeProfileDir) {
			t.Errorf("ArmPortFile(non-empty profile) = %v, %v; want nil, ErrUnsafeProfileDir", pf, err)
		}
	})

	t.Run("opener finds a file before start", func(t *testing.T) {
		t.Parallel()
		o := &portOpener{content: valid}
		if pf, err := browser.ArmPortFile(emptyProfile(t), browser.PortFileConfig{Open: o.open}); pf != nil || !errors.Is(err, browser.ErrPortFile) {
			t.Errorf("ArmPortFile(file opens before start) = %v, %v; want nil, ErrPortFile", pf, err)
		}
	})

	t.Run("opener fails otherwise before start", func(t *testing.T) {
		t.Parallel()
		o := &portOpener{err: fs.ErrPermission}
		if pf, err := browser.ArmPortFile(emptyProfile(t), browser.PortFileConfig{Open: o.open}); pf != nil || !errors.Is(err, browser.ErrPortFile) {
			t.Errorf("ArmPortFile(open denied) = %v, %v; want nil, ErrPortFile (fail closed)", pf, err)
		}
	})

	t.Run("relative or missing profile", func(t *testing.T) {
		t.Parallel()
		for _, prof := range []string{"", "profile", filepath.Join(t.TempDir(), "missing")} {
			if pf, err := browser.ArmPortFile(prof, browser.PortFileConfig{}); pf != nil || err == nil {
				t.Errorf("ArmPortFile(%q) = %v, %v; want refused", prof, pf, err)
			}
		}
	})

	t.Run("default opener reads only after arm", func(t *testing.T) {
		t.Parallel()
		prof := emptyProfile(t)
		pf, err := browser.ArmPortFile(prof, browser.PortFileConfig{Wait: func(ctx context.Context) error {
			writeTestFileCtx(ctx, t, prof, browser.PortFileName, valid)
			return ctx.Err()
		}})
		if err != nil {
			t.Fatalf("ArmPortFile(empty profile) = %v", err)
		}
		got, err := pf.Read(testCtx(t))
		if err != nil || got.Port != 9222 || got.Path != testGUIDPath {
			t.Errorf("Read = %+v, %v; want port 9222 and the GUID path", got, err)
		}
	})
}

func TestPortFile_OversizedRefused(t *testing.T) {
	t.Parallel()

	t.Run("parse over the cap", func(t *testing.T) {
		t.Parallel()
		// A valid prefix padded with newlines past the cap.
		data := []byte("9222\n" + testGUIDPath + "\n")
		data = append(data, bytes.Repeat([]byte("\n"), browser.MaxPortFileBytes)...)
		if _, err := browser.ParseDevToolsActivePort(data); !errors.Is(err, browser.ErrPortFile) {
			t.Errorf("ParseDevToolsActivePort(%d bytes) = %v, want ErrPortFile", len(data), err)
		}
	})

	t.Run("file of cap+1 bytes", func(t *testing.T) {
		t.Parallel()
		o := &portOpener{}
		pf := armed(t, o, immediateWait)
		o.set(bytes.Repeat([]byte("1"), browser.MaxPortFileBytes+1))
		if _, err := pf.Read(testCtx(t)); !errors.Is(err, browser.ErrPortFile) {
			t.Errorf("Read(%d-byte file) = %v, want ErrPortFile", browser.MaxPortFileBytes+1, err)
		}
	})

	t.Run("endless file read bounded", func(t *testing.T) {
		t.Parallel()
		r := &endlessPortFile{fill: '7'}
		o := &portOpener{}
		pf := armed(t, o, immediateWait)
		o.mu.Lock()
		o.reader = func() io.ReadCloser { return r }
		o.mu.Unlock()
		if _, err := pf.Read(testCtx(t)); !errors.Is(err, browser.ErrPortFile) {
			t.Errorf("Read(endless file) = %v, want ErrPortFile", err)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		// io.LimitReader(f, 257) may let one Read return up to its buffer;
		// anything past a small read buffer means the cap was not applied.
		if r.read > 4096 {
			t.Errorf("read %d bytes from an endless file, want at most a bounded read past %d", r.read, browser.MaxPortFileBytes)
		}
		if !r.closed {
			t.Error("port file left open")
		}
	})

	t.Run("cap exactly is accepted when well formed", func(t *testing.T) {
		t.Parallel()
		// "<port>\n<path>" is at most 5+1+54+1 bytes: always under the cap.
		data := []byte("65535\n" + testGUIDPath + "\n")
		if len(data) > browser.MaxPortFileBytes {
			t.Fatalf("fixture %d bytes over the cap", len(data))
		}
		if _, err := browser.ParseDevToolsActivePort(data); err != nil {
			t.Errorf("ParseDevToolsActivePort(well formed) = %v", err)
		}
	})
}
