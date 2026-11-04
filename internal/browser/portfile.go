package browser

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/FlorianRuen/facto/internal/fsx"
)

// Windows port-0 transport, platform-neutral part (ADR 0008 "Windows (A4)",
// decision A4, plan J1 T7c). Chrome is started with
// --remote-debugging-port=0 and writes the port it picked, and the browser
// WebSocket path, to <profile>/DevToolsActivePort. That file is not trusted:
// it is read only after the start, from a profile proven empty before it,
// capped and parsed strictly; the listener on that port must then be the
// started browser, bound to 127.0.0.1 only, and answer a Browser.getVersion
// handshake before any other message (and so any secret) is sent.

// PortFileName is the file Chrome writes in --user-data-dir once its
// DevTools listener is up.
const PortFileName = "DevToolsActivePort"

// MaxPortFileBytes caps the port file (ADR 0008: at most 256 bytes).
const MaxPortFileBytes = 256

// portFilePoll is the default pause between two reads of a port file not
// written yet.
const portFilePoll = 50 * time.Millisecond

// devToolsBrowserPrefix starts the only WebSocket path accepted: the browser
// target, never a page.
const devToolsBrowserPrefix = "/devtools/browser/"

// guidLen is the length of the browser GUID in the WebSocket path.
const guidLen = 36

// Windows port-0 sentinel errors, errors.Is targets. Their messages never
// quote the port file nor anything the peer sent.
var (
	// ErrPortFile: DevToolsActivePort is malformed, oversized, present
	// before the browser started, not a regular file, or unreadable.
	ErrPortFile = errors.New("browser: bad DevToolsActivePort file")
	// ErrListenerNotBrowser: the socket listening on the CDP port is not
	// owned by the started browser, is not bound to 127.0.0.1 only, or the
	// owner lookup failed (fail closed).
	ErrListenerNotBrowser = errors.New("browser: cdp port listener is not the browser")
	// ErrHandshake: the Browser.getVersion handshake failed.
	ErrHandshake = errors.New("browser: cdp handshake failed")
	// ErrNoHandshake: a message was sent or read on a PortTransport before
	// its handshake succeeded. Nothing reached the browser.
	ErrNoHandshake = errors.New("browser: cdp handshake not done")
)

// DevToolsTarget is a parsed DevToolsActivePort.
type DevToolsTarget struct {
	Port int    // 1..65535
	Path string // ^/devtools/browser/[0-9a-f-]{36}$
}

// valid reports whether t would be accepted by ParseDevToolsActivePort.
func (t DevToolsTarget) valid() bool {
	return t.Port >= 1 && t.Port <= 65535 && browserGUIDPath(t.Path)
}

// ParseDevToolsActivePort accepts exactly "<port>\n<path>" with an optional
// single trailing "\n": the port in decimal ASCII digits, no sign, no
// leading zero, 1..65535; the path matching ^/devtools/browser/[0-9a-f-]{36}$.
// Anything else (CR anywhere, NUL, BOM, spaces, extra or empty lines, more
// than MaxPortFileBytes) is ErrPortFile. Errors never quote the file.
func ParseDevToolsActivePort(data []byte) (DevToolsTarget, error) {
	if len(data) > MaxPortFileBytes {
		return DevToolsTarget{}, fmt.Errorf("%w: over %d bytes", ErrPortFile, MaxPortFileBytes)
	}
	s := strings.TrimSuffix(string(data), "\n")
	portStr, path, ok := strings.Cut(s, "\n")
	if !ok {
		return DevToolsTarget{}, fmt.Errorf("%w: want two lines", ErrPortFile)
	}
	port, ok := parsePortLine(portStr)
	if !ok {
		return DevToolsTarget{}, fmt.Errorf("%w: malformed port line", ErrPortFile)
	}
	if !browserGUIDPath(path) {
		return DevToolsTarget{}, fmt.Errorf("%w: path is not a browser target", ErrPortFile)
	}
	return DevToolsTarget{Port: port, Path: path}, nil
}

// parsePortLine parses 1..65535 written in ASCII digits, without sign or
// leading zero.
func parsePortLine(s string) (int, bool) {
	if s == "" || len(s) > 5 || s[0] == '0' {
		return 0, false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, false
	}
	return p, true
}

// browserGUIDPath reports whether p is /devtools/browser/ followed by
// exactly 36 characters among [0-9a-f-].
func browserGUIDPath(p string) bool {
	guid, ok := strings.CutPrefix(p, devToolsBrowserPrefix)
	if !ok || len(guid) != guidLen {
		return false
	}
	for i := range len(guid) {
		c := guid[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && c != '-' {
			return false
		}
	}
	return true
}

// PortFileConfig holds the PortFile seams.
type PortFileConfig struct {
	// Open opens a path for reading. Nil: open under the profile without
	// following a symlink (fsx). fs.ErrNotExist means "not written yet".
	Open func(path string) (io.ReadCloser, error)
	// Wait pauses between two attempts while the file is missing and
	// returns ctx's error when ctx ends. Nil: a short timer.
	Wait func(ctx context.Context) error
}

// PortFile is the DevToolsActivePort of one fresh profile, armed before the
// browser started.
type PortFile struct {
	path string
	open func(path string) (io.ReadCloser, error)
	wait func(ctx context.Context) error
}

// ArmPortFile runs BEFORE the browser starts. profile must be an absolute,
// existing, empty directory (a fresh MkdirTemp profile, not a symlink): any
// entry in it is ErrUnsafeProfileDir. Opening <profile>/DevToolsActivePort
// must then fail with fs.ErrNotExist: a file that opens (planted, symlink or
// not) or any other error is ErrPortFile.
func ArmPortFile(profile string, cfg PortFileConfig) (*PortFile, error) {
	if profile == "" || !filepath.IsAbs(profile) || filepath.Clean(profile) != profile {
		return nil, fmt.Errorf("%w: profile must be an absolute clean path", ErrUnsafeProfileDir)
	}
	if err := checkEmptyDir(profile); err != nil {
		return nil, err
	}
	pf := &PortFile{path: filepath.Join(profile, PortFileName), open: cfg.Open, wait: cfg.Wait}
	if pf.open == nil {
		pf.open = openNoFollow
	}
	if pf.wait == nil {
		pf.wait = pollWait
	}
	rc, err := pf.open(pf.path)
	switch {
	case err == nil:
		_ = rc.Close() // read-only; the planted file is the error
		return nil, fmt.Errorf("%w: present before the browser started", ErrPortFile)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%w: probe before start: %w", ErrPortFile, err)
	}
	return pf, nil
}

// checkEmptyDir requires dir to be a real directory (not a symlink) holding
// no entry.
func checkEmptyDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeProfileDir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: profile is not a real directory", ErrUnsafeProfileDir)
	}
	r, err := fsx.Open(dir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeProfileDir, err)
	}
	ents, err := r.ReadDir()
	_ = r.Close() // read-only root
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeProfileDir, err)
	}
	if len(ents) != 0 {
		return fmt.Errorf("%w: profile not empty before the browser started", ErrUnsafeProfileDir)
	}
	return nil
}

// openNoFollow opens path, a regular file, without following a symlink
// (fsx.Root.OpenRegular). A missing file wraps fs.ErrNotExist.
func openNoFollow(path string) (io.ReadCloser, error) {
	r, err := fsx.Open(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("open port file: %w", err)
	}
	defer func() { _ = r.Close() }() // the opened file outlives its root
	f, err := r.OpenRegular(filepath.Base(path))
	if err != nil {
		return nil, fmt.Errorf("open port file: %w", err)
	}
	return f, nil
}

// pollWait pauses portFilePoll or until ctx ends.
func pollWait(ctx context.Context) error {
	t := time.NewTimer(portFilePoll)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for port file: %w", ctx.Err())
	}
}

// Read runs AFTER the browser started. It opens the port file; while it is
// missing (fs.ErrNotExist) it waits and retries, until ctx ends. Once the
// file opens it reads at most MaxPortFileBytes+1 bytes, closes it and parses
// it once: over the cap, malformed or unreadable is ErrPortFile, never
// retried.
func (p *PortFile) Read(ctx context.Context) (DevToolsTarget, error) {
	for {
		if err := ctx.Err(); err != nil {
			return DevToolsTarget{}, fmt.Errorf("read port file: %w", err)
		}
		rc, err := p.open(p.path)
		if errors.Is(err, fs.ErrNotExist) {
			if werr := p.wait(ctx); werr != nil {
				return DevToolsTarget{}, fmt.Errorf("read port file: %w", werr)
			}
			continue
		}
		if err != nil {
			return DevToolsTarget{}, fmt.Errorf("%w: open: %w", ErrPortFile, err)
		}
		data, rerr := io.ReadAll(io.LimitReader(rc, MaxPortFileBytes+1))
		_ = rc.Close() // read-only
		if rerr != nil {
			return DevToolsTarget{}, fmt.Errorf("%w: read: %w", ErrPortFile, rerr)
		}
		return ParseDevToolsActivePort(data)
	}
}
