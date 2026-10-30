//go:build unix

// Fake browser for the T7 pipe tests: this test binary, re-executed with
// FACTO_FAKE_BROWSER set, plays Chrome. It reads NUL-delimited JSON on fd 3
// and writes NUL-delimited JSON on fd 4, like --remote-debugging-pipe. The
// method of each request picks a behaviour (see serveCDP). It holds no secret
// and never prints a frame.
package browser_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/fsx"
)

const (
	fakeModeEnv = "FACTO_FAKE_BROWSER"
	// fakeStderrMarker is written to stderr by the fake at startup, to
	// prove StartPipe wires Command.Stderr.
	fakeStderrMarker = "fake-browser-started"
	// fakeLifetime bounds every helper process, so a failed test never
	// leaves one behind for long.
	fakeLifetime = 2 * time.Minute
	// fakeExitCorrupt is the fake's exit code when it reads a frame that is
	// not one whole JSON request (interleaved or split writes).
	fakeExitCorrupt = 9
)

// Fake modes.
const (
	modeCDP    = "cdp"    // serve CDP on fds 3/4
	modeDeaf   = "deaf"   // no I/O, wait for fakeLifetime (a grandchild, or a fake that ignores pipe EOF)
	modeParent = "parent" // start a deaf fake through StartPipe, print its pid, wait (parent-death test)
)

// Pool tests (T10): the fake also answers NewPage's setup, and writes into
// its --user-data-dir like Chrome does.
const (
	// fakePageEnv selects how the fake answers NewPage's setup.
	fakePageEnv = "FACTO_FAKE_PAGE"
	// pageFailContext: Target.createBrowserContext answers a CDP error.
	pageFailContext = "fail-context"
	// fakeProfileFile is written (0600) by the fake into
	// <user-data-dir>/Default at startup, before it answers anything.
	fakeProfileFile = "Default/Cookies"
	// fakeProfileLock is the dangling symlink Chrome keeps in its profile
	// (SingletonLock -> "<host>-<pid>").
	fakeProfileLock = "SingletonLock"
)

func TestMain(m *testing.M) {
	mode := os.Getenv(fakeModeEnv)
	if mode == "" {
		os.Exit(m.Run())
	}
	os.Exit(runFake(mode))
}

func runFake(mode string) int {
	switch mode {
	case modeCDP:
		return serveCDP()
	case modeDeaf:
		<-time.After(fakeLifetime)
		return 0
	case modeParent:
		return runParent()
	default:
		// Real-Chrome helper modes (chrome_e2e_linux_test.go); 2 when the
		// mode is unknown to this build.
		return runE2EMode(mode)
	}
}

// selfCommand is a Command that re-executes this test binary in mode.
func selfCommand(mode string, stderr io.Writer) (browser.Command, error) {
	exe, err := os.Executable()
	if err != nil {
		return browser.Command{}, fmt.Errorf("executable: %w", err)
	}
	return browser.Command{
		Path:   exe,
		Args:   []string{"--remote-debugging-pipe"},
		Env:    []string{fakeModeEnv + "=" + mode},
		Stderr: stderr,
	}, nil
}

// runParent starts a deaf fake browser through the real StartPipe, prints
// "pid=<n>" on stdout and waits to be killed.
func runParent() int {
	cmd, err := selfCommand(modeDeaf, io.Discard)
	if err != nil {
		return 3
	}
	p, err := browser.StartPipe(context.Background(), cmd)
	if err != nil {
		return 4
	}
	if _, err := fmt.Fprintf(os.Stdout, "pid=%d\n", p.Pid()); err != nil {
		return 5
	}
	<-time.After(fakeLifetime)
	return 0
}

type fakeRequest struct {
	ID        int64           `json:"id"`
	Method    string          `json:"method"`
	SessionID string          `json:"sessionId,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
}

// echoResult is what Fake.echo (and the held replies) answer.
type echoResult struct {
	Method    string          `json:"method"`
	SessionID string          `json:"sessionId"`
	Params    json.RawMessage `json:"params"`
	Raw       []byte          `json:"raw"`   // the frame as read, without its NUL
	Frame     int             `json:"frame"` // frames read so far, this one included
}

func frame(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // helper process only: a bug in the fake itself
	}
	return append(b, 0)
}

func serveCDP() int {
	in, out := os.NewFile(3, "cdp-in"), os.NewFile(4, "cdp-out")
	if in == nil || out == nil {
		return 10
	}
	if _, err := io.WriteString(os.Stderr, fakeStderrMarker+"\n"); err != nil {
		return 11
	}
	go func() { <-time.After(fakeLifetime); os.Exit(12) }()
	if err := populateProfile(os.Args[1:]); err != nil {
		return 14
	}
	failContext := os.Getenv(fakePageEnv) == pageFailContext

	r := bufio.NewReader(in)
	var held, flush []byte // Fake.hold replies; the pending Fake.flush reply
	heldN, flushWant, frames := 0, 0, 0
	for {
		raw, err := r.ReadBytes(0)
		if err != nil {
			return 0 // pipe closed: exit like Chrome
		}
		raw = raw[:len(raw)-1]
		frames++
		var req fakeRequest
		if !json.Valid(raw) || json.Unmarshal(raw, &req) != nil || req.ID <= 0 || req.Method == "" {
			return fakeExitCorrupt
		}
		reply := func(result any) []byte {
			m := map[string]any{"id": req.ID, "result": result}
			if req.SessionID != "" {
				m["sessionId"] = req.SessionID
			}
			return frame(m)
		}
		echo := echoResult{Method: req.Method, SessionID: req.SessionID, Params: req.Params, Raw: raw, Frame: frames}
		var p struct {
			Text     string `json:"text"`
			Size     int    `json:"size"`
			HoldPipe bool   `json:"holdPipe"`
		}
		_ = json.Unmarshal(req.Params, &p)

		var w []byte
		switch req.Method {
		case "Fake.echo":
			w = reply(echo)
		case "Fake.splitReply":
			// One write per byte: the client must reassemble.
			for _, b := range reply(echo) {
				if _, err := out.Write([]byte{b}); err != nil {
					return 0
				}
			}
		case "Fake.hold":
			held = append(held, reply(echo)...)
			heldN++
		case "Fake.flush":
			// Once p.Size replies are held: every held reply (in arrival
			// order, not call order), an event and this reply, in a single
			// write.
			flush, flushWant = reply(echo), p.Size
		case "Fake.oversize":
			// One message of p.Size bytes (text repeated), then the NUL.
			head := `{"id":` + strconv.FormatInt(req.ID, 10) + `,"result":"`
			fill := p.Text
			if fill == "" {
				fill = "a"
			}
			body := []byte(head)
			for len(body) < p.Size-2 {
				body = append(body, fill...)
			}
			body = append(body, `"}`...)
			body = append(body, 0)
			if _, err := out.Write(body); err != nil {
				return 0
			}
		case "Fake.garbage":
			w = append([]byte("not json "+p.Text+"\x00"), reply(map[string]any{"after": "garbage"})...)
		case "Fake.cdpError":
			e := map[string]any{"id": req.ID, "error": map[string]any{"code": -32000, "message": p.Text, "data": p.Text}}
			if req.SessionID != "" {
				e["sessionId"] = req.SessionID
			}
			w = frame(e)
		case "Fake.unknown":
			other := "SESSION-OTHER"
			w = frame(map[string]any{"id": 999_999, "result": map[string]any{"x": "wrong-id"}})
			w = append(w, frame(map[string]any{"id": req.ID, "sessionId": other, "result": map[string]any{"x": "wrong-session"}})...)
			if req.SessionID != "" {
				w = append(w, frame(map[string]any{"id": req.ID, "result": map[string]any{"x": "missing-session"}})...)
			}
			w = append(w, frame(map[string]any{"method": "Target.targetCreated", "params": map[string]any{"x": "event"}})...)
			w = append(w, reply(map[string]any{"x": "right"})...)
			w = append(w, reply(map[string]any{"x": "late-duplicate"})...)
		case "Fake.spawnChild":
			pid, err := spawnDeaf(p.HoldPipe, in, out)
			if err != nil {
				return 13
			}
			w = reply(map[string]any{"pid": pid})
		case "Fake.exit":
			return 3
		case "Fake.hang":
			// Never answer.
		// NewPage's setup (pool tests).
		case "Target.createBrowserContext":
			if failContext {
				w = frame(map[string]any{"id": req.ID, "error": map[string]any{"code": -32000, "message": "scripted failure"}})
			} else {
				w = reply(map[string]any{"browserContextId": "ctx-pipe-1"})
			}
		case "Target.createTarget":
			w = reply(map[string]any{"targetId": "tgt-pipe-1"})
		case "Target.attachToTarget":
			w = reply(map[string]any{"sessionId": "sess-pipe-1"})
		// Fetch.enable and Target.setAutoAttach: NewPage's in-browser
		// allowlist steps (T9).
		case "Browser.setDownloadBehavior", "Page.enable", "Target.disposeBrowserContext",
			"Fetch.enable", "Target.setAutoAttach":
			w = reply(map[string]any{})
		default:
			w = frame(map[string]any{"id": req.ID, "error": map[string]any{"code": -32601, "message": "method not found"}})
		}
		if flush != nil && heldN >= flushWant {
			w = append(w, held...)
			w = append(w, frame(map[string]any{"method": "Page.loadEventFired", "params": map[string]any{"timestamp": 1}})...)
			w = append(w, flush...)
			held, heldN, flush = nil, 0, nil
		}
		if len(w) > 0 {
			if _, err := out.Write(w); err != nil {
				return 0
			}
		}
	}
}

// populateProfile writes into the --user-data-dir found in args (if any) what
// Chrome leaves in a profile: a nested file and a dangling SingletonLock
// symlink. Without the switch it does nothing (pipe tests).
func populateProfile(args []string) error {
	var dir string
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--user-data-dir="); ok {
			dir = v
		}
	}
	if dir == "" {
		return nil
	}
	r, err := fsx.Open(dir)
	if err != nil {
		return fmt.Errorf("open profile: %w", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.MkdirPrivate("Default"); err != nil {
		return fmt.Errorf("profile subdir: %w", err)
	}
	if err := r.WriteAtomic(context.Background(), fakeProfileFile, []byte("fake cookie store")); err != nil {
		return fmt.Errorf("profile file: %w", err)
	}
	if err := os.Symlink("fakehost-"+strconv.Itoa(os.Getpid()), filepath.Join(dir, fakeProfileLock)); err != nil {
		return fmt.Errorf("profile lock: %w", err)
	}
	return nil
}

// spawnDeaf starts a deaf grandchild in the fake's process group. With
// holdPipe it inherits both CDP pipe ends and the fake's stderr, as Chrome's
// own children may.
func spawnDeaf(holdPipe bool, in, out *os.File) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("executable: %w", err)
	}
	c := exec.CommandContext(context.Background(), exe) //nolint:gosec // re-executes this test binary
	c.Env = []string{fakeModeEnv + "=" + modeDeaf}
	if holdPipe {
		c.ExtraFiles = []*os.File{in, out}
		c.Stderr = os.Stderr
	}
	if err := c.Start(); err != nil {
		return 0, fmt.Errorf("start grandchild: %w", err)
	}
	go func() { _ = c.Wait() }()
	return c.Process.Pid, nil
}

// readPidLine parses the "pid=<n>" line printed by runParent.
func readPidLine(r io.Reader) (int, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("read pid line: %w", err)
	}
	v, ok := strings.CutPrefix(strings.TrimSpace(line), "pid=")
	if !ok {
		return 0, fmt.Errorf("unexpected line %q", bytes.TrimSpace([]byte(line)))
	}
	pid, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("parse pid: %w", err)
	}
	return pid, nil
}
