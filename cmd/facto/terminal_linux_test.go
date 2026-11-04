// Tests of the termios no-echo read on a real pseudo-terminal (J1 task
// T19): what the user types is never echoed, echo comes back afterwards,
// and a run canceled at the prompt leaves echo on. Synthetic input only.
package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// openPTY returns the master and the slave of a new pseudo-terminal, closed at the end of the test.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	mfd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open ptmx: %v", err)
	}
	if err := unix.IoctlSetPointerInt(mfd, unix.TIOCSPTLCK, 0); err != nil {
		_ = unix.Close(mfd)
		t.Fatalf("unlock pty: %v", err)
	}
	n, err := unix.IoctlGetUint32(mfd, unix.TIOCGPTN)
	if err != nil {
		_ = unix.Close(mfd)
		t.Fatalf("pty number: %v", err)
	}
	sfd, err := unix.Open("/dev/pts/"+strconv.FormatUint(uint64(n), 10), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(mfd)
		t.Fatalf("open pty slave: %v", err)
	}
	master, slave = os.NewFile(uintptr(mfd), "ptmx"), os.NewFile(uintptr(sfd), "pts")
	t.Cleanup(func() {
		_ = slave.Close()
		_ = master.Close()
	})
	return master, slave
}

// readUntil reads the master side until marker appears and returns
// everything read before it.
func readUntil(t *testing.T, master *os.File, marker string) string {
	t.Helper()
	var out bytes.Buffer
	buf := make([]byte, 256)
	for !strings.Contains(out.String(), marker) {
		n, err := master.Read(buf)
		out.Write(buf[:n])
		if err != nil {
			t.Fatalf("read pty master: %v", err)
		}
	}
	before, _, _ := strings.Cut(out.String(), marker)
	return before
}

// echoOn reports whether ECHO is set on f.
func echoOn(t *testing.T, f *os.File) bool {
	t.Helper()
	tio, err := unix.IoctlGetTermios(int(f.Fd()), ioctlGetTermios)
	if err != nil {
		t.Fatalf("get termios: %v", err)
	}
	return tio.Lflag&unix.ECHO != 0
}

func TestOSTerminal_NoEchoOnPTY(t *testing.T) {
	t.Parallel()
	master, slave := openPTY(t)
	code := testsecrets.Canary(t, testsecrets.Token)
	term := &osTerminal{}
	if !term.IsTerminal(slave) || !echoOn(t, slave) {
		t.Fatal("the pty slave is not a terminal with echo on")
	}

	// Control: a plain read on the same terminal echoes, so the check
	// below is not vacuous.
	if _, err := master.WriteString("synthetic-visible\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := readSecretLine(slave); err != nil {
		t.Fatalf("plain read: %v", err)
	}
	readUntil(t, master, "synthetic-visible") // the control line is echoed

	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := term.ReadNoEcho(slave)
		done <- result{b, err}
	}()
	// The user types once echo is off.
	for echoOn(t, slave) {
		runtime.Gosched()
	}
	if _, err := master.WriteString(code + "\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	res := <-done
	if res.err != nil {
		t.Fatalf("ReadNoEcho: %v", res.err)
	}
	if string(res.b) != code {
		t.Errorf("ReadNoEcho returned another value than the typed code")
	}
	if !echoOn(t, slave) {
		t.Errorf("echo not restored after the read")
	}
	// Echo is back on: the marker is echoed, and anything echoed during
	// the no-echo read comes before it.
	if _, err := master.WriteString("synthetic-marker\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if strings.Contains(readUntil(t, master, "synthetic-marker"), code) {
		t.Errorf("the code was echoed to the terminal")
	}
}

func TestPrompt_CanceledAtTerminalRestoresEcho(t *testing.T) {
	t.Parallel()
	master, slave := openPTY(t)
	e := newSandbox(t).env()
	term := &osTerminal{}
	e.Terminal = term
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	type result struct {
		zero bool
		err  error
	}
	done := make(chan result, 1)
	p := newPrompter(e, slave, &bytes.Buffer{}, false)
	go func() {
		got, err := p.Prompt(ctx, connector.PromptRequest{Label: "Code"})
		done <- result{got.IsZero(), err}
	}()
	// Cancel only once the read has turned echo off: the abort must turn
	// it back on.
	for echoOn(t, slave) {
		runtime.Gosched()
	}
	cancel()
	res := <-done
	if !errors.Is(res.err, context.Canceled) || !res.zero {
		t.Fatalf("Prompt = (zero %v, %v), want context.Canceled and no value", res.zero, res.err)
	}
	if !echoOn(t, slave) {
		t.Errorf("echo left off after a canceled prompt")
	}
	if _, err := term.ReadNoEcho(slave); !errors.Is(err, errAborted) {
		t.Errorf("ReadNoEcho after abort: %v, want errAborted", err)
	}
	// Release the read still blocked on the terminal.
	_, _ = master.WriteString("synthetic\n")
}
