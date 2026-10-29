//go:build linux

package browser_test

import (
	"bytes"
	"os"
	"strconv"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// TestStartPipe_EnvIsExactlyCommandEnv: the browser gets Command.Env and
// nothing of facto's own environment (os/exec would inherit it for a nil
// Env). Read from /proc while the fake serves.
func TestStartPipe_EnvIsExactlyCommandEnv(t *testing.T) {
	t.Setenv("FACTO_T7_PROBE", "must-not-leak")
	cmd, err := selfCommand(modeCDP, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := browser.StartPipe(t.Context(), cmd)
	if err != nil {
		t.Fatalf("StartPipe: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if _, err := call(t, p.Client(), "", "Fake.echo", nil); err != nil {
		t.Fatalf("Call: %v", err)
	}
	env, err := os.ReadFile("/proc/" + strconv.Itoa(p.Pid()) + "/environ")
	if err != nil {
		t.Fatalf("read environ: %v", err)
	}
	want := []byte(fakeModeEnv + "=" + modeCDP + "\x00")
	if !bytes.Equal(env, want) {
		t.Errorf("browser environment = %q, want exactly %q", env, want)
	}
}
