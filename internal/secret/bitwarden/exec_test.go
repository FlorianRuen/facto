package bitwarden_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/bitwarden"
)

// helperEnv switches the test binary into a fake bw that prints its argv and
// environment as JSON. ExecRunner does not inherit it: tests pass it through
// Command.Env. The real bw binary is never executed.
const (
	helperEnv     = "FACTO_TEST_FAKE_BW"
	helperExitEnv = "FACTO_TEST_FAKE_BW_EXIT"
)

type helperReport struct {
	Args []string `json:"args"`
	Env  []string `json:"env"`
}

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		_ = json.NewEncoder(os.Stdout).Encode(helperReport{Args: os.Args[1:], Env: os.Environ()})
		code, _ := strconv.Atoi(os.Getenv(helperExitEnv))
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func selfRunner(t *testing.T) bitwarden.ExecRunner {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return bitwarden.ExecRunner{Path: exe}
}

func runHelper(ctx context.Context, t *testing.T, env map[string]secret.Secret, args ...string) (helperReport, error) {
	t.Helper()
	if env == nil {
		env = map[string]secret.Secret{}
	}
	env[helperEnv] = secret.FromString("1")
	var stdout, stderr bytes.Buffer
	err := selfRunner(t).Run(ctx, bitwarden.Command{Args: args, Env: env, Stdout: &stdout, Stderr: &stderr})
	var rep helperReport
	if stdout.Len() > 0 {
		if jerr := json.Unmarshal(stdout.Bytes(), &rep); jerr != nil {
			t.Fatalf("helper output: %v", jerr)
		}
	}
	return rep, err
}

func envMap(kvs []string) map[string]string {
	m := map[string]string{}
	for _, kv := range kvs {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

// Not parallel: t.Setenv.
func TestExecRunner_MinimalEnvironment(t *testing.T) {
	t.Setenv("BW_SESSION", "synthetic-parent-session")
	t.Setenv("BW_PASSWORD", "synthetic-parent-password")
	t.Setenv("NODE_OPTIONS", "--require=/synthetic/inject.js")
	t.Setenv("FACTO_UNLISTED", "synthetic")
	t.Setenv("HOME", "/synthetic/home")

	rep, err := runHelper(t.Context(), t, map[string]secret.Secret{
		"FACTO_BW_MASTER_PASSWORD": secret.FromString("synthetic-master"),
		"HOME":                     secret.FromString("/synthetic/override"),
	}, "unlock", "--raw", "--passwordenv", "FACTO_BW_MASTER_PASSWORD")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if want := []string{"unlock", "--raw", "--passwordenv", "FACTO_BW_MASTER_PASSWORD"}; !slices.Equal(rep.Args, want) {
		t.Errorf("argv = %q, want %q", rep.Args, want)
	}
	env := envMap(rep.Env)
	for _, k := range []string{"BW_SESSION", "BW_PASSWORD", "NODE_OPTIONS", "FACTO_UNLISTED"} {
		if v, ok := env[k]; ok {
			t.Errorf("%s inherited by the subprocess (%d bytes)", k, len(v))
		}
	}
	for k, want := range map[string]string{
		"FACTO_BW_MASTER_PASSWORD": "synthetic-master",
		"HOME":                     "/synthetic/override",
		"BW_NOINTERACTION":         "true",
		"PATH":                     os.Getenv("PATH"),
	} {
		if got := env[k]; got != want {
			t.Errorf("subprocess %s = %q, want %q", k, got, want)
		}
	}
	if n := strings.Count(strings.Join(rep.Env, "\n"), "HOME="); n != 1 {
		t.Errorf("HOME set %d times, want 1", n)
	}
	// The parent environment is untouched.
	if _, ok := os.LookupEnv("FACTO_BW_MASTER_PASSWORD"); ok {
		t.Error("master password variable set in the parent process")
	}
}

func TestExecRunner_Errors(t *testing.T) {
	t.Parallel()

	t.Run("exit status", func(t *testing.T) {
		t.Parallel()
		_, err := runHelper(t.Context(), t, map[string]secret.Secret{helperExitEnv: secret.FromString("3")}, "status")
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
			t.Fatalf("Run error = %v, want exit status 3", err)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := runHelper(ctx, t, nil, "status"); !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want context.Canceled", err)
		}
	})

	t.Run("invalid env name", func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{"", "1X", "A=B", "A B", "BW_NOINTERACTION"} {
			_, err := runHelper(t.Context(), t, map[string]secret.Secret{name: secret.FromString("synthetic")}, "status")
			if err == nil {
				t.Errorf("env name %q accepted", name)
			}
		}
	})

	t.Run("empty path", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		err := bitwarden.ExecRunner{}.Run(t.Context(), bitwarden.Command{Args: []string{"status"}, Stdout: &out, Stderr: &out})
		if err == nil {
			t.Fatal("Run with an empty Path: nil error")
		}
	})
}

// The provider surfaces the exit code of a real subprocess, never its output.
func TestExecRunner_ThroughProvider(t *testing.T) {
	t.Parallel()
	runner := envRunner{inner: selfRunner(t), env: map[string]string{helperEnv: "1", helperExitEnv: "2"}}
	p := newProvider(t, bitwarden.Options{Runner: runner})
	_, err := p.Resolve(t.Context(), bwRef("password"))
	if err == nil || !strings.Contains(err.Error(), "exit status 2") {
		t.Fatalf("Resolve error = %v, want it to mention exit status 2", err)
	}
	if strings.Contains(err.Error(), "args") {
		t.Errorf("subprocess output leaked into the error: %v", err)
	}
}

// envRunner adds fixed variables to every command.
type envRunner struct {
	inner bitwarden.Runner
	env   map[string]string
}

func (r envRunner) Run(ctx context.Context, cmd bitwarden.Command) error {
	env := map[string]secret.Secret{}
	for k, v := range cmd.Env {
		env[k] = v
	}
	for k, v := range r.env {
		env[k] = secret.FromString(v)
	}
	cmd.Env = env
	return r.inner.Run(ctx, cmd)
}
