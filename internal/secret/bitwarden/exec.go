package bitwarden

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// waitDelay bounds how long Run waits for the output pipes once the process
// exited or was killed (a grandchild keeping them open).
const waitDelay = 5 * time.Second

// ExecRunner runs the bw binary as a subprocess with a minimal environment:
// only a fixed list of non-secret variables (HOME, PATH, the bw data
// directory…) is inherited, never BW_SESSION, BW_PASSWORD or NODE_OPTIONS;
// Command.Env is added on top; BW_NOINTERACTION=true keeps bw from
// prompting. Stdin is empty. Secrets never reach argv.
type ExecRunner struct {
	// Path is the bw binary: an absolute path, or a name looked up in PATH
	// (for example "bw"). Required.
	Path string
}

var _ Runner = ExecRunner{}

// Run starts bw and waits for it. ctx cancellation kills the process.
func (r ExecRunner) Run(ctx context.Context, cmd Command) error {
	if r.Path == "" {
		return errors.New("bitwarden: ExecRunner.Path is empty")
	}
	env, err := buildEnv(os.LookupEnv, cmd)
	if err != nil {
		return err
	}
	// Path is facto's own bw binary setting and Args are fixed subcommands
	// plus a validated UUID built by Provider; no shell is involved.
	c := exec.CommandContext(ctx, r.Path, cmd.Args...) // #nosec G204 -- trusted path and argv, see above (J0-T19, no GitHub issue yet)
	c.Env = env
	c.Stdout = cmd.Stdout
	c.Stderr = cmd.Stderr
	c.WaitDelay = waitDelay
	if err := c.Run(); err != nil {
		return fmt.Errorf("bitwarden: run bw: %w", err)
	}
	return nil
}

// inherited lists the variables passed from facto's environment to bw. None
// of them holds a secret.
func inherited() []string {
	return []string{
		"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TZ", "TMPDIR",
		"XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "BITWARDENCLI_APPDATA_DIR",
		"NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR",
		// Windows.
		"SYSTEMROOT", "WINDIR", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP",
	}
}

// buildEnv returns the subprocess environment. Command.Env names must be
// environment variable names; they override inherited values.
func buildEnv(lookup func(string) (string, bool), cmd Command) ([]string, error) {
	env := []string{"BW_NOINTERACTION=true"}
	for _, k := range inherited() {
		if _, override := cmd.Env[k]; override {
			continue
		}
		if v, ok := lookup(k); ok {
			env = append(env, k+"="+v)
		}
	}
	for k, v := range cmd.Env {
		if !isEnvName(k) || k == "BW_NOINTERACTION" {
			return nil, errors.New("bitwarden: invalid subprocess environment variable name")
		}
		env = append(env, k+"="+v.Expose())
	}
	return env, nil
}

// isEnvName reports whether s matches [A-Za-z_][A-Za-z0-9_]*.
func isEnvName(s string) bool {
	if s == "" || ('0' <= s[0] && s[0] <= '9') {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}
