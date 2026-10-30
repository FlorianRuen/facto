// Tests for `facto login <id>` (J1 task T19; docs/spec.md "Commands":
// "Interactive login, visible browser window when needed"; decisions A3,
// A6, A8, A12, A13). Every test injects the key backend, the browser pool,
// the terminal, the secret resolver and the connector catalog: none reaches
// the OS keyring, a real browser, the network or the real terminal. All
// values are synthetic (testsecrets canaries).
//
// Expected API (implementer: follow exactly; package main):
//
//	// terminal is the controlling-terminal seam: the J0 isTerminal check
//	// plus a no-echo line read.
//	type terminal interface {
//		// IsTerminal reports whether r is an interactive terminal
//		// (isTerminal in production).
//		IsTerminal(r io.Reader) bool
//		// ReadNoEcho reads one line from r with terminal echo off and
//		// returns it without its line terminator. The caller owns the
//		// bytes (wraps them in a secret.Secret).
//		ReadNoEcho(r io.Reader) ([]byte, error)
//	}
//
//	// env gains (nil = production behaviour; every one is a test seam):
//	//	Terminal terminal
//	//	// KeyBackend returns the session key backend. Nil = the OS keyring
//	//	// (keyring.New(keyring.System())), probed once; an error means "no
//	//	// keyring": vault.Options{Keyring: nil, KeyringErr: err}, i.e.
//	//	// ephemeral sessions and one warning (A3). The e2e build may add
//	//	// the e2ekey file source here (T22); the release build never.
//	//	KeyBackend func(ctx context.Context, e env) (vault.KeyBackend, error)
//	//	// NewPool builds the run's browser pool; nil = newBrowserPool.
//	//	NewPool func(ctx context.Context, e env, p poolParams) (browserPool, error)
//	//	// Connectors returns every connector this build ships; nil =
//	//	// availableConnectors.
//	//	Connectors func() (*connector.Registry, error)
//	//	// InstalledBrowser returns the Chrome installed by `facto browser
//	//	// install` (T12); nil = that install location ("", false until
//	//	// T12 lands).
//	//	InstalledBrowser func(e env) (string, bool)
//
//	// browserPool is what the CLI needs from the pool; *browser.Pool
//	// satisfies it.
//	type browserPool interface {
//		connector.BrowserPool
//		Close() error
//	}
//
//	// poolParams are the inputs of one pool.
//	type poolParams struct {
//		StateDir    string       // cfg.StateDir (A12 fallback base <state>/tmp)
//		Executable  string       // resolveBrowserPath; "" in collect when none
//		Interactive bool         // true for `facto login` only (A6)
//		Log         *slog.Logger // the run's redacting logger
//	}
//
//	// newBrowserPool is browser.NewPool(ctx, browser.PoolConfig{Host:
//	// browser.Host{Executable: p.Executable, Geteuid: os.Geteuid,
//	// LookupEnv: e.LookupEnv, Log: p.Log}, StateDir: p.StateDir,
//	// Interactive: p.Interactive}). NewPool sweeps stale profiles (A12).
//	func newBrowserPool(ctx context.Context, e env, p poolParams) (browserPool, error)
//
//	// resolveBrowserPath: browser.path when set (must name an existing
//	// regular file, symlinks followed; otherwise an error wrapping
//	// config.ErrInvalid that names "browser.path" and never quotes the
//	// path); else installed(); else an error wrapping errNoBrowser whose
//	// message names both "facto browser install" and "browser.path".
//	func resolveBrowserPath(cfg *config.Config, installed func() (string, bool)) (string, error)
//	var errNoBrowser = errors.New(...)
//
//	// sessionMode maps cfg.Sessions to vault.Persistent / vault.Ephemeral;
//	// any other value is an error.
//	func sessionMode(cfg *config.Config) (vault.Mode, error)
//
//	// registerTestConnectors is nil in every build but -tags e2e, where a
//	// //go:build e2e file of this package sets it to fakeprovider.Register
//	// (the release build never links connectors/fakeprovider;
//	// `make release-e2e-check` must still pass).
//	var registerTestConnectors func(r *connector.Registry) error
//	// availableConnectors returns a new registry of the connectors this
//	// build ships: none in a release build, fakeprovider in an e2e build.
//	func availableConnectors() (*connector.Registry, error)
//
//	// e2eInteractiveEnv enables stdin prompts in e2e builds (A8).
//	const e2eInteractiveEnv = "FACTO_E2E_INTERACTIVE"
//
//	// newPrompter returns the connector.Prompter of a command:
//	//  - nonInteractive (flag) → non-interactive;
//	//  - terminal.IsTerminal(stdin) → interactive, answers read with
//	//    ReadNoEcho;
//	//  - e2e build and LookupEnv(e2eInteractiveEnv) == "1" → interactive,
//	//    answers read as plain lines from stdin (A8); a release build
//	//    never reads the variable's effect;
//	//  - otherwise non-interactive.
//	// Prompt writes req.CleanLabel() (never req.Label) and ": " to out
//	// (stderr), reads one answer, trims surrounding white space and
//	// returns it as a secret.Secret; the answer is never written anywhere.
//	// A non-interactive Prompt writes and reads nothing and returns an
//	// error wrapping connector.ErrNeedsLogin. A done ctx returns ctx.Err()
//	// (wrapped) without reading. End of input is an error with a zero
//	// Secret.
//	func newPrompter(e env, stdin io.Reader, out io.Writer, nonInteractive bool) connector.Prompter
//
//	// orchestrator.Deps gains:
//	//	Prompt connector.Prompter // copied into Env.Prompt; Env.Interactive = Prompt.Interactive()
//	// and every connector.Env carries Credentials = the connectors.<id>
//	// references of config.yaml.
//
// `facto login <id> [--config path] [--non-interactive]`:
//   - exactly one argument, else usage error (exit 2);
//   - non-interactive (flag, stdin not a terminal, or a release build with
//     only FACTO_E2E_INTERACTIVE=1) is a usage error (exit 2, stderr
//     mentions "interactive") checked before anything is built or created;
//   - the id must be shipped by the build (env.Connectors) and present in
//     config.yaml connectors, else exit 2 naming it (an unsafe id is never
//     echoed raw: stderr stays terminal-safe); nothing is built;
//   - browser: resolveBrowserPath; missing → exit 2 naming browser.path,
//     nothing built;
//   - then, as collect: NewSecrets, the state dir, vault.NewStore (mode
//     from sessions:, KeyBackend), NewPool with Interactive: true; one
//     fresh Login (Env.Saved zero, Env.Interactive true, Env.Prompt
//     interactive, Env.Browser the login-only pool wrapper, Env.Secrets,
//     Env.Credentials); a Persistable session is Persisted and Store.Saved;
//     List and Fetch are never called;
//   - success: exit 0, stdout names the connector; a Login error: exit 1,
//     stderr names the connector; Pool.Close and the resolver's CloseAll
//     run exactly once on every path once built;
//   - no secret (resolved credential, prompt answer, cookie, session blob)
//     is ever printed.
package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/secret/keyring"
	"github.com/FlorianRuen/facto/internal/testsecrets"
	"github.com/FlorianRuen/facto/internal/vault"
)

// The production types satisfy the CLI's seams.
var (
	_ browserPool      = (*browser.Pool)(nil)
	_ vault.KeyBackend = (*keyring.Provider)(nil)
)

// loginRig is one login (or collect) invocation's injected doubles.
type loginRig struct {
	s     *sandbox
	conn  *synthConn
	keys  *memKeys
	pool  *spyPool
	term  *fakeTerminal
	secr  *canaryResolver
	chrom string // fake browser binary path
}

// newLoginRig builds a sandbox whose build ships conn, with an in-memory
// keyring, a spy pool, a terminal (tty as given) and a resolver serving the
// synthetic password.
func newLoginRig(t *testing.T, conn *synthConn, tty bool, password string) *loginRig {
	t.Helper()
	s := newSandbox(t)
	return &loginRig{
		s:     s,
		conn:  conn,
		keys:  newMemKeys(),
		pool:  &spyPool{},
		term:  &fakeTerminal{tty: tty},
		secr:  &canaryResolver{values: map[string]string{synthPasswordRef: password}},
		chrom: s.fakeChrome(t),
	}
}

// env returns the sandbox env wired to the rig's doubles.
func (r *loginRig) env() env {
	e := r.s.env()
	e.Terminal = r.term
	e.KeyBackend = r.keys.factory()
	e.NewPool = r.pool.factory()
	e.NewSecrets = r.secr.factory()
	e.Connectors = r.conn.catalog()
	return e
}

// assertNothingBuilt checks that a refused command built and created
// nothing.
func (r *loginRig) assertNothingBuilt(t *testing.T) {
	t.Helper()
	if built, _ := r.secr.counts(); built != 0 {
		t.Errorf("secret resolver built %d times, want 0", built)
	}
	if params, _, _ := r.pool.snapshot(); len(params) != 0 {
		t.Errorf("browser pool built %d times, want 0", len(params))
	}
	if _, _, _, built := r.keys.counts(); built != 0 {
		t.Errorf("key backend requested %d times, want 0", built)
	}
	if envs, _, _, _, _ := r.conn.state(); len(envs) != 0 {
		t.Errorf("connector Login called %d times, want 0", len(envs))
	}
	if _, err := os.Stat(r.s.state); !os.IsNotExist(err) {
		t.Errorf("state dir created (stat err = %v)", err)
	}
}

// assertClosedOnce checks the pool and the resolver were each built and
// closed exactly once.
func (r *loginRig) assertClosedOnce(t *testing.T) {
	t.Helper()
	if built, closed := r.secr.counts(); built != 1 || closed != 1 {
		t.Errorf("resolver built %d, closed %d; want 1 and 1", built, closed)
	}
	if params, _, closed := r.pool.snapshot(); len(params) != 1 || closed != 1 {
		t.Errorf("pool built %d, closed %d; want 1 and 1", len(params), closed)
	}
}

// sessFile is the saved-session path of id.
func sessFile(state, id string) string {
	return filepath.Join(state, vault.SessionsDir, id+".sess")
}

// TestLogin_NonInteractiveIsUsageError: login needs a person at a
// terminal; anything else is a usage error before anything is built.
func TestLogin_NonInteractiveIsUsageError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		tty   bool
		flag  bool
		e2eOn bool // FACTO_E2E_INTERACTIVE=1 in the environment
	}{
		{name: "stdin not a terminal"},
		{name: "non-interactive flag on a terminal", tty: true, flag: true},
		{name: "non-interactive flag beats the e2e variable", flag: true, e2eOn: true},
	}
	if !e2eBuild {
		tests = append(tests, struct {
			name  string
			tty   bool
			flag  bool
			e2eOn bool
		}{name: "release build ignores FACTO_E2E_INTERACTIVE", e2eOn: true})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newLoginRig(t, &synthConn{persist: "synthetic-blob"}, tt.tty, "synthetic")
			cfg := r.s.writeConfig(t, synthConfig(true, r.chrom, ""))
			e := r.env()
			if tt.e2eOn {
				e.LookupEnv = func(k string) (string, bool) {
					if k == "FACTO_E2E_INTERACTIVE" {
						return "1", true
					}
					return "", false
				}
			}
			args := []string{"login", synthID, "--config", cfg}
			if tt.flag {
				args = append(args, "--non-interactive")
			}
			res := invoke(t.Context(), e, "", args...)
			if res.code != orchestrator.ExitConfig {
				t.Fatalf("exit code = %d, want %d (usage error)\nstdout:\n%s\nstderr:\n%s", res.code, orchestrator.ExitConfig, res.stdout, res.stderr)
			}
			if !strings.Contains(res.stderr, "interactive") {
				t.Errorf("stderr = %q, want it to say login needs an interactive terminal", res.stderr)
			}
			r.assertNothingBuilt(t)
		})
	}
}

// TestLogin_UnknownConnector: only a connector shipped by this build and
// configured in config.yaml can log in; anything else is exit 2 naming it,
// with nothing built.
func TestLogin_UnknownConnector(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		args   []string // after "login"
		config func(chrome string) string
		want   string // stderr must contain it ("" = not checked)
	}{
		{
			name:   "configured but not shipped by this build",
			args:   []string{"ileo"},
			config: func(c string) string { return synthConfig(false, c, "  ileo: { enabled: false, category: housing }\n") },
			want:   "ileo",
		},
		{
			name:   "neither shipped nor configured",
			args:   []string{"synthother"},
			config: func(c string) string { return synthConfig(false, c, "") },
			want:   "synthother",
		},
		{
			name:   "shipped but not configured",
			args:   []string{synthID},
			config: func(c string) string { return validConfig + "browser:\n  path: '" + c + "'\n" },
			want:   "connectors." + synthID,
		},
		{
			name:   "path traversal id",
			args:   []string{"../" + synthID},
			config: func(c string) string { return synthConfig(true, c, "") },
		},
		{
			name:   "terminal escape id",
			args:   []string{"\x1b[2J\x1b]0;pwned\x07" + synthID},
			config: func(c string) string { return synthConfig(true, c, "") },
		},
		{
			name:   "missing id",
			args:   nil,
			config: func(c string) string { return synthConfig(true, c, "") },
		},
		{
			name:   "two ids",
			args:   []string{synthID, synthID},
			config: func(c string) string { return synthConfig(true, c, "") },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newLoginRig(t, &synthConn{persist: "synthetic-blob"}, true, "synthetic")
			cfg := r.s.writeConfig(t, tt.config(r.chrom))
			args := append(append([]string{"login"}, tt.args...), "--config", cfg)
			res := invoke(t.Context(), r.env(), "", args...)
			if res.code != orchestrator.ExitConfig {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", res.code, orchestrator.ExitConfig, res.stdout, res.stderr)
			}
			if tt.want != "" && !strings.Contains(res.stderr, tt.want) {
				t.Errorf("stderr = %q, want it to name %q", res.stderr, tt.want)
			}
			assertTerminalSafe(t, tt.name, res.stderr)
			r.assertNothingBuilt(t)
		})
	}
}

// TestLogin_SavesSession: a successful interactive login of a Persistable
// session saves it through the vault store, readable by the next run;
// failures, non-persistable sessions, ephemeral mode and a missing keyring
// save nothing. List and Fetch are never called by login.
func TestLogin_SavesSession(t *testing.T) {
	t.Parallel()
	errAuth := errors.New("synthetic: credentials refused")
	tests := []struct {
		name      string
		conn      *synthConn
		extra     string // appended to config.yaml
		noKeyring bool

		wantCode   int
		wantSaved  bool
		wantOutKey string // stdout (exit 0) or stderr (exit != 0) names the connector
	}{
		{
			name:      "persistable session saved",
			conn:      &synthConn{persist: "synthetic-session-blob"},
			wantCode:  orchestrator.ExitOK,
			wantSaved: true,
		},
		{
			name:     "session that cannot be saved",
			conn:     &synthConn{},
			wantCode: orchestrator.ExitOK,
		},
		{
			name:     "login refused",
			conn:     &synthConn{persist: "synthetic-session-blob", loginErr: errors.Join(connector.ErrAuthFailed, errAuth)},
			wantCode: orchestrator.ExitAttention,
		},
		{
			name:     "sessions ephemeral saves nothing",
			conn:     &synthConn{persist: "synthetic-session-blob"},
			extra:    "sessions: ephemeral\n",
			wantCode: orchestrator.ExitOK,
		},
		{
			name:      "no keyring saves nothing",
			conn:      &synthConn{persist: "synthetic-session-blob"},
			noKeyring: true,
			wantCode:  orchestrator.ExitOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newLoginRig(t, tt.conn, true, "synthetic")
			cfg := r.s.writeConfig(t, synthConfig(true, r.chrom, tt.extra))
			e := r.env()
			if tt.noKeyring {
				e.KeyBackend = noKeyring
			}
			res := invoke(t.Context(), e, "", "login", synthID, "--config", cfg)
			if res.code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", res.code, tt.wantCode, res.stdout, res.stderr)
			}
			out := res.stdout
			if tt.wantCode != orchestrator.ExitOK {
				out = res.stderr
			}
			if !strings.Contains(out, synthID) {
				t.Errorf("output does not name the connector %q:\nstdout:\n%s\nstderr:\n%s", synthID, res.stdout, res.stderr)
			}

			envs, listed, fetched, _, _ := tt.conn.state()
			if len(envs) != 1 {
				t.Fatalf("Login called %d times, want 1", len(envs))
			}
			if !envs[0].Saved.IsZero() {
				t.Errorf("login handed a saved session to Login; want a fresh login")
			}
			if listed != 0 || fetched != 0 {
				t.Errorf("login listed %d and fetched %d times, want 0", listed, fetched)
			}
			r.assertClosedOnce(t)

			_, statErr := os.Stat(sessFile(r.s.state, synthID))
			if !tt.wantSaved {
				if !os.IsNotExist(statErr) {
					t.Errorf("session file written (stat err = %v), want none", statErr)
				}
				return
			}
			if statErr != nil {
				t.Fatalf("session file: %v", statErr)
			}
			got, err := loadSession(t.Context(), r.s.state, r.keys, synthID)
			if err != nil {
				t.Fatalf("load saved session: %v", err)
			}
			defer got.Wipe()
			if got.Expose() != tt.conn.persist {
				t.Errorf("saved session differs from the Persisted blob")
			}
		})
	}
}

// TestLogin_NeedsVisibleBrowserWhenInteractive: login builds an
// interactive pool on the configured browser, so a connector asking for a
// visible window gets one (A6), within its own allowlist; the Env says
// interactive. Without a browser, login is a configuration error.
func TestLogin_NeedsVisibleBrowserWhenInteractive(t *testing.T) {
	t.Parallel()

	t.Run("interactive pool, visible launch", func(t *testing.T) {
		t.Parallel()
		conn := &synthConn{persist: "synthetic-blob", launch: true, visible: true}
		r := newLoginRig(t, conn, true, "synthetic")
		cfg := r.s.writeConfig(t, synthConfig(true, r.chrom, ""))
		res := invoke(t.Context(), r.env(), "", "login", synthID, "--config", cfg)
		if res.code != orchestrator.ExitOK {
			t.Fatalf("exit code = %d, want 0\nstderr:\n%s", res.code, res.stderr)
		}
		params, launches, closed := r.pool.snapshot()
		if len(params) != 1 {
			t.Fatalf("pool built %d times, want 1", len(params))
		}
		p := params[0]
		if !p.Interactive {
			t.Errorf("poolParams.Interactive = false, want true for facto login")
		}
		if p.Executable != r.chrom {
			t.Errorf("poolParams.Executable = %q, want browser.path %q", p.Executable, r.chrom)
		}
		if p.StateDir != r.s.state {
			t.Errorf("poolParams.StateDir = %q, want %q", p.StateDir, r.s.state)
		}
		if len(launches) != 1 {
			t.Fatalf("pool launched %d browsers, want 1", len(launches))
		}
		if !launches[0].Visible {
			t.Errorf("launch Visible = false, want the visible window the connector asked for")
		}
		if !slices.Equal(launches[0].AllowedDomains, synthDomains) {
			t.Errorf("launch AllowedDomains = %v, want the connector's own %v", launches[0].AllowedDomains, synthDomains)
		}
		if closed != 1 {
			t.Errorf("pool closed %d times, want 1", closed)
		}
		envs, _, _, _, _ := conn.state()
		if len(envs) != 1 {
			t.Fatalf("Login called %d times, want 1", len(envs))
		}
		env := envs[0]
		if !env.Interactive {
			t.Errorf("Env.Interactive = false, want true")
		}
		if env.Prompt == nil || !env.Prompt.Interactive() {
			t.Errorf("Env.Prompt = %v, want an interactive prompter", env.Prompt)
		}
		if env.Browser == nil || env.Secrets == nil {
			t.Errorf("Env.Browser = %v, Env.Secrets = %v; want both set", env.Browser, env.Secrets)
		}
		if env.Credentials.Password != synthPasswordRef {
			t.Errorf("Env.Credentials.Password = %q, want the configured reference", env.Credentials.Password)
		}
	})

	t.Run("no browser configured or installed", func(t *testing.T) {
		t.Parallel()
		conn := &synthConn{persist: "synthetic-blob", launch: true, visible: true}
		r := newLoginRig(t, conn, true, "synthetic")
		cfg := r.s.writeConfig(t, synthConfig(true, "", ""))
		res := invoke(t.Context(), r.env(), "", "login", synthID, "--config", cfg)
		if res.code != orchestrator.ExitConfig {
			t.Fatalf("exit code = %d, want 2\nstderr:\n%s", res.code, res.stderr)
		}
		for _, want := range []string{"browser.path", "facto browser install"} {
			if !strings.Contains(res.stderr, want) {
				t.Errorf("stderr = %q, want it to mention %q", res.stderr, want)
			}
		}
		r.assertNothingBuilt(t)
	})
}

// TestLogin_SecretsNeverPrinted: the resolved password, the typed code,
// the browser cookie and the saved blob never reach stdout or stderr,
// whether the login succeeds or the supplier refuses it. The code typed at
// the prompt does reach the connector.
func TestLogin_SecretsNeverPrinted(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		loginErr error
		wantCode int
	}{
		{name: "success", wantCode: orchestrator.ExitOK},
		{name: "refused after the code", loginErr: connector.ErrAuthFailed, wantCode: orchestrator.ExitAttention},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			password := testsecrets.Canary(t, testsecrets.Password)
			otp := testsecrets.Canary(t, testsecrets.Token)
			cookie := testsecrets.Canary(t, testsecrets.Cookie)
			blob := testsecrets.Canary(t, testsecrets.Session)

			conn := &synthConn{persist: blob, loginErr: tt.loginErr, launch: true, visible: true, prompt: true, wantOTP: otp}
			r := newLoginRig(t, conn, true, password)
			r.pool.cookie = cookie
			r.term.answers = []string{"  " + otp + "  "}
			cfg := r.s.writeConfig(t, synthConfig(true, r.chrom, ""))

			res := invoke(t.Context(), r.env(), "", "login", synthID, "--config", cfg)
			art := testsecrets.ArtifactDir(t)
			writeFile(t, art, "stdout.txt", []byte(res.stdout))
			writeFile(t, art, "stderr.txt", []byte(res.stderr))
			if res.code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d\nstderr:\n%s", res.code, tt.wantCode, res.stderr)
			}
			if _, _, _, ok, err := conn.state(); !ok {
				t.Fatalf("the typed code did not reach the connector (prompt err = %v)", err)
			}
			if r.term.readCount() != 1 {
				t.Errorf("no-echo reads = %d, want 1", r.term.readCount())
			}
			for name, c := range map[string]string{"password": password, "otp": otp, "cookie": cookie, "session blob": blob} {
				if strings.Contains(res.stdout, c) || strings.Contains(res.stderr, c) {
					t.Errorf("%s canary printed by facto login\nstdout:\n%s\nstderr:\n%s", name, res.stdout, res.stderr)
				}
			}
			if !strings.Contains(res.stderr, connector.PromptRequest{Label: synthLabel}.CleanLabel()) {
				t.Errorf("stderr = %q, want the cleaned prompt label", res.stderr)
			}
			assertTerminalSafe(t, tt.name, res.stderr)
		})
	}
}
