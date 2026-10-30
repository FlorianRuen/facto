// Tests for the collect wiring of J1 task T19: the session store (vault,
// A3, A13), the browser pool (A12), the browser path, the connector catalog
// of the build and the prompter handed to connectors. Expected API:
// login_test.go. All values are synthetic; no test reaches the OS keyring,
// a real browser or the network.
package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/testsecrets"
	"github.com/FlorianRuen/facto/internal/vault"
)

// TestConfig_SessionsMode: sessions: defaults to persistent, ephemeral is
// accepted, anything else is a configuration error naming the key; the CLI
// maps the value to the vault mode.
func TestConfig_SessionsMode(t *testing.T) {
	t.Parallel()
	home := filepath.Join(t.TempDir(), "home")
	tests := []struct {
		name    string
		yaml    string
		want    vault.Mode
		wantErr bool
	}{
		{name: "default is persistent", yaml: "notify: none\n", want: vault.Persistent},
		{name: "persistent", yaml: "sessions: persistent\n", want: vault.Persistent},
		{name: "ephemeral", yaml: "sessions: ephemeral\n", want: vault.Ephemeral},
		{name: "case-sensitive", yaml: "sessions: Ephemeral\n", wantErr: true},
		{name: "unknown value", yaml: "sessions: none\n", wantErr: true},
		{name: "not a string", yaml: "sessions: [ephemeral]\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Parse([]byte(tt.yaml), config.Options{Home: home})
			if tt.wantErr {
				if !errors.Is(err, config.ErrInvalid) || !strings.Contains(err.Error(), "sessions") {
					t.Fatalf("Parse() error = %v, want ErrInvalid naming sessions", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(): %v", err)
			}
			got, err := sessionMode(cfg)
			if err != nil || got != tt.want {
				t.Fatalf("sessionMode() = %v, %v; want %v", got, err, tt.want)
			}
		})
	}

	t.Run("unvalidated unknown value refused", func(t *testing.T) {
		t.Parallel()
		if _, err := sessionMode(&config.Config{Sessions: "bogus"}); err == nil {
			t.Fatal("sessionMode accepted an unknown value")
		}
	})
}

// TestBrowserPath_RegularFileOrInstalled: browser.path, when set, must
// name an existing regular file and wins over the installed copy; when
// unset the copy from `facto browser install` is used; with neither the
// error tells the user both ways out. Errors never quote the path.
func TestBrowserPath_RegularFileOrInstalled(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	chrome := s.fakeChrome(t)
	missing := filepath.Join(s.home, "synthetic-missing-chrome")
	dir := s.out // an existing directory
	installedPath := filepath.Join(s.home, "installed", "chrome")
	installed := func() (string, bool) { return installedPath, true }
	none := func() (string, bool) { return "", false }

	tests := []struct {
		name      string
		path      string
		installed func() (string, bool)
		want      string
		wantErr   error // errors.Is target; nil = success
		mentions  []string
		noEcho    string // must not appear in the error
	}{
		{name: "configured regular file", path: chrome, installed: none, want: chrome},
		{name: "configured wins over installed", path: chrome, installed: installed, want: chrome},
		{name: "installed copy when unset", installed: installed, want: installedPath},
		{name: "configured but missing", path: missing, installed: installed, wantErr: config.ErrInvalid, mentions: []string{"browser.path"}, noEcho: "synthetic-missing-chrome"},
		{name: "configured directory", path: dir, installed: installed, wantErr: config.ErrInvalid, mentions: []string{"browser.path"}, noEcho: dir},
		{name: "neither configured nor installed", installed: none, wantErr: errNoBrowser, mentions: []string{"browser.path", "facto browser install"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{Browser: config.Browser{Path: tt.path}}
			got, err := resolveBrowserPath(cfg, tt.installed)
			if tt.wantErr == nil {
				if err != nil || got != tt.want {
					t.Fatalf("resolveBrowserPath() = %q, %v; want %q", got, err, tt.want)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("resolveBrowserPath() error = %v, want %v", err, tt.wantErr)
			}
			for _, m := range tt.mentions {
				if !strings.Contains(err.Error(), m) {
					t.Errorf("error %q does not mention %q", err, m)
				}
			}
			if tt.noEcho != "" && strings.Contains(err.Error(), tt.noEcho) {
				t.Errorf("error %q quotes the configured path", err)
			}
		})
	}
}

// TestCollect_BuildsStoreAndPool: collect opens the vault store in the
// state dir with the key backend (or falls back to ephemeral sessions with
// one warning when there is no keyring, A3), builds one non-interactive
// browser pool on the configured browser, hands both, the prompter and the
// credentials to the orchestrator, and closes the pool and the resolver
// exactly once on every exit path once built.
func TestCollect_BuildsStoreAndPool(t *testing.T) {
	t.Parallel()
	errPool := errors.New("synthetic: pool setup failure")
	tests := []struct {
		name      string
		conn      func() *synthConn
		config    func(r *loginRig) string
		noKeyring bool
		poolErr   error
		cancelAt  bool // the connector's Login cancels the run

		wantCode      int
		wantBuilt     int  // pool and resolver
		wantSaved     bool // sessions/<id>.sess written
		wantWarnLines int  // lines with "sessions are ephemeral"
		wantLogin     int
		wantStderr    string
	}{
		{
			name:      "keyring: persistent store, session saved, pool used",
			conn:      func() *synthConn { return &synthConn{persist: "synthetic-session-blob", launch: true} },
			config:    func(r *loginRig) string { return synthConfig(true, r.chrom, "") },
			wantCode:  orchestrator.ExitOK,
			wantBuilt: 1,
			wantSaved: true,
			wantLogin: 1,
		},
		{
			name:          "no keyring: ephemeral with one warning",
			conn:          func() *synthConn { return &synthConn{persist: "synthetic-session-blob", launch: true} },
			config:        func(r *loginRig) string { return synthConfig(true, r.chrom, "") },
			noKeyring:     true,
			wantCode:      orchestrator.ExitOK,
			wantBuilt:     1,
			wantWarnLines: 1,
			wantLogin:     1,
		},
		{
			name:      "no browser configured: pool still built for the startup sweep",
			conn:      func() *synthConn { return &synthConn{persist: "synthetic-session-blob"} },
			config:    func(*loginRig) string { return synthConfig(true, "", "") },
			wantCode:  orchestrator.ExitOK,
			wantBuilt: 1,
			wantSaved: true,
			wantLogin: 1,
		},
		{
			name:       "pool error fails the run",
			conn:       func() *synthConn { return &synthConn{persist: "synthetic-session-blob"} },
			config:     func(r *loginRig) string { return synthConfig(true, r.chrom, "") },
			poolErr:    errPool,
			wantCode:   orchestrator.ExitAttention,
			wantBuilt:  -1, // resolver built and closed; pool factory called, nothing to close
			wantStderr: "browser",
		},
		{
			name:      "run canceled during login",
			conn:      func() *synthConn { return &synthConn{persist: "synthetic-session-blob"} },
			config:    func(r *loginRig) string { return synthConfig(true, r.chrom, "") },
			cancelAt:  true,
			wantCode:  orchestrator.ExitAttention,
			wantBuilt: 1,
			wantLogin: 1,
		},
		{
			name: "configuration error builds nothing",
			conn: func() *synthConn { return &synthConn{} },
			config: func(r *loginRig) string {
				return synthConfig(true, r.chrom, "  ileo: { enabled: true, category: housing }\n")
			},
			wantCode: orchestrator.ExitConfig,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conn := tt.conn()
			r := newLoginRig(t, conn, false, "synthetic")
			r.pool.newErr = tt.poolErr
			cfg := r.s.writeConfig(t, tt.config(r))
			e := r.env()
			if tt.noKeyring {
				e.KeyBackend = noKeyring
			}
			ctx := t.Context()
			if tt.cancelAt {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				conn.onLogin = cancel
			}

			res := invoke(ctx, e, "", "collect", "--config", cfg, "--year", "2026")
			if res.code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", res.code, tt.wantCode, res.stdout, res.stderr)
			}
			if tt.wantStderr != "" && !strings.Contains(res.stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want it to mention %q", res.stderr, tt.wantStderr)
			}

			params, launches, poolClosed := r.pool.snapshot()
			secBuilt, secClosed := r.secr.counts()
			switch tt.wantBuilt {
			case 0:
				r.assertNothingBuilt(t)
				return
			case -1:
				if secBuilt != 1 || secClosed != 1 || len(params) != 1 || poolClosed != 0 {
					t.Errorf("resolver built %d closed %d, pool built %d closed %d; want 1 1 1 0", secBuilt, secClosed, len(params), poolClosed)
				}
			default:
				if secBuilt != 1 || secClosed != 1 || len(params) != 1 || poolClosed != 1 {
					t.Errorf("resolver built %d closed %d, pool built %d closed %d; want each once", secBuilt, secClosed, len(params), poolClosed)
				}
			}

			if len(params) > 0 {
				p := params[0]
				if p.Interactive {
					t.Errorf("collect built an interactive pool; want non-interactive (stdin not a terminal)")
				}
				if p.StateDir != r.s.state {
					t.Errorf("poolParams.StateDir = %q, want %q", p.StateDir, r.s.state)
				}
				if strings.Contains(tt.config(r), "browser:") && p.Executable != r.chrom {
					t.Errorf("poolParams.Executable = %q, want browser.path %q", p.Executable, r.chrom)
				}
			}

			envs, listed, _, _, _ := conn.state()
			if len(envs) != tt.wantLogin {
				t.Fatalf("Login called %d times, want %d", len(envs), tt.wantLogin)
			}
			if tt.wantLogin > 0 {
				env := envs[0]
				if env.Interactive || env.Prompt == nil || env.Prompt.Interactive() {
					t.Errorf("Env.Interactive = %v, Env.Prompt = %v; want a non-interactive prompter", env.Interactive, env.Prompt)
				}
				if env.Credentials.Password != synthPasswordRef {
					t.Errorf("Env.Credentials.Password = %q, want the configured reference", env.Credentials.Password)
				}
				if env.Browser == nil {
					t.Errorf("Env.Browser = nil, want the login-only wrapper of the run's pool")
				}
				if conn.launch {
					if len(launches) != 1 || !slices.Equal(launches[0].AllowedDomains, synthDomains) {
						t.Errorf("pool launches = %+v, want one launch on the connector's allowlist", launches)
					}
				}
				if !tt.cancelAt && listed != 1 {
					t.Errorf("List called %d times, want 1", listed)
				}
			}

			_, statErr := os.Stat(sessFile(r.s.state, synthID))
			if tt.wantSaved {
				if statErr != nil {
					t.Fatalf("session file: %v", statErr)
				}
				got, err := loadSession(t.Context(), r.s.state, r.keys, synthID)
				if err != nil {
					t.Fatalf("load saved session: %v", err)
				}
				defer got.Wipe()
				if got.Expose() != conn.persist {
					t.Errorf("saved session differs from the Persisted blob")
				}
			} else if !os.IsNotExist(statErr) {
				t.Errorf("session file written (stat err = %v), want none", statErr)
			}
			if tt.noKeyring {
				if _, err := os.Stat(filepath.Join(r.s.state, vault.InstallIDFile)); !os.IsNotExist(err) {
					t.Errorf("install-id written without a keyring (stat err = %v)", err)
				}
			}
			if n := strings.Count(res.stderr, "sessions are ephemeral"); n != tt.wantWarnLines {
				t.Errorf("%d ephemeral-fallback warnings on stderr, want %d:\n%s", n, tt.wantWarnLines, res.stderr)
			}
		})
	}
}

// TestCollect_EphemeralSweepsAtStartup (A13): with sessions: ephemeral,
// collect deletes every saved session file at startup without reading it
// (no key is resolved, the content is never printed), keyring available or
// not, and saves nothing.
func TestCollect_EphemeralSweepsAtStartup(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name      string
		noKeyring bool
	}{
		{name: "keyring available"},
		{name: "no keyring", noKeyring: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			blob := testsecrets.Canary(t, testsecrets.Session)
			conn := &synthConn{persist: "synthetic-new-blob"}
			r := newLoginRig(t, conn, false, "synthetic")
			cfg := r.s.writeConfig(t, synthConfig(true, r.chrom, "sessions: ephemeral\n"))
			// A previous persistent run left a session and its install id.
			writeFile(t, r.s.home, filepath.Base(r.s.state)+"/"+vault.InstallIDFile, []byte("0123456789abcdef0123456789abcdef"))
			writeFile(t, r.s.state, vault.SessionsDir+"/"+synthID+".sess", []byte(blob))
			writeFile(t, r.s.state, vault.SessionsDir+"/other-synth.sess", []byte(blob))
			e := r.env()
			if tt.noKeyring {
				e.KeyBackend = noKeyring
			}

			res := invoke(t.Context(), e, "", "collect", "--config", cfg, "--year", "2026")
			art := testsecrets.ArtifactDir(t)
			writeFile(t, art, "stdout.txt", []byte(res.stdout))
			writeFile(t, art, "stderr.txt", []byte(res.stderr))
			if res.code != orchestrator.ExitOK {
				t.Fatalf("exit code = %d, want 0\nstderr:\n%s", res.code, res.stderr)
			}
			for _, id := range []string{synthID, "other-synth"} {
				if _, err := os.Stat(sessFile(r.s.state, id)); !os.IsNotExist(err) {
					t.Errorf("%s.sess still present after an ephemeral startup (stat err = %v)", id, err)
				}
			}
			resolves, sets, _, _ := r.keys.counts()
			if resolves != 0 || sets != 0 {
				t.Errorf("keyring resolves = %d, sets = %d; want 0 (ephemeral never reads nor saves)", resolves, sets)
			}
			envs, _, _, _, _ := conn.state()
			if len(envs) != 1 || !envs[0].Saved.IsZero() {
				t.Errorf("Login calls = %d, saved session handed over = %v; want 1 fresh login", len(envs), len(envs) > 0 && !envs[0].Saved.IsZero())
			}
			if strings.Contains(res.stdout, blob) || strings.Contains(res.stderr, blob) {
				t.Errorf("swept session content printed")
			}
		})
	}
}

// TestCollect_EnabledUnknownConnectorStillRefused: an enabled connector the
// build does not ship is still a configuration error naming it, before
// anything is built or created, even when the build ships others; shipped
// connectors run only when enabled.
func TestCollect_EnabledUnknownConnectorStillRefused(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		catalog   bool // false = the build's own catalog (env.Connectors nil)
		extra     string
		enabled   bool // synthlogin enabled
		wantCode  int
		wantName  string
		wantLogin int
		release   bool // case only meaningful in a release build
	}{
		{name: "unknown enabled beside a shipped one", catalog: true, enabled: true, extra: "  ileo: { enabled: true, category: housing }\n", wantCode: orchestrator.ExitConfig, wantName: "connectors.ileo"},
		{name: "unknown enabled alone", catalog: true, extra: "  ileo: { enabled: true, category: housing }\n", wantCode: orchestrator.ExitConfig, wantName: "connectors.ileo"},
		{name: "unknown disabled is ignored", catalog: true, extra: "  ileo: { enabled: false, category: housing }\n", wantCode: orchestrator.ExitOK},
		{name: "shipped and enabled runs", catalog: true, enabled: true, wantCode: orchestrator.ExitOK, wantLogin: 1},
		{name: "shipped but disabled never runs", catalog: true, wantCode: orchestrator.ExitOK},
		{name: "release build ships no fakeprovider", extra: "  fakeprovider: { enabled: true, category: energy }\n", wantCode: orchestrator.ExitConfig, wantName: "connectors.fakeprovider", release: true},
	}
	for _, tt := range tests {
		if tt.release && e2eBuild {
			continue
		}
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conn := &synthConn{persist: "synthetic-blob"}
			r := newLoginRig(t, conn, false, "synthetic")
			cfg := r.s.writeConfig(t, synthConfig(tt.enabled, r.chrom, tt.extra))
			e := r.env()
			if !tt.catalog {
				e.Connectors = nil
			}
			res := invoke(t.Context(), e, "", "collect", "--config", cfg, "--year", "2026")
			if res.code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", res.code, tt.wantCode, res.stdout, res.stderr)
			}
			if tt.wantCode == orchestrator.ExitConfig {
				if !strings.Contains(res.stderr, tt.wantName) {
					t.Errorf("stderr = %q, want it to name %q", res.stderr, tt.wantName)
				}
				r.assertNothingBuilt(t)
				return
			}
			if envs, _, _, _, _ := conn.state(); len(envs) != tt.wantLogin {
				t.Errorf("Login called %d times, want %d", len(envs), tt.wantLogin)
			}
		})
	}
}

// TestAvailableConnectors_FakeproviderOnlyInE2E: the release build ships
// no connector yet; the e2e build ships fakeprovider, registered by an
// e2e-only file (release-e2e-check proves the release binary lacks it).
func TestAvailableConnectors_FakeproviderOnlyInE2E(t *testing.T) {
	t.Parallel()
	reg, err := availableConnectors()
	if err != nil {
		t.Fatalf("availableConnectors: %v", err)
	}
	var ids []string
	for _, c := range reg.All() {
		ids = append(ids, c.Info().ID)
	}
	want := []string(nil)
	if e2eBuild {
		want = []string{"fakeprovider"}
	}
	if !slices.Equal(ids, want) {
		t.Fatalf("shipped connectors = %v, want %v (e2e build: %v)", ids, want, e2eBuild)
	}
	if !e2eBuild && registerTestConnectors != nil {
		t.Errorf("registerTestConnectors is set in a release build")
	}
	// Each call returns a fresh registry: no package-level registry.
	again, err := availableConnectors()
	if err != nil || again == reg {
		t.Errorf("availableConnectors returned the same registry twice (err = %v)", err)
	}
	func(*connector.Registry) {}(reg)
}
