// Tests for the secret resolver wiring of collect (J1 task T17, SEC-J0-22;
// ADR 0009 A3). collect builds one secret resolver per run, hands it to
// every connector through connector.Env.Secrets and always closes it (which
// locks the password manager) before returning, whatever the exit path:
// success, run error, cancellation or SIGTERM/SIGINT. All values are
// synthetic; no test runs the bw binary or touches the real keyring.
//
// Expected API (implementer: follow exactly; package main):
//
//	// secretResolver is what collect needs from the run's resolver.
//	// *secret.Resolver satisfies it.
//	type secretResolver interface {
//		connector.SecretResolver // Resolve(ctx, ref string) (secret.Secret, error)
//		CloseAll() error
//	}
//
//	// env gains one field:
//	//	// NewSecrets builds the run's secret resolver; nil means
//	//	// newSecretResolver. Test seam.
//	//	NewSecrets func(ctx context.Context, e env, cfg *config.Config) (secretResolver, error)
//
//	// newSecretResolver is secret.NewResolver(secretProviders(e)...).
//	func newSecretResolver(ctx context.Context, e env, cfg *config.Config) (secretResolver, error)
//
//	// secretProviders returns the production providers: bw (bitwarden over
//	// bitwarden.ExecRunner) and keyring (keyring.System) in every build,
//	// plus the e2e file provider (internal/secret/e2efile, scheme "e2e")
//	// only in builds with -tags e2e, added by a //go:build e2e file of this
//	// package. Constructing them runs nothing (no bw, no keyring call).
//	func secretProviders(e env) ([]secret.Provider, error)
//
//	// collectDeps gains:
//	//	secrets connector.SecretResolver // handed to orchestrator.Deps.Secrets
//
//	// orchestrator.Deps gains:
//	//	Secrets connector.SecretResolver // copied into every connector.Env
//
// collect behaviour:
//   - NewSecrets is called exactly once per run, after the config, the
//     registry and the namer are validated (a configuration error builds
//     nothing: exit 2, zero calls) and before any folder is created.
//   - A NewSecrets error is a failed run: exit 1, the error is printed on
//     stderr ("secrets" in the message), nothing to close.
//   - Once NewSecrets succeeded, CloseAll is called exactly once on every
//     return path (success, run error, cancellation, signal), after the
//     connectors and the inbox are done and before collect returns.
//   - A CloseAll error is printed on stderr ("close secrets" in the
//     message) and makes the run exit at least 1, even if everything else
//     was fine: a password manager that may still be unlocked needs
//     attention.
package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/inbox"
	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// The production resolver satisfies what collect needs.
var _ secretResolver = (*secret.Resolver)(nil)

// spyResolver records how collect builds, uses and closes the resolver.
type spyResolver struct {
	mu       sync.Mutex
	runCtx   context.Context // ctx NewSecrets was called with
	built    int
	closed   int
	closeErr error
	// ctxDoneAtClose records whether the run ctx was already done when
	// CloseAll ran (signal and cancel cases).
	ctxDoneAtClose bool
	// resolvedAfterClose is set when Resolve is called after CloseAll.
	resolvedAfterClose bool
}

func (s *spyResolver) Resolve(context.Context, string) (secret.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed > 0 {
		s.resolvedAfterClose = true
	}
	return secret.Secret{}, secret.ErrSecretNotFound
}

func (s *spyResolver) CloseAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	if s.runCtx != nil && s.runCtx.Err() != nil {
		s.ctxDoneAtClose = true
	}
	return s.closeErr
}

func (s *spyResolver) counts() (built, closed int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.built, s.closed
}

// factory returns a NewSecrets seam handing out s (or failing with err).
func (s *spyResolver) factory(err error) func(context.Context, env, *config.Config) (secretResolver, error) {
	return func(ctx context.Context, _ env, _ *config.Config) (secretResolver, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.built++
		s.runCtx = ctx
		if err != nil {
			return nil, err
		}
		return s, nil
	}
}

// signalingPrompter raises a real shutdown signal when asked about an inbox
// file, then waits for the signal context to be canceled, like a user
// hitting Ctrl-C at the prompt or systemd stopping the unit.
type signalingPrompter struct {
	t     *testing.T
	raise func(t *testing.T)
}

func (p signalingPrompter) AskDoc(ctx context.Context, _ string, _ normalize.Doc) (normalize.Doc, bool, error) {
	p.raise(p.t)
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return normalize.Doc{}, false, ctx.Err()
	case <-timer.C:
		return normalize.Doc{}, false, errors.New("signal never canceled the run context")
	}
}

// TestCollect_ResolverClosedOnSuccessErrorAndSignal: the resolver is built
// once and CloseAll runs exactly once on every exit path once it exists;
// a configuration error builds nothing.
func TestCollect_ResolverClosedOnSuccessErrorAndSignal(t *testing.T) {
	t.Parallel()
	errBuild := errors.New("synthetic provider setup failure")
	errClose := errors.New("synthetic lock failure")

	tests := []struct {
		name string
		// setup writes the sandbox and returns the config path.
		setup func(t *testing.T, s *sandbox) string
		// ctx returns the run context and the prompter for the inbox.
		ctx      func(t *testing.T) (context.Context, inbox.Prompter)
		buildErr error
		closeErr error
		signal   bool // needs a real shutdown signal (unix only)

		wantCode       int
		wantBuilt      int
		wantClosed     int
		wantCtxDone    bool   // the run ctx was done when CloseAll ran
		wantStderrPart string // "" = not checked
	}{
		{
			name:       "success",
			setup:      func(t *testing.T, s *sandbox) string { return s.writeConfig(t, validConfig) },
			wantCode:   orchestrator.ExitOK,
			wantBuilt:  1,
			wantClosed: 1,
		},
		{
			name: "configuration error builds nothing",
			setup: func(t *testing.T, s *sandbox) string {
				return s.writeConfig(t, validConfig+"connectors:\n  ileo: { enabled: true, category: housing }\n")
			},
			wantCode:   orchestrator.ExitConfig,
			wantBuilt:  0,
			wantClosed: 0,
		},
		{
			name: "run error after build",
			setup: func(t *testing.T, s *sandbox) string {
				writeFile(t, s.home, "Blocked", []byte("synthetic"))
				return s.writeConfig(t, "output: { local: ~/Blocked }\nstate_dir: ~/.facto\nnotify: none\n")
			},
			wantCode:       orchestrator.ExitAttention,
			wantBuilt:      1,
			wantClosed:     1,
			wantStderrPart: "output folder",
		},
		{
			name: "canceled mid-run",
			setup: func(t *testing.T, s *sandbox) string {
				writeFile(t, s.inbox, "scan.pdf", syntheticPDF(t))
				return s.writeConfig(t, validConfig)
			},
			ctx: func(t *testing.T) (context.Context, inbox.Prompter) {
				ctx, cancel := context.WithCancel(t.Context())
				t.Cleanup(cancel)
				return ctx, cancelingPrompter{cancel: cancel}
			},
			wantCode:    orchestrator.ExitAttention,
			wantBuilt:   1,
			wantClosed:  1,
			wantCtxDone: true,
		},
		{
			name: "SIGTERM mid-run",
			setup: func(t *testing.T, s *sandbox) string {
				writeFile(t, s.inbox, "scan.pdf", syntheticPDF(t))
				return s.writeConfig(t, validConfig)
			},
			ctx: func(t *testing.T) (context.Context, inbox.Prompter) {
				// The production seam: main wraps the run in
				// signal.NotifyContext(shutdownSignals()...).
				ctx, stop := signal.NotifyContext(t.Context(), shutdownSignals()...)
				t.Cleanup(stop)
				return ctx, signalingPrompter{t: t, raise: raiseTerm}
			},
			signal:      true,
			wantCode:    orchestrator.ExitAttention,
			wantBuilt:   1,
			wantClosed:  1,
			wantCtxDone: true,
		},
		{
			name:           "resolver construction fails",
			setup:          func(t *testing.T, s *sandbox) string { return s.writeConfig(t, validConfig) },
			buildErr:       errBuild,
			wantCode:       orchestrator.ExitAttention,
			wantBuilt:      1,
			wantClosed:     0,
			wantStderrPart: "secrets",
		},
		{
			name:           "close error is reported",
			setup:          func(t *testing.T, s *sandbox) string { return s.writeConfig(t, validConfig) },
			closeErr:       errClose,
			wantCode:       orchestrator.ExitAttention,
			wantBuilt:      1,
			wantClosed:     1,
			wantStderrPart: "close secrets",
		},
	}
	for _, tc := range tests {
		if tc.signal && !canRaiseTerm {
			// Windows: the runtime never delivers SIGTERM and a process
			// cannot send itself Ctrl-C; the cancel case covers the path.
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			if !tc.signal {
				t.Parallel()
			}
			s := newSandbox(t)
			cfg := tc.setup(t, s)
			ctx, prompter := t.Context(), inbox.Prompter(nil)
			if tc.ctx != nil {
				ctx, prompter = tc.ctx(t)
			}
			spy := &spyResolver{closeErr: tc.closeErr}
			e := s.env()
			e.NewSecrets = spy.factory(tc.buildErr)
			var stdout, stderr bytes.Buffer

			err := collect(ctx, e, collectParams{
				configPath: cfg,
				period:     connector.Year(2026),
				prompter:   prompter,
				stdout:     &stdout,
				stderr:     &stderr,
			})

			code := orchestrator.ExitOK
			if err != nil {
				var ee *exitError
				if !errors.As(err, &ee) {
					t.Fatalf("collect error = %v (%T), want nil or *exitError", err, err)
				}
				code = ee.code
				if ee.err != nil {
					writeErr(&stderr, ee.err)
				}
			}
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d\nstderr:\n%s", code, tc.wantCode, stderr.String())
			}
			built, closed := spy.counts()
			if built != tc.wantBuilt {
				t.Errorf("NewSecrets called %d times, want %d", built, tc.wantBuilt)
			}
			if closed != tc.wantClosed {
				t.Errorf("CloseAll called %d times, want %d (the password manager must be locked on every exit path)", closed, tc.wantClosed)
			}
			spy.mu.Lock()
			ctxDone, late := spy.ctxDoneAtClose, spy.resolvedAfterClose
			spy.mu.Unlock()
			if tc.wantCtxDone && !ctxDone {
				t.Error("CloseAll ran before the run was canceled: the cancel/signal path was not exercised")
			}
			if late {
				t.Error("Resolve called after CloseAll")
			}
			if tc.wantStderrPart != "" && !strings.Contains(stderr.String(), tc.wantStderrPart) {
				t.Errorf("stderr = %q, want it to mention %q", stderr.String(), tc.wantStderrPart)
			}
		})
	}
}

// TestCollect_ResolverCloseErrorNeverLeaksSecret: a provider whose lock
// error echoes a secret (a hostile or buggy backend) never gets it printed:
// stderr goes through the redacting writeErr path.
func TestCollect_ResolverCloseErrorNeverLeaksSecret(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Session)
	s := newSandbox(t)
	cfg := s.writeConfig(t, validConfig)
	spy := &spyResolver{closeErr: errors.New("lock failed: session=" + canary)}
	e := s.env()
	e.NewSecrets = spy.factory(nil)
	var stdout, stderr bytes.Buffer
	err := collect(t.Context(), e, collectParams{
		configPath: cfg, period: connector.Year(2026), stdout: &stdout, stderr: &stderr,
	})
	var ee *exitError
	if errors.As(err, &ee) && ee.err != nil {
		writeErr(&stderr, ee.err)
	}
	if _, closed := spy.counts(); closed != 1 {
		t.Fatalf("CloseAll called %d times, want 1", closed)
	}
	if out := stdout.String() + stderr.String(); strings.Contains(out, canary) {
		t.Fatalf("canary secret leaked in collect output:\n%s", out)
	}
	if !strings.Contains(stderr.String(), "close secrets") {
		t.Errorf("stderr = %q, want the close failure reported", stderr.String())
	}
}

// TestCollect_ResolverPassedToEnv: the resolver collect built is the one
// every connector gets in connector.Env.Secrets.
func TestCollect_ResolverPassedToEnv(t *testing.T) {
	t.Parallel()
	s := newSandbox(t)
	cfgPath := s.writeConfig(t, validConfig)
	cfg, err := config.Load(t.Context(), cfgPath, config.Options{Home: s.home})
	if err != nil {
		t.Fatalf("setup config.Load: %v", err)
	}
	namer, err := normalize.NewNamer(normalize.Config{File: cfg.Naming.File, Dir: cfg.Naming.Dir, Language: cfg.Naming.Language})
	if err != nil {
		t.Fatalf("setup NewNamer: %v", err)
	}
	spy := &spyResolver{}
	conn := &envSpyConn{}
	reg := connector.NewRegistry()
	if err := reg.Register(conn); err != nil {
		t.Fatalf("setup Register: %v", err)
	}
	var stdout, stderr bytes.Buffer
	var report orchestrator.Report

	_, runErr := collectInto(t.Context(), s.env(), cfg,
		collectDeps{reg: reg, namer: namer, log: discardLogger(), secrets: spy},
		collectParams{configPath: cfgPath, period: connector.Year(2026), stdout: &stdout, stderr: &stderr},
		&report)
	if runErr != nil {
		t.Fatalf("collectInto: %v", runErr)
	}
	envs := conn.envList()
	if len(envs) != 1 {
		t.Fatalf("Login called %d times, want 1", len(envs))
	}
	got, ok := envs[0].Secrets.(*spyResolver)
	if !ok || got != spy {
		t.Fatalf("Env.Secrets = %T %p, want the run's resolver %p", envs[0].Secrets, envs[0].Secrets, spy)
	}
}

// envSpyConn is a synthetic connector recording the Env it is given; its
// login always needs the user, so nothing is listed or fetched and no
// network is touched.
type envSpyConn struct {
	mu   sync.Mutex
	envs []connector.Env
}

func (c *envSpyConn) Info() connector.Info {
	return connector.Info{
		ID:             "synthspy",
		Name:           "Synthetic spy",
		Category:       "energy",
		Kinds:          []connector.DocKind{connector.Invoice},
		AllowedDomains: []string{"billing.synthspy.example"},
	}
}

func (c *envSpyConn) Login(_ context.Context, env connector.Env) (connector.Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.envs = append(c.envs, env)
	return nil, connector.ErrNeedsLogin
}

func (c *envSpyConn) List(context.Context, connector.Session, connector.Period) ([]connector.DocumentRef, error) {
	return nil, errors.New("synthetic: List must not be reached")
}

func (c *envSpyConn) Fetch(context.Context, connector.Session, connector.DocumentRef) (io.ReadCloser, error) {
	return nil, errors.New("synthetic: Fetch must not be reached")
}

func (c *envSpyConn) envList() []connector.Env {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]connector.Env(nil), c.envs...)
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// TestSecretProviders_ProductionSchemes: a default build serves bw and
// keyring only. The e2e file provider is unknown: an e2e:// reference never
// reaches any provider (A3: e2e-only sources are absent from release builds).
func TestSecretProviders_ProductionSchemes(t *testing.T) {
	t.Parallel()
	e := newSandbox(t).env()
	ps, err := secretProviders(e)
	if err != nil {
		t.Fatalf("secretProviders: %v", err)
	}
	var schemes []string
	for _, p := range ps {
		schemes = append(schemes, p.Scheme())
	}
	slices.Sort(schemes)
	if want := wantSchemes(); !slices.Equal(schemes, want) {
		t.Fatalf("schemes = %q, want %q", schemes, want)
	}
	r, err := newSecretResolver(t.Context(), e, &config.Config{})
	if err != nil {
		t.Fatalf("newSecretResolver: %v", err)
	}
	t.Cleanup(func() {
		if err := r.CloseAll(); err != nil {
			t.Errorf("CloseAll: %v", err)
		}
	})
	if !e2eBuild {
		_, err := r.Resolve(t.Context(), "e2e://synthetic-item/password")
		if err == nil || (!errors.Is(err, secret.ErrNoProvider) && !errors.Is(err, secret.ErrInvalidRef)) {
			t.Fatalf("Resolve(e2e://…) in a default build = %v, want ErrNoProvider or ErrInvalidRef", err)
		}
	}
}
