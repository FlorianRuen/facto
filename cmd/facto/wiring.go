package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/browser/cft"
	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/keyring"
	"github.com/FlorianRuen/facto/internal/vault"
)

// browserPool is what the CLI needs from the pool; *browser.Pool
// satisfies it.
type browserPool interface {
	connector.BrowserPool
	Close() error
}

var _ browserPool = (*browser.Pool)(nil)

// poolParams are the inputs of one pool.
type poolParams struct {
	StateDir    string       // cfg.StateDir (A12 fallback base <state>/tmp)
	Executable  string       // resolveBrowserPath; "" in collect when none
	Interactive bool         // true for `facto login` only (A6)
	Log         *slog.Logger // the run's redacting logger
	// Configure, when non-nil, adjusts the pool configuration (runHooks:
	// e2e builds only); nil in a release build.
	Configure func(browser.PoolConfig) (browser.PoolConfig, error)
}

// newBrowserPool builds the production pool. browser.NewPool sweeps the
// stale profiles a crashed run left behind (A12); it starts no browser.
func newBrowserPool(ctx context.Context, e env, p poolParams) (browserPool, error) {
	cfg := browser.PoolConfig{
		Host: browser.Host{
			Executable: p.Executable,
			Geteuid:    os.Geteuid,
			LookupEnv:  e.LookupEnv,
			Log:        p.Log,
		},
		StateDir:    p.StateDir,
		Interactive: p.Interactive,
	}
	if p.Configure != nil {
		var err error
		if cfg, err = p.Configure(cfg); err != nil {
			return nil, fmt.Errorf("pool config: %w", err)
		}
	}
	pool, err := browser.NewPool(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("new pool: %w", err)
	}
	return pool, nil
}

// buildPool calls e.NewPool, or newBrowserPool.
func buildPool(ctx context.Context, e env, p poolParams) (browserPool, error) {
	newPool := e.NewPool
	if newPool == nil {
		newPool = newBrowserPool
	}
	pool, err := newPool(ctx, e, p)
	if err != nil {
		return nil, fmt.Errorf("browser pool: %w", err)
	}
	return pool, nil
}

// errNoBrowser reports that no browser is configured or installed.
var errNoBrowser = errors.New("no browser: run `facto browser install`, or set browser.path in config.yaml to a Chrome for Testing binary")

// resolveBrowserPath returns the browser binary: browser.path when set
// (it must name an existing regular file, symlinks followed; otherwise an
// error wrapping config.ErrInvalid that names browser.path and never
// quotes the path), else the installed copy, else an error wrapping
// errNoBrowser.
func resolveBrowserPath(cfg *config.Config, installed func() (string, bool)) (string, error) {
	if p := cfg.Browser.Path; p != "" {
		fi, err := os.Stat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return "", fmt.Errorf("%w: browser.path: no such file", config.ErrInvalid)
		case err != nil:
			return "", fmt.Errorf("%w: browser.path: cannot be read", config.ErrInvalid)
		case !fi.Mode().IsRegular():
			return "", fmt.Errorf("%w: browser.path: not a regular file", config.ErrInvalid)
		}
		return p, nil
	}
	if installed != nil {
		if p, ok := installed(); ok && p != "" {
			return p, nil
		}
	}
	return "", errNoBrowser
}

// installedBrowser returns the executable of the Chrome for Testing build
// `facto browser install` verified under <stateDir>/chrome (cft.Verified:
// no symlink below stateDir followed, marker holding the pinned SHA-256),
// and ("", false) for anything else or on a platform without a pinned
// build. It never creates or modifies anything.
func installedBrowser(_ env, stateDir string) (string, bool) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || stateDir == "" {
		return "", false
	}
	m := cft.Pinned()
	state, err := fsx.Open(stateDir)
	if err != nil {
		return "", false
	}
	defer func() { _ = state.Close() }() // read-side handle
	dir, err := state.OpenDir(browserSubdir)
	if err != nil {
		return "", false
	}
	defer func() { _ = dir.Close() }() // read-side handle
	if !cft.Verified(dir, m) {
		return "", false
	}
	return filepath.Join(stateDir, browserSubdir, m.Version, "chrome-"+m.Platform, "chrome"), true
}

// runHooks are the test-only adjustments of one run. Every field is zero
// in a release build: only an e2e-tagged file of this package sets
// testRunHooks.
type runHooks struct {
	// Browser, when set, is the absolute Chrome path used in place of the
	// installed one (browser.path in config.yaml still wins).
	Browser string
	// NewHTTP builds the connector clients; nil = the orchestrator default.
	NewHTTP orchestrator.HTTPFactory
	// Pool adjusts the browser pool configuration; nil = none.
	Pool func(browser.PoolConfig) (browser.PoolConfig, error)
}

// testRunHooks is nil in every build but -tags e2e, where an e2e-only file
// of this package sets it at package initialization. Its error is a usage
// error naming the variable at fault, never quoting a value.
var testRunHooks func(e env) (runHooks, error)

// loadRunHooks returns the run's test hooks: none in a release build. An
// error is a configuration error (exit 2), returned before anything is
// built or contacted.
func loadRunHooks(e env) (runHooks, error) {
	if testRunHooks == nil {
		return runHooks{}, nil
	}
	h, err := testRunHooks(e)
	if err != nil {
		return runHooks{}, configError(err)
	}
	return h, nil
}

// installedWith returns installedFor(e, stateDir), or h.Browser when set.
func installedWith(e env, stateDir string, h runHooks) func() (string, bool) {
	if h.Browser != "" {
		return func() (string, bool) { return h.Browser, true }
	}
	return installedFor(e, stateDir)
}

// installedFor returns the InstalledBrowser seam of e bound to e and the
// configured state dir.
func installedFor(e env, stateDir string) func() (string, bool) {
	f := e.InstalledBrowser
	if f == nil {
		f = installedBrowser
	}
	return func() (string, bool) { return f(e, stateDir) }
}

// warnIfStalePin warns once (cft.WarnIfStale) when the browser in use is
// the installed pinned build: never for a browser.path set in config.yaml
// (user-supplied, unpinned), never when no browser was found.
func warnIfStalePin(ctx context.Context, e env, cfg *config.Config, exe string, log *slog.Logger) {
	if cfg.Browser.Path != "" || exe == "" {
		return
	}
	cft.WarnIfStale(ctx, log, e.Clock, cft.Pinned())
}

// sessionMode maps cfg.Sessions to the vault mode; any other value is an
// error.
func sessionMode(cfg *config.Config) (vault.Mode, error) {
	switch cfg.Sessions {
	case config.SessionsPersistent:
		return vault.Persistent, nil
	case config.SessionsEphemeral:
		return vault.Ephemeral, nil
	}
	return 0, fmt.Errorf("%w: sessions: want %s or %s", config.ErrInvalid, config.SessionsPersistent, config.SessionsEphemeral)
}

// keyringProbeRef is a keyring entry nobody writes: reading it tells
// whether the OS keyring answers at all.
const keyringProbeRef = "keyring://facto/keyring-probe"

// keyringProbeTimeout bounds the keyring probe of a non-interactive run.
// On Linux, go-keyring's Get first asks the Secret Service to Unlock the
// login collection, even for an entry that does not exist: a locked
// keyring then shows an unlock dialog and the call waits for an answer.
// Nobody answers it in a scheduled run, so the probe gives up after this
// bound and the run's sessions are ephemeral (one warning) instead of
// hanging for the provider's own, longer bound (keyring.DefaultTimeout).
// An interactive run keeps that longer bound so the user can unlock.
const keyringProbeTimeout = 2 * time.Second

// defaultKeyBackend returns the OS keyring after one probe read: a missing
// entry means the keyring works; any other error means there is none
// usable (no Secret Service, locked, timed out), and sessions become
// ephemeral for the run (A3). See keyringProbeTimeout for the unlock
// dialog the probe may trigger.
func defaultKeyBackend(ctx context.Context, _ env) (vault.KeyBackend, error) {
	ref, err := secret.ParseRef(keyringProbeRef)
	if err != nil {
		return nil, fmt.Errorf("keyring probe: %w", err)
	}
	p := keyring.New(keyring.System())
	v, err := p.Resolve(ctx, ref)
	v.Wipe()
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return nil, fmt.Errorf("keyring probe: %w", err)
	}
	return p, nil
}

// openSessions opens the session store of the state dir (which must
// exist): the mode comes from sessions:, the key backend from e.KeyBackend
// (or the OS keyring). Without a keyring a persistent store is ephemeral
// for the run and logs one warning (A3). Ephemeral mode removes every saved
// session file unread (A13) and deletes their keys (ADR 0009: a backed-up
// .sess must not stay decryptable), so it asks for the key backend only
// when sessions/ holds a .sess file: a run with nothing to clean never
// triggers a keyring unlock dialog; without a keyring the files are still
// removed and one warning says their keys were not. A non-interactive run
// bounds the keyring probe with keyringProbeTimeout.
func openSessions(ctx context.Context, e env, cfg *config.Config, log *slog.Logger, interactive bool) (*vault.Store, error) {
	mode, err := sessionMode(cfg)
	if err != nil {
		return nil, err
	}
	opts := vault.Options{StateDir: cfg.StateDir, Mode: mode, Rand: rand.Reader, Log: log}
	switch {
	case mode == vault.Persistent:
		opts.Keyring, opts.KeyringErr = probeKeyBackend(ctx, e, interactive)
	case hasSessionFiles(cfg.StateDir):
		opts.Keyring, opts.KeyringErr = probeKeyBackend(ctx, e, interactive)
		if opts.KeyringErr != nil {
			log.WarnContext(ctx, "vault: keyring unavailable, keys of removed sessions not deleted", "cause", opts.KeyringErr.Error())
		}
	}
	st, err := vault.NewStore(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("sessions: %w", err)
	}
	return st, nil
}

// hasSessionFiles reports whether <stateDir>/sessions holds a *.sess entry
// (names only, nothing is opened). A sessions/ it cannot list counts as
// holding some, so their keys are not skipped by mistake.
func hasSessionFiles(stateDir string) bool {
	root, err := fsx.Open(stateDir)
	if err != nil {
		return true
	}
	defer func() { _ = root.Close() }() // read-only
	dir, err := root.OpenDir(vault.SessionsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	defer func() { _ = dir.Close() }() // read-only
	des, err := dir.ReadDir()
	if err != nil {
		return true
	}
	return slices.ContainsFunc(des, func(de fs.DirEntry) bool {
		return !de.IsDir() && strings.HasSuffix(de.Name(), ".sess")
	})
}

// probeKeyBackend calls e.KeyBackend (or defaultKeyBackend), bounded by
// keyringProbeTimeout when the run is not interactive.
func probeKeyBackend(ctx context.Context, e env, interactive bool) (vault.KeyBackend, error) {
	keyBackend := e.KeyBackend
	if keyBackend == nil {
		keyBackend = defaultKeyBackend
	}
	if !interactive {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, keyringProbeTimeout)
		defer cancel()
	}
	kb, err := keyBackend(ctx, e)
	if err != nil {
		return nil, err
	}
	return kb, nil
}

// registerTestConnectors is nil in every build but -tags e2e, where an
// e2e-only file of this package sets it to fakeprovider.Register at
// package initialization (the release build never links
// connectors/fakeprovider).
var registerTestConnectors func(r *connector.Registry) error

// availableConnectors returns a new registry of the connectors this build
// ships: none in a release build, fakeprovider in an e2e build.
func availableConnectors() (*connector.Registry, error) {
	r := connector.NewRegistry()
	if registerTestConnectors != nil {
		if err := registerTestConnectors(r); err != nil {
			return nil, fmt.Errorf("register test connectors: %w", err)
		}
	}
	return r, nil
}

// shippedConnectors calls e.Connectors, or availableConnectors.
func shippedConnectors(e env) (*connector.Registry, error) {
	f := e.Connectors
	if f == nil {
		f = availableConnectors
	}
	return f()
}

// credentials returns the configured secret references of every
// connector, by id.
func credentials(cfg *config.Config) map[string]connector.Credentials {
	out := make(map[string]connector.Credentials, len(cfg.Connectors))
	for id, c := range cfg.Connectors {
		out[id] = connector.Credentials{Login: c.Login, Password: c.Password, OTP: c.OTP}
	}
	return out
}

// enabledRegistry returns the shipped connectors enabled in cfg, in the
// shipped order. An enabled connector this build does not ship is a
// configuration error naming the first one (sorted), rather than a
// silently skipped account.
func enabledRegistry(cfg *config.Config, shipped *connector.Registry) (*connector.Registry, error) {
	var missing []string
	for id, c := range cfg.Connectors {
		if _, ok := shipped.Get(id); c.Enabled && !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return nil, fmt.Errorf("connectors.%s: connector not available in this version (set enabled: false)", missing[0])
	}
	r := connector.NewRegistry()
	for _, c := range shipped.All() {
		if cc, ok := cfg.Connectors[c.Info().ID]; ok && cc.Enabled {
			if err := r.Register(c); err != nil {
				return nil, fmt.Errorf("connectors.%s: %w", c.Info().ID, err)
			}
		}
	}
	return r, nil
}
