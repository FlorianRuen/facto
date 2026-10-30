package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/vault"
)

// SessionStore is the saved-session store (*vault.Store implements it).
// Load returns an error wrapping vault.ErrNoSession when there is nothing
// usable to restore.
type SessionStore interface {
	Persistent() bool
	Load(ctx context.Context, id string) (secret.Secret, error)
	Save(ctx context.Context, id string, blob secret.Secret) error
	Delete(ctx context.Context, id string) error
}

// Session phases, logged when a restore, a save or a drop fails.
const (
	phaseRestore = "restore"
	phaseSave    = "save"
)

// Fixed report notes. They never carry error text or supplier data.
const (
	noteSessionNotSaved = "session not saved: the next run logs in again"
	noteLoginPrefix     = "login required: run `facto login "
	noteLoginSuffix     = "`"
)

// errLoginOnly reports a browser launch outside Login.
var errLoginOnly = errors.New("orchestrator: browser is available during login only")

// sessionsOn reports whether saved sessions are read and written this run.
func (o *Orchestrator) sessionsOn() bool {
	return o.sessions != nil && o.sessions.Persistent()
}

// restore loads the saved session of id. A missing session is silent; any
// other error logs one warning and yields a zero Secret (the saved session is
// kept: it may be readable next run).
func (o *Orchestrator) restore(ctx context.Context, cr *connRun, id string) secret.Secret {
	if !o.sessionsOn() {
		return secret.Secret{}
	}
	cr.phase = phaseRestore
	blob, err := o.sessions.Load(ctx, id)
	switch {
	case err == nil:
		return blob
	case errors.Is(err, vault.ErrNoSession):
	default:
		cr.log.LogAttrs(ctx, slog.LevelWarn, "saved session not restored; logging in again",
			slog.String("phase", cr.phase),
			slog.Bool("keyring", errors.Is(err, vault.ErrKeyring)),
			slog.Any("error", err))
	}
	blob.Wipe()
	return secret.Secret{}
}

// save persists sess after a successful Login when it implements
// connector.Persistable. A failed Persist or Save is a warning and a report
// note, never a connector failure; fsx.ErrNotDurable counts as saved.
func (o *Orchestrator) save(ctx context.Context, cr *connRun, id string, sess connector.Session) {
	p, ok := sess.(connector.Persistable)
	if !ok || !o.sessionsOn() {
		return
	}
	cr.phase = phaseSave
	blob, err := p.Persist(ctx)
	defer blob.Wipe()
	if err == nil {
		err = o.sessions.Save(ctx, id, blob)
	}
	if err == nil || errors.Is(err, fsx.ErrNotDurable) {
		return
	}
	cr.res.Notes = append(cr.res.Notes, noteSessionNotSaved)
	cr.log.LogAttrs(ctx, slog.LevelWarn, "session not saved; the next run logs in again",
		slog.String("phase", cr.phase),
		slog.Any("error", err))
}

// rejected reports whether err means the supplier refused a restored
// session, and drops that session from the store when it does.
func (o *Orchestrator) rejected(ctx context.Context, cr *connRun, id string, restored bool, err error) bool {
	if !restored || !o.sessionsOn() || ctx.Err() != nil {
		return false
	}
	if !errors.Is(err, connector.ErrNeedsLogin) && !errors.Is(err, connector.ErrAuthFailed) {
		return false
	}
	if derr := o.sessions.Delete(ctx, id); derr != nil {
		cr.log.LogAttrs(ctx, slog.LevelWarn, "rejected saved session not removed",
			slog.String("phase", cr.phase),
			slog.Any("error", derr))
	}
	return true
}

// loginNote is the fixed note of a needs_login connector. id is a valid
// connector id (connector.ValidateInfo).
func loginNote(id string) string {
	return noteLoginPrefix + id + noteLoginSuffix
}

// loginBrowser is the connector.BrowserPool handed to a connector's Login.
// It launches with the connector's own allowlist, tracks every browser and,
// once Login returns, closes those still open and refuses any new launch.
type loginBrowser struct {
	pool    connector.BrowserPool
	allowed []string

	mu       sync.Mutex
	done     bool
	browsers []*trackedBrowser
}

var _ connector.BrowserPool = (*loginBrowser)(nil)

func newLoginBrowser(pool connector.BrowserPool, allowed []string) *loginBrowser {
	return &loginBrowser{pool: pool, allowed: slices.Clone(allowed)}
}

// Launch launches a browser restricted to the connector's
// Info().AllowedDomains, whatever opts says. After Login it returns
// errLoginOnly without reaching the pool.
//
// l.mu is held while the pool launches, so that finish never misses a
// browser launched concurrently: the pool's Launch must honour ctx (return
// promptly once it is done), or the close-after-Login sweep waits on l.mu
// for as long as the launch blocks.
func (l *loginBrowser) Launch(ctx context.Context, opts connector.LaunchOptions) (connector.Browser, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return nil, errLoginOnly
	}
	b, err := l.pool.Launch(ctx, connector.LaunchOptions{AllowedDomains: slices.Clone(l.allowed), Visible: opts.Visible})
	if err != nil {
		return nil, fmt.Errorf("launch browser: %w", err)
	}
	if b == nil {
		return nil, errors.New("orchestrator: browser pool returned no browser")
	}
	t := &trackedBrowser{Browser: b}
	l.browsers = append(l.browsers, t)
	return t, nil
}

// finish refuses further launches and closes every browser still open. It
// returns how many were left open.
func (l *loginBrowser) finish() int {
	l.mu.Lock()
	l.done = true
	bs := l.browsers
	l.browsers = nil
	l.mu.Unlock()
	open := 0
	for _, b := range bs {
		if b.closeIfOpen() {
			open++
		}
	}
	return open
}

// trackedBrowser forwards to the pool's browser and closes it at most once.
type trackedBrowser struct {
	connector.Browser

	mu     sync.Mutex
	closed bool
	err    error
}

// Close closes the browser once; later calls return the first result.
func (t *trackedBrowser) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.closed = true
		t.err = t.Browser.Close()
	}
	return t.err
}

// closeIfOpen closes the browser when the connector did not, and reports
// whether it had to. A panicking Close is recovered (value withheld).
func (t *trackedBrowser) closeIfOpen() (wasOpen bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.closed = true
	defer func() {
		if recover() != nil {
			// The panic value is withheld, as in Orchestrator.recovered.
			t.err = errors.New("orchestrator: browser close panicked")
			wasOpen = true
		}
	}()
	t.err = t.Browser.Close()
	return true
}

// login runs c.Login with the restored blob and the login-only browser.
// Whatever Login does (return or panic), the blob is wiped and every browser
// still open is closed, with one warning, before it returns.
func (o *Orchestrator) login(ctx context.Context, cr *connRun, c connector.Connector, env connector.Env, lb *loginBrowser) (connector.Session, error) {
	defer func() {
		env.Saved.Wipe()
		if lb == nil {
			return
		}
		if n := lb.finish(); n > 0 {
			cr.log.LogAttrs(ctx, slog.LevelWarn, "browser left open by login; closed",
				slog.String("phase", phaseLogin),
				slog.Int("browsers", n))
		}
	}()
	cr.phase = phaseLogin
	sess, err := c.Login(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}
	return sess, nil
}
