// Fakes for the session restore/save and login-only browser tests (J1 task
// T18). Everything is synthetic: connector ids, blobs and domains are made
// up. The fakes stand in for *vault.Store and the internal/browser pool: the
// orchestrator only sees its consumer-side interfaces.
package orchestrator_test

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/vault"
)

// The real store must satisfy the orchestrator's view of it, so the CLI can
// wire *vault.Store directly (this pins vault.Store.Delete, added by T18).
var _ orchestrator.SessionStore = (*vault.Store)(nil)

// fakeSessions is an in-memory orchestrator.SessionStore. It records every
// call in the shared event log ("load:<id>", "save:<id>", "delete:<id>") and
// keeps exposed copies of the blobs (test only).
type fakeSessions struct {
	ev         *events
	persistent bool

	mu        sync.Mutex
	blobs     map[string]string // id -> saved blob
	loadErr   map[string]error  // id -> forced Load error
	saveErr   error
	deleteErr error
	loads     []string
	saves     []string
	deletes   []string
	returned  []secret.Secret // what Load handed out, to check it is wiped
}

func newFakeSessions(ev *events, persistent bool) *fakeSessions {
	return &fakeSessions{ev: ev, persistent: persistent, blobs: map[string]string{}, loadErr: map[string]error{}}
}

func (f *fakeSessions) Persistent() bool { return f.persistent }

func (f *fakeSessions) Load(_ context.Context, id string) (secret.Secret, error) {
	f.ev.add("load:%s", id)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loads = append(f.loads, id)
	if err := f.loadErr[id]; err != nil {
		return secret.Secret{}, err
	}
	b, ok := f.blobs[id]
	if !ok {
		return secret.Secret{}, vault.ErrNoSession
	}
	s := secret.FromString(b)
	f.returned = append(f.returned, s)
	return s, nil
}

func (f *fakeSessions) Save(_ context.Context, id string, blob secret.Secret) error {
	f.ev.add("save:%s", id)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saves = append(f.saves, id)
	if f.saveErr != nil {
		return f.saveErr
	}
	f.blobs[id] = blob.Expose()
	return nil
}

func (f *fakeSessions) Delete(_ context.Context, id string) error {
	f.ev.add("delete:%s", id)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, id)
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.blobs, id)
	return nil
}

func (f *fakeSessions) put(id, blob string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blobs[id] = blob
}

func (f *fakeSessions) blob(id string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.blobs[id]
	return b, ok
}

func (f *fakeSessions) calls() (loads, saves, deletes []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.loads), slices.Clone(f.saves), slices.Clone(f.deletes)
}

func (f *fakeSessions) handedOut() []secret.Secret {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.returned)
}

func withSessions(s orchestrator.SessionStore) rigOpt {
	return func(d *orchestrator.Deps) { d.Sessions = s }
}

func withBrowser(p connector.BrowserPool) rigOpt {
	return func(d *orchestrator.Deps) { d.Browser = p }
}

// persistSession is a connector session that implements
// connector.Persistable. secretField stands for the live cookies it holds:
// it must never be formatted into a log or a report.
type persistSession struct {
	secretField string
	blob        string
	err         error

	mu       sync.Mutex
	persists int
	handed   []secret.Secret // what Persist returned, to check it is wiped
}

var _ connector.Persistable = (*persistSession)(nil)

func (s *persistSession) Persist(context.Context) (secret.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persists++
	if s.err != nil {
		return secret.Secret{}, s.err
	}
	sec := secret.FromString(s.blob)
	s.handed = append(s.handed, sec)
	return sec, nil
}

func (s *persistSession) persistCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.persists
}

func (s *persistSession) handedOut() []secret.Secret {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.handed)
}

// sessConn is a fakeConn whose Login returns sess (when non-nil) instead of
// its plain *fakeSession, and records what Env.Saved held during Login.
type sessConn struct {
	*fakeConn
	sess connector.Session

	smu   sync.Mutex
	saved []string // Env.Saved exposed during each Login ("" = zero)
	zero  []bool
}

func newSessConn(ev *events, id string, sess connector.Session, refs ...connector.DocumentRef) *sessConn {
	return &sessConn{fakeConn: newFakeConn(ev, id, refs...), sess: sess}
}

func (c *sessConn) Login(ctx context.Context, env connector.Env) (connector.Session, error) {
	c.smu.Lock()
	c.saved = append(c.saved, env.Saved.Expose())
	c.zero = append(c.zero, env.Saved.IsZero())
	c.smu.Unlock()
	s, err := c.fakeConn.Login(ctx, env)
	if err != nil {
		return nil, err
	}
	if c.sess != nil {
		return c.sess, nil
	}
	return s, nil
}

func (c *sessConn) savedSeen() ([]string, []bool) {
	c.smu.Lock()
	defer c.smu.Unlock()
	return slices.Clone(c.saved), slices.Clone(c.zero)
}

// fakePool is a connector.BrowserPool that records launches. Every browser
// it hands out records its Close calls in the shared event log
// ("browser-launch:<n>", "browser-close:<n>").
type fakePool struct {
	ev *events

	mu       sync.Mutex
	opts     []connector.LaunchOptions
	browsers []*fakeBrowser
}

func (p *fakePool) Launch(_ context.Context, opts connector.LaunchOptions) (connector.Browser, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.browsers)
	p.ev.add("browser-launch:%d", n)
	p.opts = append(p.opts, connector.LaunchOptions{AllowedDomains: slices.Clone(opts.AllowedDomains), Visible: opts.Visible})
	b := &fakeBrowser{ev: p.ev, n: n}
	p.browsers = append(p.browsers, b)
	return b, nil
}

func (p *fakePool) launched() ([]connector.LaunchOptions, []*fakeBrowser) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.opts), slices.Clone(p.browsers)
}

// fakeBrowser is an inert connector.Browser.
type fakeBrowser struct {
	ev *events
	n  int

	mu     sync.Mutex
	closes int
}

func (*fakeBrowser) Navigate(context.Context, string) error                  { return nil }
func (*fakeBrowser) WaitVisible(context.Context, string) error               { return nil }
func (*fakeBrowser) TypeSecret(context.Context, string, secret.Secret) error { return nil }
func (*fakeBrowser) Click(context.Context, string) error                     { return nil }
func (*fakeBrowser) CurrentURL(context.Context) (string, error) {
	return "https://login.alpha.example/", nil
}

func (*fakeBrowser) Cookies(context.Context, []string) ([]connector.Cookie, error) {
	return nil, nil
}

func (b *fakeBrowser) Close() error {
	b.ev.add("browser-close:%d", b.n)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closes++
	return nil
}

func (b *fakeBrowser) closeCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closes
}

// errSynthetic builds a synthetic store or connector error.
func errSynthetic(what string, wrapped error) error {
	if wrapped == nil {
		return fmt.Errorf("synthetic %s failure", what)
	}
	return fmt.Errorf("synthetic %s failure: %w", what, wrapped)
}
