// Synthetic doubles for the J1 T19 tests (login_test.go, sessions_test.go,
// prompt_secret_test.go, startup_unix_test.go): an in-memory key backend, a
// spy browser pool, a fake terminal, a canary secret resolver and a
// synthetic connector. None touches the OS keyring, a real browser, the
// network or the real terminal. The expected production API is documented
// in login_test.go.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/config"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/keyring"
	"github.com/FlorianRuen/facto/internal/vault"
)

// The doubles satisfy the CLI's seams.
var (
	_ browserPool      = (*spyPool)(nil)
	_ vault.KeyBackend = (*memKeys)(nil)
	_ terminal         = (*fakeTerminal)(nil)
)

// errNoTestKeyring is the cause the sandbox reports for "no OS keyring".
var errNoTestKeyring = errors.New("synthetic: no keyring in tests")

// noKeyring is the sandbox KeyBackend seam: no OS keyring, so persistent
// sessions fall back to ephemeral with one warning (A3).
func noKeyring(context.Context, env) (vault.KeyBackend, error) {
	return nil, errNoTestKeyring
}

// noInstalledBrowser is the sandbox InstalledBrowser seam: nothing was
// installed with `facto browser install`.
func noInstalledBrowser(env) (string, bool) { return "", false }

// ------------------------------------------------------------ key backend

// memKeys is an in-memory vault.KeyBackend counting its calls.
type memKeys struct {
	mu       sync.Mutex
	m        map[string]string
	resolves int
	sets     int
	deletes  int
	built    int // KeyBackend seam calls
}

func newMemKeys() *memKeys { return &memKeys{m: map[string]string{}} }

func (k *memKeys) Resolve(_ context.Context, ref secret.Ref) (secret.Secret, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.resolves++
	v, ok := k.m[ref.String()]
	if !ok {
		return secret.Secret{}, keyring.ErrNotFound
	}
	return secret.FromString(v), nil
}

func (k *memKeys) Set(_ context.Context, ref secret.Ref, value secret.Secret) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.sets++
	k.m[ref.String()] = value.Expose()
	return nil
}

func (k *memKeys) Delete(_ context.Context, ref secret.Ref) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.deletes++
	delete(k.m, ref.String())
	return nil
}

// factory is the KeyBackend seam handing out k.
func (k *memKeys) factory() func(context.Context, env) (vault.KeyBackend, error) {
	return func(context.Context, env) (vault.KeyBackend, error) {
		k.mu.Lock()
		defer k.mu.Unlock()
		k.built++
		return k, nil
	}
}

func (k *memKeys) counts() (resolves, sets, deletes, built int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.resolves, k.sets, k.deletes, k.built
}

// countingNoKeyring is a KeyBackend seam reporting no keyring and counting
// its calls.
type countingNoKeyring struct {
	mu    sync.Mutex
	calls int
}

func (c *countingNoKeyring) factory() func(context.Context, env) (vault.KeyBackend, error) {
	return func(context.Context, env) (vault.KeyBackend, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.calls++
		return nil, errNoTestKeyring
	}
}

func (c *countingNoKeyring) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// loadSession opens the store of stateDir with keys and loads id, the way
// the next run would.
func loadSession(ctx context.Context, stateDir string, keys vault.KeyBackend, id string) (secret.Secret, error) {
	st, err := vault.NewStore(ctx, vault.Options{
		StateDir: stateDir,
		Mode:     vault.Persistent,
		Keyring:  keys,
		Rand:     rand.Reader,
		Log:      slog.New(slog.DiscardHandler),
	})
	if err != nil {
		return secret.Secret{}, fmt.Errorf("new store: %w", err)
	}
	return st.Load(ctx, id)
}

// ------------------------------------------------------------ browser pool

// spyPool is a browser pool recording how the CLI builds, uses and closes
// it. It never starts a process.
type spyPool struct {
	mu       sync.Mutex
	newErr   error
	params   []poolParams
	launches []connector.LaunchOptions
	closed   int
	// cookie is the value of the one cookie its browsers return.
	cookie string
}

// factory is the NewPool seam handing out p (or failing with p.newErr).
func (p *spyPool) factory() func(context.Context, env, poolParams) (browserPool, error) {
	return func(_ context.Context, _ env, pp poolParams) (browserPool, error) {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.params = append(p.params, pp)
		if p.newErr != nil {
			return nil, p.newErr
		}
		return p, nil
	}
}

func (p *spyPool) Launch(_ context.Context, opts connector.LaunchOptions) (connector.Browser, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed > 0 {
		return nil, errors.New("synthetic: launch on a closed pool")
	}
	opts.AllowedDomains = slices.Clone(opts.AllowedDomains)
	p.launches = append(p.launches, opts)
	return &fakeBrowser{cookie: p.cookie}, nil
}

func (p *spyPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed++
	return nil
}

// snapshot returns copies of what was recorded.
func (p *spyPool) snapshot() (params []poolParams, launches []connector.LaunchOptions, closed int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.params), slices.Clone(p.launches), p.closed
}

// fakeBrowser is a connector.Browser that does nothing.
type fakeBrowser struct {
	cookie string
}

func (*fakeBrowser) Navigate(context.Context, string) error { return nil }

func (*fakeBrowser) WaitVisible(context.Context, string) error { return nil }

func (*fakeBrowser) TypeSecret(context.Context, string, secret.Secret) error { return nil }

func (*fakeBrowser) Click(context.Context, string) error { return nil }

func (*fakeBrowser) CurrentURL(context.Context) (string, error) {
	return "https://login.synthlogin.example/done", nil
}

func (b *fakeBrowser) Cookies(context.Context, []string) ([]connector.Cookie, error) {
	if b.cookie == "" {
		return nil, nil
	}
	return []connector.Cookie{{Name: "synth_sid", Value: secret.FromString(b.cookie), Domain: "login.synthlogin.example", Path: "/", Secure: true, HTTPOnly: true}}, nil
}

func (*fakeBrowser) Close() error { return nil }

// ---------------------------------------------------------------- terminal

// fakeTerminal is the terminal seam: it says whether stdin is a terminal
// and serves no-echo answers in order (io.EOF once exhausted). It never
// reads the reader it is given.
type fakeTerminal struct {
	mu      sync.Mutex
	tty     bool
	answers []string
	reads   int
}

func (f *fakeTerminal) IsTerminal(io.Reader) bool { return f.tty }

func (f *fakeTerminal) ReadNoEcho(io.Reader) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if len(f.answers) == 0 {
		return nil, io.EOF
	}
	a := f.answers[0]
	f.answers = f.answers[1:]
	return []byte(a), nil
}

func (f *fakeTerminal) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// ---------------------------------------------------------------- resolver

// canaryResolver resolves configured references to synthetic values and
// records its lifecycle.
type canaryResolver struct {
	mu     sync.Mutex
	values map[string]string // ref -> value
	built  int
	closed int
}

func (r *canaryResolver) Resolve(_ context.Context, ref string) (secret.Secret, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.values[ref]
	if !ok {
		return secret.Secret{}, secret.ErrSecretNotFound
	}
	return secret.FromString(v), nil
}

func (r *canaryResolver) CloseAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed++
	return nil
}

func (r *canaryResolver) factory() func(context.Context, env, *config.Config) (secretResolver, error) {
	return func(context.Context, env, *config.Config) (secretResolver, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.built++
		return r, nil
	}
}

func (r *canaryResolver) counts() (built, closed int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.built, r.closed
}

// --------------------------------------------------------------- connector

// synthID is the id of the synthetic connector shipped by the test
// catalog; synthPasswordRef is its configured password reference.
const (
	synthID          = "synthlogin"
	synthPasswordRef = "keyring://facto/synthlogin/" + "password"
)

// synthDomains is the synthetic connector's allowlist.
var synthDomains = []string{"login.synthlogin.example", "www.synthlogin.example"}

// synthLabel is a hostile OTP prompt label, as a supplier page could
// produce: an OSC title change, a colour sequence and a bidi override.
const synthLabel = "Code sent by \x1b]0;pwned\x07SMS \x1b[31mnow\u202e"

// synthConn is a synthetic connector. Login records its Env, resolves the
// password reference, optionally launches a browser and prompts for a code,
// logs every secret it saw through Env.Log (masked by secret.Secret), then
// returns loginErr or a session (Persistable when persist != "").
type synthConn struct {
	persist  string // session blob; "" = session is not Persistable
	loginErr error
	launch   bool // launch a browser during Login
	visible  bool // LaunchOptions.Visible asked by the connector
	prompt   bool // ask for a code during Login
	wantOTP  string
	onLogin  func() // called at the start of Login (e.g. cancel the run)

	mu        sync.Mutex
	envs      []connector.Env
	otpOK     bool // the code returned by Env.Prompt was wantOTP
	promptErr error
	listed    int
	fetched   int
}

func (c *synthConn) Info() connector.Info {
	return connector.Info{
		ID:             synthID,
		Name:           "Synthetic login",
		Category:       "energy",
		Kinds:          []connector.DocKind{connector.Invoice},
		AllowedDomains: slices.Clone(synthDomains),
	}
}

func (c *synthConn) Login(ctx context.Context, env connector.Env) (connector.Session, error) {
	if c.onLogin != nil {
		c.onLogin()
	}
	c.mu.Lock()
	c.envs = append(c.envs, env)
	c.mu.Unlock()

	var seen []any
	if env.Secrets != nil && env.Credentials.Password != "" {
		pw, err := env.Secrets.Resolve(ctx, env.Credentials.Password)
		if err == nil {
			seen = append(seen, "password", pw)
		}
	}
	if c.launch && env.Browser != nil {
		b, err := env.Browser.Launch(ctx, connector.LaunchOptions{AllowedDomains: []string{"evil.example"}, Visible: c.visible})
		if err != nil {
			return nil, fmt.Errorf("synthetic launch: %w", err)
		}
		cookies, _ := b.Cookies(ctx, synthDomains)
		for _, ck := range cookies {
			seen = append(seen, "cookie", ck.Value)
		}
		_ = b.Close()
	}
	if c.prompt && env.Prompt != nil {
		otp, err := env.Prompt.Prompt(ctx, connector.PromptRequest{Label: synthLabel})
		c.mu.Lock()
		c.promptErr = err
		c.otpOK = err == nil && otp.Expose() == c.wantOTP
		c.mu.Unlock()
		if err != nil {
			return nil, fmt.Errorf("synthetic prompt: %w", err)
		}
		seen = append(seen, "otp", otp)
	}
	if env.Log != nil {
		env.Log.WarnContext(ctx, "synthetic login saw secrets", seen...)
	}
	if c.loginErr != nil {
		return nil, c.loginErr
	}
	if c.persist != "" {
		return persistSession{blob: c.persist}, nil
	}
	return plainSession{}, nil
}

func (c *synthConn) List(context.Context, connector.Session, connector.Period) ([]connector.DocumentRef, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.listed++
	return nil, nil
}

func (c *synthConn) Fetch(context.Context, connector.Session, connector.DocumentRef) (io.ReadCloser, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fetched++
	return nil, errors.New("synthetic: Fetch must not be reached")
}

func (c *synthConn) state() (envs []connector.Env, listed, fetched int, otpOK bool, promptErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.envs), c.listed, c.fetched, c.otpOK, c.promptErr
}

// catalog is a Connectors seam shipping c only.
func (c *synthConn) catalog() func() (*connector.Registry, error) {
	return func() (*connector.Registry, error) {
		r := connector.NewRegistry()
		if err := r.Register(c); err != nil {
			return nil, err
		}
		return r, nil
	}
}

// persistSession is a connector.Persistable session.
type persistSession struct{ blob string }

func (s persistSession) Persist(context.Context) (secret.Secret, error) {
	return secret.FromString(s.blob), nil
}

// plainSession is a session that cannot be saved.
type plainSession struct{}

// ------------------------------------------------------------------ config

// synthConfig is validConfig plus the synthetic connector (enabled or not)
// with its password reference, an optional browser.path and optional extra
// lines: indented extra lines ("  ileo: {…}") are more connectors entries,
// unindented ones are top-level keys.
func synthConfig(enabled bool, browserPath, extra string) string {
	var b strings.Builder
	b.WriteString(validConfig)
	fmt.Fprintf(&b, "connectors:\n  %s: { enabled: %t, category: energy, password: '%s' }\n", synthID, enabled, synthPasswordRef)
	if strings.HasPrefix(extra, "  ") {
		b.WriteString(extra)
		extra = ""
	}
	if browserPath != "" {
		fmt.Fprintf(&b, "browser:\n  path: '%s'\n", browserPath)
	}
	b.WriteString(extra)
	return b.String()
}

// fakeChrome writes a synthetic regular file standing for the browser
// binary under the sandbox home and returns its absolute path. The spy pool
// never runs it.
func (s *sandbox) fakeChrome(t *testing.T) string {
	t.Helper()
	writeFile(t, s.home, "bin/chrome", []byte("synthetic browser binary\n"))
	return filepath.Join(s.home, "bin", "chrome")
}
