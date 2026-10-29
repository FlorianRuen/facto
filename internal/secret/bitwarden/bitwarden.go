// Package bitwarden resolves bw://<uuid>/<field> references through the
// Bitwarden CLI (docs/spec.md, "Security and credentials", "Bitwarden
// unlock").
//
// Flow: `bw status` first; an injected session key (BW_SESSION from the
// user's terminal) is reused when the vault reports unlocked. Otherwise, in
// interactive mode only, the master password is read once and handed to
// `bw unlock --raw --passwordenv <NAME>` through that subprocess environment
// only. Items are fetched by UUID (`bw get item <uuid>`, `bw get totp
// <uuid>`), never by name, never through `bw list` or `bw serve`. The session
// key travels only in the BW_SESSION variable of each subprocess, never on
// argv. On Close and on any fatal error the provider runs `bw lock` (also
// after a rejected `bw unlock`, which may have unlocked the CLI) and wipes the
// session key.
//
// The provider never runs a process itself: it talks to a Runner. ExecRunner
// is the real one; tests use a fake.
package bitwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/FlorianRuen/facto/internal/secret"
)

// MaxOutput caps what the provider reads from each of bw's stdout and stderr.
// A larger output fails the command with ErrOutputTooLarge.
const MaxOutput = 64 << 10

// Sentinel errors. Use errors.Is.
var (
	// ErrLocked reports a locked vault that cannot be unlocked: no password
	// source (non-interactive run) or an earlier fatal error locked it.
	ErrLocked = errors.New("bitwarden: vault locked")
	// ErrNotLoggedIn reports `bw status` unauthenticated: run `bw login`.
	ErrNotLoggedIn = errors.New("bitwarden: not logged in (run bw login)")
	// ErrOutputTooLarge reports a bw output above MaxOutput.
	ErrOutputTooLarge = errors.New("bitwarden: bw output too large")
)

const (
	// sessionEnv is the variable bw reads its session key from.
	sessionEnv = "BW_SESSION"
	// unlockEnv names the unlock subprocess variable holding the master
	// password (bw unlock --passwordenv).
	unlockEnv = "FACTO_BW_MASTER_PASSWORD"
	// lockTimeout bounds bw lock, which runs even when the caller's context
	// is canceled.
	lockTimeout = 30 * time.Second
	// maxSessionKey bounds the session key printed by bw unlock --raw.
	maxSessionKey = 4096
)

// Command is one bw invocation.
type Command struct {
	// Args are the arguments after the binary name. They never hold a
	// secret.
	Args []string
	// Env holds the only variables the provider adds to the subprocess
	// environment (BW_SESSION, the master password variable). The runner
	// exposes them to that subprocess only.
	Env map[string]secret.Secret
	// Stdout and Stderr receive the command output. The provider caps them
	// at MaxOutput; a write past the cap returns ErrOutputTooLarge.
	Stdout, Stderr io.Writer
}

// Runner runs a bw command and waits for it. It returns a non-nil error when
// the command fails to start, exits non-zero, or a writer fails. The error must
// never contain the command's stdout or stderr, which can echo secrets.
type Runner interface {
	Run(ctx context.Context, cmd Command) error
}

// Options configure a Provider.
type Options struct {
	// Runner runs bw. Required.
	Runner Runner
	// Session is an existing session key (BW_SESSION of the user's
	// terminal), reused when bw status reports the vault unlocked. The
	// provider takes ownership: it is wiped on Close or when replaced.
	Session secret.Secret
	// Password reads the master password interactively. Nil means
	// non-interactive: a locked vault fails with ErrLocked. The returned
	// Secret is wiped once bw unlock has run.
	Password func(ctx context.Context) (secret.Secret, error)
}

// Provider resolves bw references. Safe for concurrent use: bw commands are
// serialized.
type Provider struct {
	runner   Runner
	password func(ctx context.Context) (secret.Secret, error)

	mu      sync.Mutex
	session secret.Secret
	ready   bool // bw status reported unlocked, or bw unlock succeeded
	// unlocking is set just before bw unlock runs: the CLI may have unlocked
	// its local state even when the provider rejects the result.
	unlocking bool
	failed    bool // a fatal error locked the vault for the rest of the run
	closed    bool
}

// New returns a provider. It fails when opts.Runner is nil.
func New(opts Options) (*Provider, error) {
	if opts.Runner == nil {
		return nil, errors.New("bitwarden: Options.Runner is nil")
	}
	return &Provider{runner: opts.Runner, password: opts.Password, session: opts.Session}, nil
}

// Scheme returns secret.SchemeBitwarden.
func (p *Provider) Scheme() string { return secret.SchemeBitwarden }

// String hides the provider state from fmt.
func (p *Provider) String() string { return "bitwarden.Provider" }

// GoString hides the provider state from %#v.
func (p *Provider) GoString() string { return p.String() }

// Resolve returns the username, password or current TOTP code of the item
// whose UUID is ref.Item.
//
// Errors: secret.ErrInvalidRef for a non-canonical ref (bw is not run),
// secret.ErrClosed after Close, ErrNotLoggedIn, ErrLocked,
// secret.ErrSecretNotFound for a missing item or an empty field. Any other
// failure (bw crash, unreadable or oversized output, another item returned,
// canceled context during a command) is fatal: the vault is locked, the
// session key wiped, and later calls fail with ErrLocked. Error messages
// never contain bw output.
func (p *Provider) Resolve(ctx context.Context, ref secret.Ref) (secret.Secret, error) {
	if err := validate(ref); err != nil {
		return secret.Secret{}, err
	}
	if err := ctx.Err(); err != nil {
		return secret.Secret{}, fmt.Errorf("bitwarden: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return secret.Secret{}, secret.ErrClosed
	}
	if p.failed {
		return secret.Secret{}, fmt.Errorf("bitwarden: locked after an earlier error: %w", ErrLocked)
	}
	if err := p.ensureSession(ctx); err != nil {
		return secret.Secret{}, err
	}
	s, err := p.fetch(ctx, ref)
	if err != nil {
		if errors.Is(err, secret.ErrSecretNotFound) {
			// A configuration problem, not a reason to lock the vault.
			return secret.Secret{}, err
		}
		return secret.Secret{}, p.fail(ctx, err)
	}
	return s, nil
}

// Close runs bw lock when a session key is held or bw unlock was run, then
// wipes the key. It waits for an in-flight Resolve to return;
// secret.Resolver.CloseAll cancels the in-flight ctx before calling Close, so
// the wait is bounded by the runner killing the subprocess. It is
// idempotent; later Resolve calls fail with secret.ErrClosed.
func (p *Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	return p.lock(context.Background())
}

// ensureSession makes sure p.session is an unlocked session key.
func (p *Provider) ensureSession(ctx context.Context) error {
	if p.ready {
		return nil
	}
	st, err := p.status(ctx)
	if err != nil {
		return p.fail(ctx, err)
	}
	switch {
	case st == "unauthenticated":
		return ErrNotLoggedIn
	case st == "unlocked" && !p.session.IsZero():
		p.ready = true
		return nil
	case p.password == nil:
		return ErrLocked
	}
	if err := p.unlock(ctx); err != nil {
		return p.fail(ctx, err)
	}
	p.ready = true
	return nil
}

// status runs bw status and returns "unlocked", "locked" or
// "unauthenticated".
func (p *Provider) status(ctx context.Context) (string, error) {
	var env map[string]secret.Secret
	if !p.session.IsZero() {
		env = map[string]secret.Secret{sessionEnv: p.session}
	}
	out, err := p.run(ctx, env, "status")
	if err != nil {
		return "", err
	}
	defer out.wipe()
	var doc struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(out.buf, &doc) != nil {
		return "", errors.New("bitwarden: unreadable bw status output")
	}
	switch doc.Status {
	case "unlocked", "locked", "unauthenticated":
		return doc.Status, nil
	}
	return "", errors.New("bitwarden: unknown bw status")
}

// unlock reads the master password and runs bw unlock --raw with it in the
// subprocess environment only.
func (p *Provider) unlock(ctx context.Context) error {
	pw, err := p.password(ctx)
	defer pw.Wipe()
	if err != nil {
		return fmt.Errorf("bitwarden: read master password: %w", err)
	}
	if pw.IsZero() {
		return errors.New("bitwarden: empty master password")
	}
	p.unlocking = true
	out, err := p.run(ctx, map[string]secret.Secret{unlockEnv: pw}, "unlock", "--raw", "--passwordenv", unlockEnv)
	pw.Wipe()
	if err != nil {
		return err
	}
	defer out.wipe()
	key := bytes.TrimSpace(out.buf)
	if !isSessionKey(key) {
		return errors.New("bitwarden: unexpected bw unlock output")
	}
	p.session.Wipe() // a stale injected session
	p.session = secret.New(bytes.Clone(key))
	return nil
}

// item is the part of `bw get item` output the provider reads.
type item struct {
	ID    string `json:"id"`
	Login *struct {
		Username *string `json:"username"`
		Password *string `json:"password"`
	} `json:"login"`
}

// fetch runs bw get for ref with the unlocked session.
func (p *Provider) fetch(ctx context.Context, ref secret.Ref) (secret.Secret, error) {
	env := map[string]secret.Secret{sessionEnv: p.session}
	kind := "item"
	if ref.Field == "totp" {
		kind = "totp"
	}
	out, err := p.run(ctx, env, "get", kind, ref.Item)
	if err != nil {
		if ce := (*commandError)(nil); errors.As(err, &ce) && ce.notFound {
			return secret.Secret{}, fmt.Errorf("bitwarden: %s %w", ref.Field, secret.ErrSecretNotFound)
		}
		return secret.Secret{}, err
	}
	defer out.wipe()

	if kind == "totp" {
		code := bytes.TrimSpace(out.buf)
		if !isTOTPCode(code) {
			return secret.Secret{}, errors.New("bitwarden: bw get totp did not print a code")
		}
		return secret.New(bytes.Clone(code)), nil
	}

	var it item
	if json.Unmarshal(out.buf, &it) != nil {
		return secret.Secret{}, errors.New("bitwarden: unreadable bw get item output")
	}
	if strings.ToLower(it.ID) != ref.Item {
		return secret.Secret{}, errors.New("bitwarden: bw returned another item than the requested UUID")
	}
	var v *string
	if it.Login != nil {
		v = it.Login.Password
		if ref.Field == "username" {
			v = it.Login.Username
		}
	}
	if v == nil || *v == "" {
		return secret.Secret{}, fmt.Errorf("bitwarden: empty %s: %w", ref.Field, secret.ErrSecretNotFound)
	}
	return secret.FromString(*v), nil
}

// fail handles a fatal error: bw lock, wipe the session, refuse later calls.
// It returns cause, joined with the lock error if any.
func (p *Provider) fail(ctx context.Context, cause error) error {
	p.failed = true
	return errors.Join(cause, p.lock(ctx))
}

// lock runs bw lock when a session key is held or bw unlock was run (its
// result may have been rejected after the CLI unlocked its local state), even
// when ctx is canceled, then wipes the key. Without a session key, bw lock
// runs without BW_SESSION: it needs none.
func (p *Provider) lock(ctx context.Context) error {
	p.ready = false
	if p.session.IsZero() && !p.unlocking {
		return nil
	}
	p.unlocking = false
	var env map[string]secret.Secret
	if !p.session.IsZero() {
		env = map[string]secret.Secret{sessionEnv: p.session}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lockTimeout)
	defer cancel()
	out, err := p.run(ctx, env, "lock")
	out.wipe()
	p.session.Wipe()
	return err
}

// run executes bw with capped outputs and returns stdout, which the caller
// wipes. Stderr is only classified, then wiped. On error stdout is wiped too.
// Errors never contain the output.
func (p *Provider) run(ctx context.Context, env map[string]secret.Secret, args ...string) (*capWriter, error) {
	stdout, stderr := &capWriter{}, &capWriter{}
	defer stderr.wipe()
	runErr := p.runner.Run(ctx, Command{Args: args, Env: env, Stdout: stdout, Stderr: stderr})
	var err error
	switch {
	case stdout.over || stderr.over:
		err = fmt.Errorf("bitwarden: bw %s: %w", args[0], ErrOutputTooLarge)
	case runErr != nil:
		err = &commandError{sub: args[0], err: runErr, ctxErr: ctx.Err(), notFound: isNotFound(stderr.buf)}
	default:
		return stdout, nil
	}
	stdout.wipe()
	return stdout, err
}

// isNotFound reports whether bw get failed because the item or its TOTP
// does not exist. Only exact messages are trusted.
func isNotFound(stderr []byte) bool {
	switch string(bytes.TrimSpace(stderr)) {
	case "Not found.", "No TOTP available for this login.":
		return true
	}
	return false
}

// isSessionKey reports whether b looks like a bw session key: printable
// ASCII without spaces, bounded length.
func isSessionKey(b []byte) bool {
	if len(b) == 0 || len(b) > maxSessionKey {
		return false
	}
	for _, c := range b {
		if c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

// isTOTPCode reports whether b is a 6 to 8 digit code.
func isTOTPCode(b []byte) bool {
	if len(b) < 6 || len(b) > 8 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// validate re-parses a possibly hand-built ref: only the canonical form of a
// bw reference (lowercase UUID, known field) is accepted.
func validate(ref secret.Ref) error {
	if ref.Scheme != secret.SchemeBitwarden {
		return fmt.Errorf("%w: bitwarden: wrong scheme", secret.ErrInvalidRef)
	}
	parsed, err := secret.ParseRef(ref.String())
	if err != nil {
		return fmt.Errorf("bitwarden: %w", err)
	}
	if parsed != ref {
		return fmt.Errorf("%w: bitwarden: not canonical", secret.ErrInvalidRef)
	}
	return nil
}

// commandError reports a failed bw command without its output or the
// runner's message (a runner may copy stderr, which can echo secrets, into
// its error). The runner error stays reachable through errors.As.
type commandError struct {
	sub      string
	err      error
	ctxErr   error
	notFound bool // bw reported a missing item or TOTP
}

func (e *commandError) Error() string {
	msg := "bitwarden: bw " + e.sub + " failed"
	var exit interface{ ExitCode() int }
	switch {
	case e.ctxErr != nil:
		msg += ": " + e.ctxErr.Error()
	case errors.As(e.err, &exit):
		msg += fmt.Sprintf(" (exit status %d)", exit.ExitCode())
	}
	return msg
}

func (e *commandError) GoString() string { return e.Error() }

// Unwrap returns the context error when the context ended, else the runner
// error.
func (e *commandError) Unwrap() []error {
	if e.ctxErr != nil {
		return []error{e.ctxErr, e.err}
	}
	return []error{e.err}
}

// capWriter buffers at most MaxOutput bytes. Growing copies and wipes the
// old buffer, so no stale copy of a secret stays behind.
type capWriter struct {
	buf  []byte
	over bool
}

func (w *capWriter) Write(b []byte) (int, error) {
	if w.over || len(w.buf)+len(b) > MaxOutput {
		w.over = true
		return 0, ErrOutputTooLarge
	}
	if need := len(w.buf) + len(b); need > cap(w.buf) {
		grown := make([]byte, len(w.buf), min(max(2*cap(w.buf), need, 512), MaxOutput))
		copy(grown, w.buf)
		clear(w.buf)
		w.buf = grown
	}
	w.buf = append(w.buf, b...)
	return len(b), nil
}

// wipe zeroes and drops the buffer.
func (w *capWriter) wipe() {
	clear(w.buf)
	w.buf = nil
}
