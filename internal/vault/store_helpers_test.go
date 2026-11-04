package vault_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/keyring"
	"github.com/FlorianRuen/facto/internal/vault"
)

// The production keyring provider must satisfy the store's consumer-side
// interface.
var _ vault.KeyBackend = (*keyring.Provider)(nil)

// ---------------------------------------------------------------- keyring

// fakeKeys is an in-memory vault.KeyBackend that records every call. Missing
// entries resolve to keyring.ErrNotFound like the real provider.
type fakeKeys struct {
	mu       sync.Mutex
	m        map[string]string // ref.String() -> value
	resolves []secret.Ref
	sets     []secret.Ref
	deletes  []secret.Ref

	resolveErr error
	setErr     error
	// yield, when set, makes Set reschedule a few times before and after
	// writing, to widen interleavings in concurrency tests.
	yield bool
}

func newFakeKeys() *fakeKeys { return &fakeKeys{m: map[string]string{}} }

func (f *fakeKeys) Resolve(_ context.Context, ref secret.Ref) (secret.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolves = append(f.resolves, ref)
	if f.resolveErr != nil {
		return secret.Secret{}, f.resolveErr
	}
	v, ok := f.m[ref.String()]
	if !ok {
		return secret.Secret{}, keyring.ErrNotFound
	}
	return secret.FromString(v), nil
}

func (f *fakeKeys) Set(_ context.Context, ref secret.Ref, value secret.Secret) error {
	if f.yield {
		for range 5 {
			runtime.Gosched()
		}
	}
	f.mu.Lock()
	f.sets = append(f.sets, ref)
	if f.setErr != nil {
		f.mu.Unlock()
		return f.setErr
	}
	f.m[ref.String()] = value.Expose()
	f.mu.Unlock()
	if f.yield {
		for range 5 {
			runtime.Gosched()
		}
	}
	return nil
}

func (f *fakeKeys) Delete(_ context.Context, ref secret.Ref) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, ref)
	delete(f.m, ref.String())
	return nil
}

func (f *fakeKeys) get(ref secret.Ref) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[ref.String()]
	return v, ok
}

func (f *fakeKeys) put(ref secret.Ref, v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[ref.String()] = v
}

func (f *fakeKeys) remove(ref secret.Ref) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, ref.String())
}

func (f *fakeKeys) setErrors(resolveErr, setErr error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolveErr, f.setErr = resolveErr, setErr
}

// calls returns copies of the recorded calls.
func (f *fakeKeys) calls() (resolves, sets, deletes []secret.Ref) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.resolves), slices.Clone(f.sets), slices.Clone(f.deletes)
}

func (f *fakeKeys) resetCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolves, f.sets, f.deletes = nil, nil, nil
}

func (f *fakeKeys) wantNoCalls(t *testing.T) {
	t.Helper()
	r, s, d := f.calls()
	if len(r)+len(s)+len(d) != 0 {
		t.Fatalf("keyring touched: %d Resolve, %d Set, %d Delete; want none", len(r), len(s), len(d))
	}
}

// sessionRef is the ADR 0009 keyring entry of a connector.
func sessionRef(install, id string) secret.Ref {
	return secret.Ref{Scheme: secret.SchemeKeyring, Item: vault.KeyringService, Field: install + "/" + id}
}

// gatedBackend is a keyring.Backend (below the real Provider) whose Set can
// be held until the test releases it, to drive the provider timeout.
type gatedBackend struct {
	mu      sync.Mutex
	m       map[string]string
	gate    chan struct{} // when non-nil, the next Set waits on it
	entered chan struct{} // closed when a gated Set starts waiting
	setDone chan struct{} // closed when a gated Set has written
}

func newGatedBackend() *gatedBackend { return &gatedBackend{m: map[string]string{}} }

func (b *gatedBackend) arm() (release func(), entered, done <-chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gate = make(chan struct{})
	b.entered = make(chan struct{})
	b.setDone = make(chan struct{})
	g := b.gate
	return func() { close(g) }, b.entered, b.setDone
}

func (b *gatedBackend) Get(service, user string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.m[service+"/"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (b *gatedBackend) Set(service, user, value string) error {
	b.mu.Lock()
	gate, entered, done := b.gate, b.entered, b.setDone
	b.gate = nil
	b.mu.Unlock()
	if gate != nil {
		close(entered)
		<-gate
	}
	b.mu.Lock()
	b.m[service+"/"+user] = value
	b.mu.Unlock()
	if gate != nil {
		close(done)
	}
	return nil
}

func (b *gatedBackend) Delete(service, user string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.m, service+"/"+user)
	return nil
}

// ---------------------------------------------------------------- opener

// openSpy counts session file opens. openErr fails the open; readErr makes
// the returned reader fail.
type openSpy struct {
	mu      sync.Mutex
	opens   []string
	closed  int
	openErr error
	readErr error
}

func (o *openSpy) open(sessions *fsx.Root, name string) (io.ReadCloser, error) {
	o.mu.Lock()
	o.opens = append(o.opens, name)
	openErr, readErr := o.openErr, o.readErr
	o.mu.Unlock()
	if openErr != nil {
		return nil, openErr
	}
	f, err := sessions.OpenRegular(name)
	if err != nil {
		return nil, err
	}
	if readErr != nil {
		_ = f.Close()
		return &failingFile{spy: o, err: readErr}, nil
	}
	return &spiedFile{File: f, spy: o}, nil
}

func (o *openSpy) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.opens)
}

func (o *openSpy) closes() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closed
}

type spiedFile struct {
	*os.File
	spy *openSpy
}

func (s *spiedFile) Close() error {
	s.spy.mu.Lock()
	s.spy.closed++
	s.spy.mu.Unlock()
	return s.File.Close()
}

type failingFile struct {
	spy *openSpy
	err error
}

func (f *failingFile) Read([]byte) (int, error) { return 0, f.err }

func (f *failingFile) Close() error {
	f.spy.mu.Lock()
	f.spy.closed++
	f.spy.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------- logs

// logCapture records every slog record as JSON lines (raw, not redacted: the
// store must not log secrets in the first place).
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(c, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func (c *logCapture) text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// records decodes the lines at or above floor.
func (c *logCapture) records(t *testing.T, floor slog.Level) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(c.text()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		var lvl slog.Level
		if err := lvl.UnmarshalText([]byte(m["level"].(string))); err != nil {
			t.Fatalf("decode level: %v", err)
		}
		if lvl >= floor {
			out = append(out, m)
		}
	}
	return out
}

// ---------------------------------------------------------------- store

type storeFixture struct {
	dir   string // state dir
	keys  *fakeKeys
	spy   *openSpy
	logs  *logCapture
	store *vault.Store
}

// newStateDir returns a fresh private state directory.
func newStateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	parent, err := fsx.Open(filepath.Dir(dir))
	if err != nil {
		t.Fatalf("open temp dir: %v", err)
	}
	defer func() { _ = parent.Close() }()
	if err := parent.MkdirPrivate("state"); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	return dir
}

// openStore builds a Store over dir with the given mode and keyring.
func openStore(t *testing.T, dir string, mode vault.Mode, keys vault.KeyBackend, keysErr error) (*vault.Store, *openSpy, *logCapture) {
	t.Helper()
	spy := &openSpy{}
	logs := &logCapture{}
	s, err := vault.NewStore(t.Context(), vault.Options{
		StateDir:   dir,
		Mode:       mode,
		Keyring:    keys,
		KeyringErr: keysErr,
		Rand:       rand.Reader,
		Log:        logs.logger(),
		Open:       spy.open,
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s, spy, logs
}

func newPersistent(t *testing.T) *storeFixture {
	t.Helper()
	dir := newStateDir(t)
	keys := newFakeKeys()
	s, spy, logs := openStore(t, dir, vault.Persistent, keys, nil)
	return &storeFixture{dir: dir, keys: keys, spy: spy, logs: logs, store: s}
}

func (f *storeFixture) sessPath(id string) string {
	return filepath.Join(f.dir, "sessions", id+".sess")
}

func (f *storeFixture) installID(t *testing.T) string {
	t.Helper()
	return readInstallID(t, f.dir)
}

func readInstallID(t *testing.T, dir string) string {
	t.Helper()
	return string(readBytes(t, filepath.Join(dir, "install-id")))
}

func mustSave(t *testing.T, s *vault.Store, id, blob string) {
	t.Helper()
	if err := s.Save(t.Context(), id, secret.FromString(blob)); err != nil {
		t.Fatalf("Save(%q): %v", id, err)
	}
}

func mustLoad(t *testing.T, s *vault.Store, id, want string) {
	t.Helper()
	got, err := s.Load(t.Context(), id)
	if err != nil {
		t.Fatalf("Load(%q): %v", id, err)
	}
	if got.Expose() != want {
		t.Fatalf("Load(%q) returned a different blob (%d bytes, want %d)", id, len(got.Expose()), len(want))
	}
}

func wantNoSession(t *testing.T, s *vault.Store, id string) {
	t.Helper()
	got, err := s.Load(t.Context(), id)
	if !errors.Is(err, vault.ErrNoSession) {
		t.Fatalf("Load(%q): err = %v, want ErrNoSession", id, err)
	}
	if !got.IsZero() {
		t.Fatalf("Load(%q) returned a blob alongside ErrNoSession", id)
	}
}

func readBytes(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(p))
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return b
}

func exists(t *testing.T, p string) bool {
	t.Helper()
	_, err := os.Lstat(p)
	if err == nil {
		return true
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("lstat %s: %v", p, err)
	}
	return false
}

// put writes data at rel (slash-separated) under dir through fsx, creating
// missing parent directories 0700.
func put(t *testing.T, dir, rel string, data []byte) {
	t.Helper()
	r, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("open %s: %v", dir, err)
	}
	defer func() { _ = r.Close() }()
	if parent := path.Dir(rel); parent != "." {
		if err := r.MkdirPrivate(parent); err != nil {
			t.Fatalf("mkdir %s: %v", parent, err)
		}
	}
	if err := r.WriteAtomic(t.Context(), rel, data); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// snapshot maps every path under dir to its type, mode and content, so a
// test can prove nothing was written, removed or changed. Reads go through
// an os.Root confined to dir and never follow symlinks.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root %s: %v", dir, err)
	}
	defer func() { _ = root.Close() }()
	out := map[string]string{}
	err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		rel := filepath.FromSlash(p)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := root.Readlink(rel)
			if err != nil {
				return err
			}
			out[p] = "symlink:" + target
		case d.IsDir():
			out[p] = "dir:" + fi.Mode().Perm().String()
		default:
			b, err := root.ReadFile(rel)
			if err != nil {
				return err
			}
			out[p] = "file:" + fi.Mode().Perm().String() + ":" + string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", dir, err)
	}
	return out
}

func wantSameTree(t *testing.T, before, after map[string]string) {
	t.Helper()
	for p, v := range before {
		if a, ok := after[p]; !ok {
			t.Errorf("%s was removed", p)
		} else if a != v {
			t.Errorf("%s changed", p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("%s was created", p)
		}
	}
}

// keyOf parses the keyring value of ref.
func keyOf(t *testing.T, keys *fakeKeys, ref secret.Ref) vault.Key {
	t.Helper()
	v, ok := keys.get(ref)
	if !ok {
		t.Fatalf("no keyring entry %s", ref)
	}
	k, err := vault.ParseKey(secret.FromString(v))
	if err != nil {
		t.Fatalf("keyring entry %s is not a valid key: %v", ref, err)
	}
	return k
}

// manualAfter is a keyring.WithAfter timer that only fires when the test
// sends on its channel.
type manualAfter struct{ ch chan time.Time }

func (m *manualAfter) after(time.Duration) <-chan time.Time { return m.ch }
