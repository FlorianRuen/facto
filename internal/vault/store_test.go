// Tests for the session store (J1 T16, ADR 0009 "Key source", "Rotation",
// "Ephemeral mode", "File location"). Black-box, package vault_test. Fakes:
// fakeKeys (vault.KeyBackend), gatedBackend under the real keyring.Provider
// for the timeout case, openSpy for session file opens, a temp state dir,
// a JSON slog capture. No sleeps: the keyring timeout is driven through
// keyring.WithAfter.
//
// Expected API (package vault):
//
//	const (
//		KeyringService = "facto-session" // keyring service of every session key
//		InstallIDFile  = "install-id"    // <state_dir>/install-id
//		SessionsDir    = "sessions"      // <state_dir>/sessions/<id>.sess, <id>.lock
//	)
//
//	// Mode selects how sessions are kept.
//	type Mode int
//	const (
//		// Persistent keeps sessions/<id>.sess sealed under a per-connector
//		// keyring key rotated on every Save.
//		Persistent Mode = iota
//		// Ephemeral keeps nothing. NewStore removes every sessions/*.sess
//		// without opening it and Deletes the keyring entry of each one whose
//		// stem is a valid connector id (when install-id is readable), without
//		// reading it; one log line (Info, attribute "removed" = count).
//		Ephemeral
//	)
//
//	var (
//		// ErrNoSession: no usable saved session (missing file, missing or
//		// malformed key, or a file that failed vault.Open with ErrInvalid,
//		// which is then removed). The connector logs in again.
//		ErrNoSession = errors.New("vault: no saved session")
//		// ErrKeyring: a keyring backend error or timeout on Resolve or Set.
//		// Wraps the backend error (errors.Is reaches keyring.ErrTimeout). The
//		// session file is kept.
//		ErrKeyring = errors.New("vault: keyring error")
//	)
//
//	// KeyBackend is the store's view of the keyring (*keyring.Provider
//	// satisfies it). A missing entry resolves to an error wrapping
//	// secret.ErrSecretNotFound. Refs are
//	// keyring://facto-session/<install-id>/<connector-id>.
//	type KeyBackend interface {
//		Resolve(ctx context.Context, ref secret.Ref) (secret.Secret, error)
//		Set(ctx context.Context, ref secret.Ref, value secret.Secret) error
//		Delete(ctx context.Context, ref secret.Ref) error
//	}
//
//	// OpenFunc opens name (e.g. "edf.sess") inside the sessions directory
//	// for reading. Default: (*fsx.Root).OpenRegular. Tests inject a spy.
//	type OpenFunc func(sessions *fsx.Root, name string) (io.ReadCloser, error)
//
//	type Options struct {
//		StateDir   string     // existing private directory
//		Mode       Mode
//		Keyring    KeyBackend // nil: no keyring backend
//		KeyringErr error      // non-nil: backend unavailable or unsupported (the cause)
//		Rand       io.Reader  // keys, nonces, install id; nil is ErrInvalidArgument
//		Log        *slog.Logger
//		Open       OpenFunc   // nil: fsx OpenRegular
//	}
//
//	// NewStore prepares the store. Persistent mode with a keyring reads
//	// <state_dir>/install-id or creates it once (16 bytes from Rand as 32
//	// lowercase hex chars, 0600, fsx.WriteNew, never rewritten). A malformed
//	// install-id disables persistence for the run with one Warn line and is
//	// left untouched. Persistent mode with Keyring == nil or KeyringErr != nil
//	// falls back to ephemeral with one Warn line naming the cause, and
//	// neither writes nor deletes anything (files or keyring). Ephemeral mode
//	// runs the sweep described above.
//	func NewStore(ctx context.Context, opts Options) (*Store, error)
//
//	// Persistent reports whether Save and Load use the disk and keyring.
//	func (s *Store) Persistent() bool
//
//	// Save and Load validate id first, in every mode: anything
//	// ValidConnectorID refuses is ErrInvalidArgument before any file or
//	// keyring access.
//	//
//	// Save (persistent): validates id (ValidConnectorID, then fsx.SafeName;
//	// ErrInvalidArgument), creates sessions/ 0700, takes the fsx lock
//	// sessions/<id>.lock, generates a new key, seals blob, Sets the key
//	// (failure or timeout: abort, old pair untouched, error wraps ErrKeyring),
//	// then fsx.WriteAtomic sessions/<id>.sess (failure: old file removed).
//	// Not persistent: returns nil and writes nothing.
//	func (s *Store) Save(ctx context.Context, id string, blob secret.Secret) error
//
//	// Load (persistent): validates id (ErrInvalidArgument), then: no file →
//	// ErrNoSession; key missing or malformed → ErrNoSession without opening
//	// the file (file kept); keyring error → ErrKeyring (file kept); read
//	// error → wrapped, neither ErrNoSession nor vault.ErrInvalid (file kept);
//	// vault.ErrInvalid → file removed, one log line, ErrNoSession. Not
//	// persistent: ErrNoSession without touching anything.
//	func (s *Store) Load(ctx context.Context, id string) (secret.Secret, error)
package vault_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/secret/keyring"
	"github.com/FlorianRuen/facto/internal/testsecrets"
	"github.com/FlorianRuen/facto/internal/vault"
)

var installIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

func TestStore_RoundTrip(t *testing.T) {
	t.Parallel()
	f := newPersistent(t)
	if !f.store.Persistent() {
		t.Fatalf("Persistent() = false with a working keyring")
	}
	wantNoSession(t, f.store, "edf")

	mustSave(t, f.store, "edf", "synthetic edf jar v1")
	mustSave(t, f.store, "ileo", "synthetic ileo jar v1")
	mustLoad(t, f.store, "edf", "synthetic edf jar v1")
	mustLoad(t, f.store, "ileo", "synthetic ileo jar v1")

	// A later run (new Store, same state dir and keyring) restores it.
	again, _, _ := openStore(t, f.dir, vault.Persistent, f.keys, nil)
	mustLoad(t, again, "edf", "synthetic edf jar v1")

	if err := f.store.Save(t.Context(), "edf", secret.Secret{}); !errors.Is(err, vault.ErrPlaintextSize) {
		t.Fatalf("Save(empty blob): err = %v, want ErrPlaintextSize", err)
	}
	mustLoad(t, f.store, "edf", "synthetic edf jar v1")
}

func TestStore_RotatesKeyOnSave(t *testing.T) {
	t.Parallel()
	f := newPersistent(t)
	install := f.installID(t)
	ref := sessionRef(install, "edf")

	var keys []string
	var files [][]byte
	for i := range 3 {
		f.keys.resetCalls()
		mustSave(t, f.store, "edf", fmt.Sprintf("synthetic jar %d", i))
		_, sets, _ := f.keys.calls()
		if len(sets) != 1 || sets[0] != ref {
			t.Fatalf("save %d: keyring Sets = %v, want exactly one on %s", i, sets, ref)
		}
		v, ok := f.keys.get(ref)
		if !ok || len(v) != vault.EncodedKeyLen {
			t.Fatalf("save %d: keyring value of length %d, want %d", i, len(v), vault.EncodedKeyLen)
		}
		keys = append(keys, v)
		files = append(files, readBytes(t, f.sessPath("edf")))
	}
	for i := range keys {
		for j := range i {
			if keys[i] == keys[j] {
				t.Fatalf("save %d reused the key of save %d", i, j)
			}
			if bytes.Equal(files[i][9:33], files[j][9:33]) {
				t.Fatalf("save %d reused the nonce of save %d", i, j)
			}
		}
	}
	// Older files do not open under the current key.
	cur := keyOf(t, f.keys, ref)
	for i, old := range files[:2] {
		got, err := openBytes(t, install, "edf", cur, old)
		if !errors.Is(err, vault.ErrInvalid) || !got.IsZero() {
			t.Fatalf("file of save %d opened under the rotated key (err = %v)", i, err)
		}
	}
	mustLoad(t, f.store, "edf", "synthetic jar 2")
}

func TestStore_RollbackToPreviousFileFails(t *testing.T) {
	t.Parallel()
	f := newPersistent(t)
	mustSave(t, f.store, "edf", "synthetic jar old")
	old := readBytes(t, f.sessPath("edf"))
	mustSave(t, f.store, "edf", "synthetic jar new")

	// Restore the older file (backup, synced copy, snapshot).
	put(t, f.dir, "sessions/edf.sess", old)
	wantNoSession(t, f.store, "edf")
	if exists(t, f.sessPath("edf")) {
		t.Fatalf("rolled-back file was kept after failing authentication")
	}
}

func TestStore_CorruptOrUndecryptableIsNoSession(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Session)
	tests := []struct {
		name   string
		mangle func(t *testing.T, f *storeFixture, file []byte) []byte
	}{
		{"canary garbage", func(*testing.T, *storeFixture, []byte) []byte {
			return []byte(strings.Repeat(canary, 4))
		}},
		{"empty", func(*testing.T, *storeFixture, []byte) []byte { return []byte{} }},
		{"header only", func(_ *testing.T, _ *storeFixture, b []byte) []byte { return b[:vault.HeaderSize] }},
		{"truncated tag", func(_ *testing.T, _ *storeFixture, b []byte) []byte { return b[:len(b)-1] }},
		{"flipped ciphertext byte", func(_ *testing.T, _ *storeFixture, b []byte) []byte {
			c := bytes.Clone(b)
			c[len(c)-1] ^= 0x01
			return c
		}},
		{"unknown version", func(_ *testing.T, _ *storeFixture, b []byte) []byte {
			c := bytes.Clone(b)
			c[8] = 0x02
			return c
		}},
		{"sealed under another key", func(t *testing.T, f *storeFixture, _ []byte) []byte {
			other := mustKey(t, randBytes(t, 32))
			file, err := vault.Seal(t.Context(), f.installID(t), "edf", other, []byte("synthetic other jar"))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			return file
		}},
		{"copied from another connector", func(t *testing.T, f *storeFixture, _ []byte) []byte {
			mustSave(t, f.store, "ileo", "synthetic ileo jar")
			return readBytes(t, f.sessPath("ileo"))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newPersistent(t)
			mustSave(t, f.store, "edf", "synthetic edf jar")
			put(t, f.dir, "sessions/edf.sess", tc.mangle(t, f, readBytes(t, f.sessPath("edf"))))

			wantNoSession(t, f.store, "edf")
			if exists(t, f.sessPath("edf")) {
				t.Fatalf("invalid session file was kept")
			}
			if n := f.spy.count(); n != 1 {
				t.Fatalf("session file opened %d times, want 1", n)
			}
			if f.spy.closes() != 1 {
				t.Fatalf("session file not closed")
			}
			recs := f.logs.records(t, slog.LevelInfo)
			if len(recs) == 0 {
				t.Fatalf("removal of an invalid session file was not logged")
			}
			if out := f.logs.text(); strings.Contains(out, canary[len(testsecrets.Prefix):]) {
				t.Fatalf("log carries session file content:\n%s", out)
			}
			// Other connectors are untouched.
			if tc.name == "copied from another connector" {
				mustLoad(t, f.store, "ileo", "synthetic ileo jar")
			}
		})
	}
}

func TestStore_KeyringBackendErrorKeepsFile(t *testing.T) {
	t.Parallel()
	backendErr := errors.New("synthetic keyring backend failure")
	tests := []struct {
		name string
		err  error
	}{
		{"backend error", backendErr},
		{"timeout", keyring.ErrTimeout},
	}
	for _, tc := range tests {
		t.Run("Load/"+tc.name, func(t *testing.T) {
			t.Parallel()
			f := newPersistent(t)
			mustSave(t, f.store, "edf", "synthetic jar")
			before := snapshot(t, f.dir)
			f.keys.setErrors(tc.err, nil)
			f.keys.resetCalls()

			got, err := f.store.Load(t.Context(), "edf")
			if !errors.Is(err, vault.ErrKeyring) || !errors.Is(err, tc.err) {
				t.Fatalf("Load: err = %v, want ErrKeyring wrapping the backend error", err)
			}
			if errors.Is(err, vault.ErrNoSession) || errors.Is(err, vault.ErrInvalid) {
				t.Fatalf("Load: keyring error reported as %v", err)
			}
			if !got.IsZero() {
				t.Fatalf("Load returned a blob alongside an error")
			}
			wantSameTree(t, before, snapshot(t, f.dir))
			if _, _, d := f.keys.calls(); len(d) != 0 {
				t.Fatalf("keyring Delete called %d times after a backend error", len(d))
			}
			// The pair is intact once the keyring answers again.
			f.keys.setErrors(nil, nil)
			mustLoad(t, f.store, "edf", "synthetic jar")
		})

		t.Run("Save/"+tc.name, func(t *testing.T) {
			t.Parallel()
			f := newPersistent(t)
			mustSave(t, f.store, "edf", "synthetic jar old")
			ref := sessionRef(f.installID(t), "edf")
			oldKey, _ := f.keys.get(ref)
			before := snapshot(t, f.dir)
			f.keys.setErrors(nil, tc.err)

			err := f.store.Save(t.Context(), "edf", secret.FromString("synthetic jar new"))
			if !errors.Is(err, vault.ErrKeyring) || !errors.Is(err, tc.err) {
				t.Fatalf("Save: err = %v, want ErrKeyring wrapping the backend error", err)
			}
			after := snapshot(t, f.dir)
			if after["sessions/edf.sess"] != before["sessions/edf.sess"] {
				t.Fatalf("session file changed although the key Set failed")
			}
			if k, _ := f.keys.get(ref); k != oldKey {
				t.Fatalf("keyring entry changed although Set failed")
			}
			f.keys.setErrors(nil, nil)
			mustLoad(t, f.store, "edf", "synthetic jar old")
		})
	}
}

func TestStore_ReadErrorKeepsFile(t *testing.T) {
	t.Parallel()
	readErr := errors.New("synthetic read failure")
	tests := []struct {
		name      string
		configure func(*openSpy)
	}{
		{"read fails", func(o *openSpy) { o.readErr = readErr }},
		{"open fails", func(o *openSpy) { o.openErr = fmt.Errorf("synthetic open: %w", readErr) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newPersistent(t)
			mustSave(t, f.store, "edf", "synthetic jar")
			before := snapshot(t, f.dir)
			tc.configure(f.spy)

			got, err := f.store.Load(t.Context(), "edf")
			if !errors.Is(err, readErr) {
				t.Fatalf("Load: err = %v, want the read error wrapped", err)
			}
			if errors.Is(err, vault.ErrInvalid) || errors.Is(err, vault.ErrNoSession) || errors.Is(err, vault.ErrKeyring) {
				t.Fatalf("Load: read error reported as %v", err)
			}
			if !got.IsZero() {
				t.Fatalf("Load returned a blob alongside an error")
			}
			wantSameTree(t, before, snapshot(t, f.dir))
			if f.spy.count() != f.spy.closes() && tc.name == "read fails" {
				t.Fatalf("session file not closed after a read error")
			}
		})
	}
}

func TestStore_MalformedKeyIsNoSession(t *testing.T) {
	t.Parallel()
	b31 := base64.RawURLEncoding.EncodeToString(make([]byte, 31))
	b33 := base64.RawURLEncoding.EncodeToString(make([]byte, 33))
	tests := []struct {
		name  string
		value *string // nil: entry removed
	}{
		{"missing entry", nil},
		{"short", ptr("c3ludGhldGlj")},
		{"31 bytes", &b31},
		{"33 bytes", &b33},
		{"padded", ptr(base64.URLEncoding.EncodeToString(make([]byte, 32)))},
		{"std alphabet", ptr(strings.Repeat("+", 43))},
		{"not base64", ptr(strings.Repeat("!", 43))},
		{"trailing newline", ptr(base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + "\n")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newPersistent(t)
			mustSave(t, f.store, "edf", "synthetic jar")
			ref := sessionRef(f.installID(t), "edf")
			if tc.value == nil {
				f.keys.remove(ref)
			} else {
				f.keys.put(ref, *tc.value)
			}
			before := snapshot(t, f.dir)
			f.keys.resetCalls()

			wantNoSession(t, f.store, "edf")
			if n := f.spy.count(); n != 0 {
				t.Fatalf("session file opened %d times with an unusable key, want 0", n)
			}
			wantSameTree(t, before, snapshot(t, f.dir))
			if _, s, d := f.keys.calls(); len(s)+len(d) != 0 {
				t.Fatalf("Load wrote to the keyring (%d Set, %d Delete)", len(s), len(d))
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestStore_SetTimeoutThenLateWriteMeansRelogin(t *testing.T) {
	t.Parallel()
	dir := newStateDir(t)
	backend := newGatedBackend()
	timer := &manualAfter{ch: make(chan time.Time)}
	provider := keyring.New(backend, keyring.WithAfter(timer.after))
	s, _, _ := openStore(t, dir, vault.Persistent, provider, nil)
	sess := filepath.Join(dir, "sessions", "edf.sess")

	mustSave(t, s, "edf", "synthetic jar v1")
	v1 := readBytes(t, sess)

	release, entered, done := backend.arm()
	errc := make(chan error, 1)
	go func() { errc <- s.Save(t.Context(), "edf", secret.FromString("synthetic jar v2")) }()
	<-entered
	timer.ch <- time.Time{}
	err := <-errc
	if !errors.Is(err, keyring.ErrTimeout) || !errors.Is(err, vault.ErrKeyring) {
		t.Fatalf("Save with a hung keyring: err = %v, want ErrKeyring wrapping keyring.ErrTimeout", err)
	}
	if !bytes.Equal(readBytes(t, sess), v1) {
		t.Fatalf("session file replaced although the key Set timed out")
	}

	// The abandoned Set lands later: the old file no longer matches its key.
	release()
	<-done
	wantNoSession(t, s, "edf")
	if exists(t, sess) {
		t.Fatalf("file left behind after it failed authentication")
	}

	// Logging in again recovers.
	mustSave(t, s, "edf", "synthetic jar v3")
	mustLoad(t, s, "edf", "synthetic jar v3")
}

func TestStore_ConcurrentSavesLeaveOpenablePair(t *testing.T) {
	t.Parallel()
	dir := newStateDir(t)
	keys := newFakeKeys()
	keys.yield = true
	// Two stores on the same state dir stand for a scheduled collect and a
	// manual login running at once.
	a, _, _ := openStore(t, dir, vault.Persistent, keys, nil)
	b, _, _ := openStore(t, dir, vault.Persistent, keys, nil)

	for round := range 5 {
		const writers = 8
		blobs := make([]string, writers)
		var wg sync.WaitGroup
		errc := make(chan error, writers)
		for i := range writers {
			blobs[i] = fmt.Sprintf("synthetic jar round %d writer %d", round, i)
			s := a
			if i%2 == 1 {
				s = b
			}
			wg.Go(func() {
				if err := s.Save(t.Context(), "edf", secret.FromString(blobs[i])); err != nil {
					errc <- err
				}
			})
		}
		wg.Wait()
		close(errc)
		for err := range errc {
			t.Fatalf("round %d: concurrent Save: %v", round, err)
		}
		got, err := a.Load(t.Context(), "edf")
		if err != nil {
			t.Fatalf("round %d: Load after concurrent saves: %v (file and key from different saves)", round, err)
		}
		if !slices.Contains(blobs, got.Expose()) {
			t.Fatalf("round %d: Load returned a blob no writer saved", round)
		}
	}
	// No temp file left behind.
	des, err := os.ReadDir(filepath.Join(dir, "sessions"))
	if err != nil {
		t.Fatalf("read sessions: %v", err)
	}
	for _, de := range des {
		if n := de.Name(); n != "edf.sess" && n != "edf.lock" {
			t.Fatalf("unexpected entry %q in sessions/", n)
		}
	}
}

func TestStore_IDTraversalRefused(t *testing.T) {
	t.Parallel()
	ids := []string{
		"", ".", "..", "../edf", "../../etc/edf", "a/b", `..\edf`, `a\b`, "/edf",
		"edf.sess", "edf.lock", "EDF", "edf\x00", "edf\n", " edf",
		strings.Repeat("a", 41), "-edf", "edf-",
	}
	for _, mode := range []vault.Mode{vault.Persistent, vault.Ephemeral} {
		t.Run(fmt.Sprintf("mode %d", mode), func(t *testing.T) {
			t.Parallel()
			dir := newStateDir(t)
			keys := newFakeKeys()
			s, spy, _ := openStore(t, dir, mode, keys, nil)
			parent := filepath.Dir(dir)
			before := snapshot(t, parent)
			keys.resetCalls()
			for _, id := range ids {
				if err := s.Save(t.Context(), id, secret.FromString("synthetic jar")); !errors.Is(err, vault.ErrInvalidArgument) {
					t.Errorf("Save(%q): err = %v, want ErrInvalidArgument", id, err)
				}
				got, err := s.Load(t.Context(), id)
				if !errors.Is(err, vault.ErrInvalidArgument) || !got.IsZero() {
					t.Errorf("Load(%q): err = %v, want ErrInvalidArgument", id, err)
				}
			}
			wantSameTree(t, before, snapshot(t, parent))
			keys.wantNoCalls(t)
			if n := spy.count(); n != 0 {
				t.Fatalf("%d opens for invalid ids", n)
			}
		})
	}
}

func TestStore_CanaryCookieNeverInClearOnDisk(t *testing.T) {
	t.Parallel()
	art := testsecrets.ArtifactDir(t)
	cookie := testsecrets.Canary(t, testsecrets.Cookie)
	token := testsecrets.Canary(t, testsecrets.Token)
	blob := `{"cookies":[{"name":"sid","value":"` + cookie + `"}],"token":"` + token + `"}`

	f := newPersistent(t)
	mustSave(t, f.store, "edf", blob)
	mustLoad(t, f.store, "edf", blob)
	key, _ := f.keys.get(sessionRef(f.installID(t), "edf"))

	needles := map[string]string{
		"cookie":        cookie[len(testsecrets.Prefix):],
		"token":         token[len(testsecrets.Prefix):],
		"cookie base64": base64.StdEncoding.EncodeToString([]byte(cookie))[4:24],
		"key (encoded)": key,
		"canary prefix": testsecrets.Prefix,
	}
	tree := snapshot(t, f.dir)
	for p, content := range tree {
		writeArtifact(t, art, strings.NewReplacer("/", "_", `\`, "_").Replace(p)+".txt", []byte(content))
		for what, n := range needles {
			if strings.Contains(content, n) {
				t.Fatalf("%s found in clear in %s", what, p)
			}
		}
	}
	logs := f.logs.text()
	writeArtifact(t, art, "store.log", []byte(logs))
	for what, n := range needles {
		if strings.Contains(logs, n) {
			t.Fatalf("%s found in the store log", what)
		}
	}
}

func TestStore_OtherStateDirFileRejected(t *testing.T) {
	t.Parallel()
	keys := newFakeKeys() // one OS account, two state dirs
	dirA, dirB := newStateDir(t), newStateDir(t)
	a, _, _ := openStore(t, dirA, vault.Persistent, keys, nil)
	b, _, _ := openStore(t, dirB, vault.Persistent, keys, nil)
	mustSave(t, a, "edf", "synthetic jar A")
	mustSave(t, b, "edf", "synthetic jar B")

	idA, idB := readInstallID(t, dirA), readInstallID(t, dirB)
	if idA == idB {
		t.Fatalf("two state dirs share the install id %s", idA)
	}
	refA, refB := sessionRef(idA, "edf"), sessionRef(idB, "edf")
	if _, ok := keys.get(refA); !ok {
		t.Fatalf("no key under %s", refA)
	}
	if _, ok := keys.get(refB); !ok {
		t.Fatalf("no key under %s", refB)
	}

	t.Run("file copied", func(t *testing.T) {
		put(t, dirB, "sessions/edf.sess", readBytes(t, filepath.Join(dirA, "sessions", "edf.sess")))
		wantNoSession(t, b, "edf")
		if exists(t, filepath.Join(dirB, "sessions", "edf.sess")) {
			t.Fatalf("foreign file kept")
		}
		mustLoad(t, a, "edf", "synthetic jar A")
	})

	t.Run("file and key copied", func(t *testing.T) {
		mustSave(t, b, "edf", "synthetic jar B2")
		v, _ := keys.get(refA)
		keys.put(refB, v)
		put(t, dirB, "sessions/edf.sess", readBytes(t, filepath.Join(dirA, "sessions", "edf.sess")))
		wantNoSession(t, b, "edf")
		if exists(t, filepath.Join(dirB, "sessions", "edf.sess")) {
			t.Fatalf("foreign file kept")
		}
	})
}

func TestInstallID_CreatedOnceAndStable(t *testing.T) {
	t.Parallel()

	t.Run("created once, then reused", func(t *testing.T) {
		t.Parallel()
		f := newPersistent(t)
		id := f.installID(t)
		if !installIDRe.MatchString(id) {
			t.Fatalf("install-id = %q, want 32 lowercase hex chars", id)
		}
		for range 3 {
			openStore(t, f.dir, vault.Persistent, f.keys, nil)
			if got := f.installID(t); got != id {
				t.Fatalf("install-id changed from %s to %s", id, got)
			}
		}
		mustSave(t, f.store, "edf", "synthetic jar")
		_, sets, _ := f.keys.calls()
		if len(sets) != 1 || sets[0] != sessionRef(id, "edf") {
			t.Fatalf("Set refs = %v, want %s", sets, sessionRef(id, "edf"))
		}
	})

	t.Run("concurrent first runs agree", func(t *testing.T) {
		t.Parallel()
		dir := newStateDir(t)
		keys := newFakeKeys()
		const n = 8
		stores := make([]*vault.Store, n)
		var wg sync.WaitGroup
		errc := make(chan error, n)
		for i := range n {
			wg.Go(func() {
				s, err := vault.NewStore(t.Context(), vault.Options{
					StateDir: dir, Mode: vault.Persistent, Keyring: keys,
					Rand: rand.Reader, Log: (&logCapture{}).logger(),
				})
				if err != nil {
					errc <- err
					return
				}
				stores[i] = s
			})
		}
		wg.Wait()
		close(errc)
		for err := range errc {
			t.Fatalf("concurrent NewStore: %v", err)
		}
		mustSave(t, stores[0], "edf", "synthetic jar")
		for i, s := range stores[1:] {
			if !s.Persistent() {
				t.Fatalf("store %d not persistent", i+1)
			}
			mustLoad(t, s, "edf", "synthetic jar")
		}
	})

	t.Run("distinct per state dir", func(t *testing.T) {
		t.Parallel()
		seen := map[string]bool{}
		for range 5 {
			f := newPersistent(t)
			id := f.installID(t)
			if seen[id] {
				t.Fatalf("install id %s generated twice", id)
			}
			seen[id] = true
		}
	})
}

func TestInstallID_MalformedDisablesPersistenceWithWarning(t *testing.T) {
	t.Parallel()
	valid := "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"not hex", "synthetic-not-an-install-id"},
		{"uppercase", strings.ToUpper(valid)},
		{"31 chars", valid[:31]},
		{"33 chars", valid + "0"},
		{"trailing newline", valid + "\n"},
		{"non-hex letter", "g" + valid[1:]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := newStateDir(t)
			put(t, dir, "install-id", []byte(tc.content))
			put(t, dir, "sessions/edf.sess", []byte("synthetic opaque bytes"))
			before := snapshot(t, dir)
			keys := newFakeKeys()

			s, spy, logs := openStore(t, dir, vault.Persistent, keys, nil)
			if s.Persistent() {
				t.Fatalf("Persistent() = true with a malformed install-id")
			}
			mustSave(t, s, "edf", "synthetic jar")
			wantNoSession(t, s, "edf")
			mustSave(t, s, "ileo", "synthetic jar")

			wantSameTree(t, before, snapshot(t, dir))
			keys.wantNoCalls(t)
			if n := spy.count(); n != 0 {
				t.Fatalf("%d session opens with persistence disabled", n)
			}
			warns := logs.records(t, slog.LevelWarn)
			if len(warns) != 1 {
				t.Fatalf("%d warnings, want exactly one:\n%s", len(warns), logs.text())
			}
		})
	}
}

func TestStore_NoKeyringFallsBackToEphemeralWithWarning(t *testing.T) {
	t.Parallel()
	cause := errors.New("synthetic: secret service unavailable")
	tests := []struct {
		name    string
		keys    bool
		keysErr error
		inWarn  string
	}{
		{"backend unavailable", true, cause, "synthetic: secret service unavailable"},
		{"no backend", false, nil, ""},
		{"no backend with cause", false, cause, "synthetic: secret service unavailable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := newStateDir(t)
			keys := newFakeKeys()
			var kb vault.KeyBackend
			if tc.keys {
				kb = keys
			}
			s, spy, logs := openStore(t, dir, vault.Persistent, kb, tc.keysErr)
			if s.Persistent() {
				t.Fatalf("Persistent() = true without a keyring")
			}
			for range 3 {
				mustSave(t, s, "edf", "synthetic jar")
				wantNoSession(t, s, "edf")
			}
			if got := snapshot(t, dir); len(got) != 1 {
				t.Fatalf("fallback wrote to the state dir: %v", slices.Collect(maps.Keys(got)))
			}
			keys.wantNoCalls(t)
			if n := spy.count(); n != 0 {
				t.Fatalf("%d session opens in fallback", n)
			}
			warns := logs.records(t, slog.LevelWarn)
			if len(warns) != 1 {
				t.Fatalf("%d warnings, want exactly one:\n%s", len(warns), logs.text())
			}
			if tc.inWarn != "" && !strings.Contains(logs.text(), tc.inWarn) {
				t.Fatalf("warning does not name the cause %q:\n%s", tc.inWarn, logs.text())
			}
		})
	}
}

func TestStore_NoKeyringFallbackDeletesNothing(t *testing.T) {
	t.Parallel()
	// A previous run with a working keyring left sessions and keys behind.
	dir := newStateDir(t)
	keys := newFakeKeys()
	prev, _, _ := openStore(t, dir, vault.Persistent, keys, nil)
	mustSave(t, prev, "edf", "synthetic jar edf")
	mustSave(t, prev, "ileo", "synthetic jar ileo")
	put(t, dir, "sessions/legacy.sess", []byte("synthetic opaque bytes"))
	before := snapshot(t, dir)
	install := readInstallID(t, dir)
	keyEDF, _ := keys.get(sessionRef(install, "edf"))
	keys.resetCalls()

	s, spy, _ := openStore(t, dir, vault.Persistent, keys, errors.New("synthetic: keyring locked out"))
	mustSave(t, s, "edf", "synthetic jar new")
	wantNoSession(t, s, "ileo")

	wantSameTree(t, before, snapshot(t, dir))
	keys.wantNoCalls(t)
	if n := spy.count(); n != 0 {
		t.Fatalf("%d session opens in fallback", n)
	}
	if v, _ := keys.get(sessionRef(install, "edf")); v != keyEDF {
		t.Fatalf("keyring entry changed by the fallback")
	}
	// The next run with a keyring still finds the session.
	next, _, _ := openStore(t, dir, vault.Persistent, keys, nil)
	mustLoad(t, next, "edf", "synthetic jar edf")
}

func TestStore_EphemeralWritesNothing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{"empty state dir", func(*testing.T, string) {}},
		{"existing install id, no sessions", func(t *testing.T, dir string) {
			put(t, dir, "install-id", []byte("0123456789abcdef0123456789abcdef"))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := newStateDir(t)
			tc.setup(t, dir)
			before := snapshot(t, dir)
			keys := newFakeKeys()

			s, spy, _ := openStore(t, dir, vault.Ephemeral, keys, nil)
			if s.Persistent() {
				t.Fatalf("Persistent() = true in ephemeral mode")
			}
			for range 3 {
				mustSave(t, s, "edf", "synthetic jar")
				wantNoSession(t, s, "edf")
			}
			wantSameTree(t, before, snapshot(t, dir))
			r, set, _ := keys.calls()
			if len(r)+len(set) != 0 {
				t.Fatalf("ephemeral mode used the keyring: %d Resolve, %d Set", len(r), len(set))
			}
			if n := spy.count(); n != 0 {
				t.Fatalf("%d session opens in ephemeral mode", n)
			}
		})
	}
}

func TestStore_EphemeralDeletesExistingUnread(t *testing.T) {
	t.Parallel()
	dir := newStateDir(t)
	keys := newFakeKeys()
	ids := []string{"edf", "fakeprovider", "ileo"}
	canary := testsecrets.Canary(t, testsecrets.Cookie)
	prev, _, _ := openStore(t, dir, vault.Persistent, keys, nil)
	for _, id := range ids {
		mustSave(t, prev, id, "synthetic jar "+canary)
	}
	install := readInstallID(t, dir)
	foreign := sessionRef("fedcba9876543210fedcba9876543210", "edf")
	keys.put(foreign, base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	keys.resetCalls()

	s, spy, logs := openStore(t, dir, vault.Ephemeral, keys, nil)
	if s.Persistent() {
		t.Fatalf("Persistent() = true in ephemeral mode")
	}
	if n := spy.count(); n != 0 {
		t.Fatalf("ephemeral sweep opened %d session files, want 0", n)
	}
	resolves, sets, deletes := keys.calls()
	if len(resolves) != 0 || len(sets) != 0 {
		t.Fatalf("ephemeral sweep read or wrote keys: %d Resolve, %d Set", len(resolves), len(sets))
	}
	var want []secret.Ref
	for _, id := range ids {
		want = append(want, sessionRef(install, id))
	}
	sortRefs := func(r []secret.Ref) {
		slices.SortFunc(r, func(a, b secret.Ref) int { return strings.Compare(a.String(), b.String()) })
	}
	sortRefs(want)
	sortRefs(deletes)
	if !slices.Equal(deletes, want) {
		t.Fatalf("Deletes = %v, want exactly one per removed session %v", deletes, want)
	}
	for _, id := range ids {
		if exists(t, filepath.Join(dir, "sessions", id+".sess")) {
			t.Fatalf("sessions/%s.sess survived the ephemeral sweep", id)
		}
		if _, ok := keys.get(sessionRef(install, id)); ok {
			t.Fatalf("key of %s survived the ephemeral sweep", id)
		}
	}
	if _, ok := keys.get(foreign); !ok {
		t.Fatalf("key of another state dir was deleted")
	}

	recs := logs.records(t, slog.LevelInfo)
	if len(recs) != 1 {
		t.Fatalf("%d log lines, want exactly one:\n%s", len(recs), logs.text())
	}
	if n, ok := recs[0]["removed"].(float64); !ok || n != float64(len(ids)) {
		t.Fatalf("log line removed = %v, want %d:\n%s", recs[0]["removed"], len(ids), logs.text())
	}
	if strings.Contains(logs.text(), canary[len(testsecrets.Prefix):]) {
		t.Fatalf("log carries session content")
	}
	// Using the store afterwards keeps nothing.
	mustSave(t, s, "edf", "synthetic jar")
	if exists(t, filepath.Join(dir, "sessions", "edf.sess")) {
		t.Fatalf("ephemeral Save wrote a session file")
	}
}

func TestStore_EphemeralRemovesUnconfiguredSessions(t *testing.T) {
	t.Parallel()

	t.Run("every *.sess, only *.sess", func(t *testing.T) {
		t.Parallel()
		dir := newStateDir(t)
		install := "0123456789abcdef0123456789abcdef"
		put(t, dir, "install-id", []byte(install))
		for _, name := range []string{"old-supplier.sess", "Legacy_Name.sess", ".sess", "x--y.sess"} {
			put(t, dir, "sessions/"+name, []byte("synthetic opaque bytes"))
		}
		put(t, dir, "sessions/notes.txt", []byte("synthetic note"))
		put(t, dir, "sessions/nested/inner.sess", []byte("synthetic opaque bytes"))
		keys := newFakeKeys()

		_, spy, logs := openStore(t, dir, vault.Ephemeral, keys, nil)
		for _, name := range []string{"old-supplier.sess", "Legacy_Name.sess", ".sess", "x--y.sess"} {
			if exists(t, filepath.Join(dir, "sessions", name)) {
				t.Errorf("sessions/%s survived the sweep", name)
			}
		}
		for _, name := range []string{"notes.txt", filepath.Join("nested", "inner.sess")} {
			if !exists(t, filepath.Join(dir, "sessions", name)) {
				t.Errorf("sessions/%s removed, want only top-level *.sess removed", name)
			}
		}
		if n := spy.count(); n != 0 {
			t.Fatalf("sweep opened %d files", n)
		}
		_, _, deletes := keys.calls()
		if want := []secret.Ref{sessionRef(install, "old-supplier")}; !slices.Equal(deletes, want) {
			t.Fatalf("Deletes = %v, want %v (only valid connector ids)", deletes, want)
		}
		recs := logs.records(t, slog.LevelInfo)
		if len(recs) != 1 || recs[0]["removed"] != float64(4) {
			t.Fatalf("want one log line with removed=4:\n%s", logs.text())
		}
	})

	t.Run("no install id: files removed, no key deleted", func(t *testing.T) {
		t.Parallel()
		dir := newStateDir(t)
		put(t, dir, "sessions/edf.sess", []byte("synthetic opaque bytes"))
		keys := newFakeKeys()
		_, _, logs := openStore(t, dir, vault.Ephemeral, keys, nil)
		if exists(t, filepath.Join(dir, "sessions", "edf.sess")) {
			t.Fatalf("sessions/edf.sess survived the sweep")
		}
		keys.wantNoCalls(t)
		if exists(t, filepath.Join(dir, "install-id")) {
			t.Fatalf("ephemeral mode created install-id")
		}
		if recs := logs.records(t, slog.LevelInfo); len(recs) != 1 {
			t.Fatalf("want one log line:\n%s", logs.text())
		}
	})
}

func TestStore_NewRefusesBadOptions(t *testing.T) {
	t.Parallel()
	dir := newStateDir(t)
	_, err := vault.NewStore(t.Context(), vault.Options{
		StateDir: dir, Mode: vault.Persistent, Keyring: newFakeKeys(), Rand: nil,
	})
	if !errors.Is(err, vault.ErrInvalidArgument) {
		t.Fatalf("NewStore(nil Rand): err = %v, want ErrInvalidArgument", err)
	}
	_, err = vault.NewStore(t.Context(), vault.Options{
		StateDir: filepath.Join(dir, "missing"), Mode: vault.Persistent, Keyring: newFakeKeys(), Rand: rand.Reader,
	})
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("NewStore(missing state dir): err = %v, want fs.ErrNotExist", err)
	}
}
