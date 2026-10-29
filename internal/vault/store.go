package vault

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/secret"
)

// Store layout and keyring naming (ADR 0009, "Key source", "File location").
const (
	// KeyringService is the keyring service of every session key.
	KeyringService = "facto-session"
	// InstallIDFile is <state_dir>/install-id.
	InstallIDFile = "install-id"
	// SessionsDir holds <id>.sess and <id>.lock under the state dir.
	SessionsDir = "sessions"

	sessExt      = ".sess"
	lockExt      = ".lock"
	installIDRaw = installIDLen / 2
	// maxInstallIDRead bounds the install-id read: anything longer is
	// malformed anyway.
	maxInstallIDRead = installIDLen + 1
)

// Mode selects how sessions are kept.
type Mode int

const (
	// Persistent keeps sessions/<id>.sess sealed under a per-connector
	// keyring key rotated on every Save.
	Persistent Mode = iota
	// Ephemeral keeps nothing. NewStore removes every sessions/*.sess without
	// opening it and Deletes the keyring entry of each one whose stem is a
	// valid connector id (when install-id is readable and a keyring is
	// available), without reading it; one log line (Info, attribute
	// "removed" = count).
	Ephemeral
)

// Sentinel errors of the store.
var (
	// ErrNoSession reports no usable saved session: missing file, missing or
	// malformed key, or a file that failed Open with ErrInvalid (then
	// removed). The connector logs in again.
	ErrNoSession = errors.New("vault: no saved session")
	// ErrKeyring reports a keyring backend error or timeout on Resolve or
	// Set. It wraps the backend error. The session file is kept.
	ErrKeyring = errors.New("vault: keyring error")
)

// KeyBackend is the store's view of the keyring (*keyring.Provider satisfies
// it). A missing entry resolves to an error wrapping
// secret.ErrSecretNotFound. Refs are
// keyring://facto-session/<install-id>/<connector-id>.
type KeyBackend interface {
	Resolve(ctx context.Context, ref secret.Ref) (secret.Secret, error)
	Set(ctx context.Context, ref secret.Ref, value secret.Secret) error
	Delete(ctx context.Context, ref secret.Ref) error
}

// OpenFunc opens name (e.g. "edf.sess") inside the sessions directory for
// reading. Default: (*fsx.Root).OpenRegular.
type OpenFunc func(sessions *fsx.Root, name string) (io.ReadCloser, error)

// WriteFunc writes name (e.g. "edf.sess") inside the sessions directory.
// Default: (*fsx.Root).WriteAtomic. An error wrapping fsx.ErrNotDurable
// means the new content is in place but may not survive a crash.
type WriteFunc func(ctx context.Context, sessions *fsx.Root, name string, data []byte) error

// Options configures NewStore.
type Options struct {
	// StateDir is the existing private state directory.
	StateDir string
	// Mode selects persistent or ephemeral sessions.
	Mode Mode
	// Keyring is the key backend; nil means none.
	Keyring KeyBackend
	// KeyringErr, when non-nil, reports the keyring backend as unavailable or
	// unsupported; it is the cause named in the fallback warning.
	KeyringErr error
	// Rand provides keys, nonces and the install id. Nil is refused.
	Rand io.Reader
	// Log receives the store's log lines. Nil discards them.
	Log *slog.Logger
	// Open opens session files; nil means fsx OpenRegular.
	Open OpenFunc
	// Write writes session files; nil means fsx WriteAtomic.
	Write WriteFunc

	// Test seams for install-id (set by export_test.go only): nil means
	// fsx WriteNew and fsx OpenRegular.
	writeNew      func(ctx context.Context, state *fsx.Root, name string, src io.Reader) error
	openInstallID func(state *fsx.Root, name string) (io.ReadCloser, error)
}

// Store saves and loads per-connector sessions under <state_dir>/sessions,
// sealed with a per-connector key kept in the keyring (ADR 0009). Safe for
// concurrent use; concurrent saves of one connector, from this or another
// process, are serialized by an fsx lock.
type Store struct {
	stateDir   string
	persistent bool
	installID  string
	keys       KeyBackend
	rand       io.Reader
	sealer     *Sealer
	log        *slog.Logger
	open       OpenFunc
	write      WriteFunc

	writeNew      func(ctx context.Context, state *fsx.Root, name string, src io.Reader) error
	openInstallID func(state *fsx.Root, name string) (io.ReadCloser, error)
}

// NewStore prepares the store. Persistent mode with a keyring reads
// <state_dir>/install-id or creates it once (16 random bytes as 32 lowercase
// hex chars, 0600, never rewritten); a malformed install-id disables
// persistence for the run with one warning and is left untouched. Persistent
// mode without a usable keyring falls back to ephemeral with one warning
// naming the cause, and neither writes nor deletes anything. Ephemeral mode
// runs the sweep described on Ephemeral. A missing state dir wraps
// fs.ErrNotExist; a nil Rand or an unknown Mode is ErrInvalidArgument.
func NewStore(ctx context.Context, opts Options) (*Store, error) {
	if opts.Rand == nil {
		return nil, fmt.Errorf("%w: nil random source", ErrInvalidArgument)
	}
	if opts.Mode != Persistent && opts.Mode != Ephemeral {
		return nil, fmt.Errorf("%w: unknown session mode %d", ErrInvalidArgument, opts.Mode)
	}
	sealer, err := NewSealer(opts.Rand)
	if err != nil {
		return nil, err
	}
	s := &Store{
		stateDir: opts.StateDir,
		keys:     opts.Keyring,
		rand:     opts.Rand,
		sealer:   sealer,
		log:      opts.Log,
		open:     opts.Open,
		write:    opts.Write,

		writeNew:      opts.writeNew,
		openInstallID: opts.openInstallID,
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.open == nil {
		s.open = openRegular
	}
	if s.write == nil {
		s.write = writeAtomic
	}
	if s.writeNew == nil {
		s.writeNew = writeNew
	}
	if s.openInstallID == nil {
		s.openInstallID = openRegular
	}
	if err := fsx.CheckPrivate(opts.StateDir); err != nil {
		return nil, fmt.Errorf("vault: state dir: %w", err)
	}
	state, err := fsx.Open(opts.StateDir)
	if err != nil {
		return nil, fmt.Errorf("vault: state dir: %w", err)
	}
	defer func() { _ = state.Close() }() // read-only use below

	keyringOK := opts.Keyring != nil && opts.KeyringErr == nil
	if opts.Mode == Ephemeral {
		if err := s.sweep(ctx, state, keyringOK); err != nil {
			return nil, err
		}
		return s, nil
	}
	if !keyringOK {
		cause := "no keyring backend"
		if opts.KeyringErr != nil {
			cause = opts.KeyringErr.Error()
		}
		s.log.WarnContext(ctx, "vault: keyring unavailable, sessions are ephemeral for this run", "cause", cause)
		return s, nil
	}
	id, err := s.ensureInstallID(ctx, state)
	if errors.Is(err, fsx.ErrLinkUnsupported) {
		s.log.WarnContext(ctx, "vault: install-id cannot be created (no hard link support in the state dir), sessions are ephemeral for this run", "file", InstallIDFile)
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if id == "" {
		s.log.WarnContext(ctx, "vault: malformed install-id, sessions are ephemeral for this run", "file", InstallIDFile)
		return s, nil
	}
	s.installID = id
	s.persistent = true
	return s, nil
}

func openRegular(dir *fsx.Root, name string) (io.ReadCloser, error) {
	f, err := dir.OpenRegular(name)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	return f, nil
}

func writeAtomic(ctx context.Context, sessions *fsx.Root, name string, data []byte) error {
	if err := sessions.WriteAtomic(ctx, name, data); err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	return nil
}

func writeNew(ctx context.Context, state *fsx.Root, name string, src io.Reader) error {
	if err := state.WriteNew(ctx, name, src); err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	return nil
}

// Persistent reports whether Save and Load use the disk and the keyring.
func (s *Store) Persistent() bool { return s.persistent }

// Save seals blob under a new key for id and stores it (ADR 0009,
// "Rotation"): sessions/ is created 0700, the lock sessions/<id>.lock is
// held, a new key is generated and blob sealed, the key is Set in the
// keyring (failure or timeout: the save is aborted, the previous pair is
// untouched, the error wraps ErrKeyring), then sessions/<id>.sess is written
// atomically (failure: the previous file, now undecryptable, is removed and a
// warning logged). An error wrapping fsx.ErrNotDurable means the new session
// is in place and matches the new key, but may not survive a crash. An
// invalid id is ErrInvalidArgument before any file or keyring access. When
// the store is not persistent Save writes nothing and returns nil. The caller
// keeps ownership of blob.
func (s *Store) Save(ctx context.Context, id string, blob secret.Secret) error {
	if err := checkID(id); err != nil {
		return err
	}
	if !s.persistent {
		return nil
	}
	state, err := fsx.Open(s.stateDir)
	if err != nil {
		return fmt.Errorf("vault: save %s: %w", id, err)
	}
	defer func() { _ = state.Close() }()
	if err := state.MkdirPrivate(SessionsDir); err != nil {
		return fmt.Errorf("vault: save %s: %w", id, err)
	}
	sessions, err := state.OpenDir(SessionsDir)
	if err != nil {
		return fmt.Errorf("vault: save %s: %w", id, err)
	}
	defer func() { _ = sessions.Close() }()
	lock, err := sessions.Lock(ctx, id+lockExt)
	if err != nil {
		return fmt.Errorf("vault: save %s: %w", id, err)
	}
	defer func() { _ = lock.Close() }() // nothing written through it

	encoded, key, err := s.newKey()
	if err != nil {
		return fmt.Errorf("vault: save %s: %w", id, err)
	}
	defer key.Wipe()
	defer encoded.Wipe()
	pt := []byte(blob.Expose())
	defer clear(pt)
	file, err := s.sealer.Seal(ctx, s.installID, id, key, pt)
	if err != nil {
		return fmt.Errorf("vault: save %s: %w", id, err)
	}
	if err := s.keys.Set(ctx, s.ref(id), encoded); err != nil {
		s.log.WarnContext(ctx, "vault: session key not stored, previous session kept", "connector", id)
		return fmt.Errorf("vault: save %s: %w: %w", id, ErrKeyring, err)
	}
	if err := s.write(ctx, sessions, id+sessExt, file); err != nil {
		if errors.Is(err, fsx.ErrNotDurable) {
			// The new file is in place and matches the new key.
			return fmt.Errorf("vault: save %s: %w", id, err)
		}
		rmErr := sessions.Remove(id + sessExt)
		if rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			err = errors.Join(err, rmErr)
		}
		s.log.WarnContext(ctx, "vault: session file not written, previous session removed", "connector", id)
		return fmt.Errorf("vault: save %s: %w", id, err)
	}
	return nil
}

// Load returns the saved session blob of id. An invalid id is
// ErrInvalidArgument before any access. No file, or a missing or malformed
// key, is ErrNoSession (the file is kept and not opened). A keyring error
// wraps ErrKeyring and a read error is wrapped as is; in both cases the file
// is kept. A file that fails authentication (ErrInvalid) is removed, logged
// once, and reported as ErrNoSession. When the store is not persistent Load
// returns ErrNoSession without touching anything. The caller wipes the
// returned Secret after use.
func (s *Store) Load(ctx context.Context, id string) (secret.Secret, error) {
	if err := checkID(id); err != nil {
		return secret.Secret{}, err
	}
	if !s.persistent {
		return secret.Secret{}, ErrNoSession
	}
	state, err := fsx.Open(s.stateDir)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("vault: load %s: %w", id, err)
	}
	defer func() { _ = state.Close() }()
	sessions, err := state.OpenDir(SessionsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return secret.Secret{}, ErrNoSession
	}
	if err != nil {
		return secret.Secret{}, fmt.Errorf("vault: load %s: %w", id, err)
	}
	defer func() { _ = sessions.Close() }()
	name := id + sessExt
	if _, err := sessions.Lstat(name); errors.Is(err, fs.ErrNotExist) {
		return secret.Secret{}, ErrNoSession
	} else if err != nil {
		return secret.Secret{}, fmt.Errorf("vault: load %s: %w", id, err)
	}
	// Held so that a concurrent Save cannot pair this key with its new
	// file (or the reverse) and make a valid session look invalid.
	lock, err := sessions.Lock(ctx, id+lockExt)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("vault: load %s: %w", id, err)
	}
	defer func() { _ = lock.Close() }()

	encoded, err := s.keys.Resolve(ctx, s.ref(id))
	if errors.Is(err, secret.ErrSecretNotFound) {
		return secret.Secret{}, ErrNoSession
	}
	if err != nil {
		return secret.Secret{}, fmt.Errorf("vault: load %s: %w: %w", id, ErrKeyring, err)
	}
	key, err := ParseKey(encoded)
	encoded.Wipe()
	if err != nil {
		return secret.Secret{}, ErrNoSession
	}
	defer key.Wipe()

	f, err := s.open(sessions, name)
	if errors.Is(err, fs.ErrNotExist) {
		return secret.Secret{}, ErrNoSession
	}
	if err != nil {
		return secret.Secret{}, fmt.Errorf("vault: load %s: %w", id, err)
	}
	blob, err := Open(ctx, s.installID, id, key, f)
	_ = f.Close() // read-only; the open result is the one reported
	if errors.Is(err, ErrInvalid) {
		if rmErr := sessions.Remove(name); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			s.log.WarnContext(ctx, "vault: invalid session file could not be removed", "connector", id)
			return secret.Secret{}, fmt.Errorf("vault: load %s: %w: %w", id, ErrNoSession, rmErr)
		}
		s.log.InfoContext(ctx, "vault: invalid session file removed, login required", "connector", id)
		return secret.Secret{}, ErrNoSession
	}
	if err != nil {
		return secret.Secret{}, fmt.Errorf("vault: load %s: %w", id, err)
	}
	return blob, nil
}

// sweep removes every top-level sessions/*.sess without opening it and, when
// a keyring is usable and install-id is valid, Deletes the key of each
// removed file whose stem is a valid connector id, without reading it. It
// logs one line. A file that could not be removed is an error: the user asked
// for nothing to be kept.
func (s *Store) sweep(ctx context.Context, state *fsx.Root, keyringOK bool) error {
	installID, keysSkipped := "", false
	if keyringOK {
		// An unreadable install-id must not keep sessions on disk: the
		// files are still removed, only the key deletes are skipped.
		id, err := s.readInstallID(state)
		if err != nil {
			keysSkipped = true
		}
		installID = id
	}
	removed, keysDeleted, keysFailed := 0, 0, 0
	var errs []error
	sessions, err := state.OpenDir(SessionsDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return fmt.Errorf("vault: ephemeral sweep: %w", err)
	default:
		defer func() { _ = sessions.Close() }()
		des, err := sessions.ReadDir()
		if err != nil {
			return fmt.Errorf("vault: ephemeral sweep: %w", err)
		}
		for _, de := range des {
			name := de.Name()
			if de.IsDir() || !strings.HasSuffix(name, sessExt) {
				continue
			}
			if err := sessions.Remove(name); err != nil {
				errs = append(errs, err)
				continue
			}
			removed++
			stem := strings.TrimSuffix(name, sessExt)
			if installID == "" || !ValidConnectorID(stem) {
				continue
			}
			ref := sessionRef(installID, stem)
			if err := s.keys.Delete(ctx, ref); err != nil {
				keysFailed++
				continue
			}
			keysDeleted++
		}
	}
	level := slog.LevelInfo
	if keysFailed > 0 || keysSkipped || len(errs) > 0 {
		level = slog.LevelWarn
	}
	s.log.Log(ctx, level, "vault: ephemeral sessions, saved sessions removed",
		"removed", removed, "keys_deleted", keysDeleted, "keys_failed", keysFailed, "keys_skipped", keysSkipped, "remove_failed", len(errs))
	if len(errs) > 0 {
		return fmt.Errorf("vault: ephemeral sweep: %w", errors.Join(errs...))
	}
	return nil
}

// ensureInstallID returns the install id, creating it once when missing. It
// returns "" when the file exists but is malformed (left untouched).
func (s *Store) ensureInstallID(ctx context.Context, state *fsx.Root) (string, error) {
	id, err := s.readInstallID(state)
	if err != nil || id != "" || s.installIDPresent(state) {
		return id, err
	}
	raw := make([]byte, installIDRaw)
	if _, err := io.ReadFull(s.rand, raw); err != nil {
		return "", fmt.Errorf("vault: install id: %w", err)
	}
	fresh := hex.EncodeToString(raw)
	err = s.writeNew(ctx, state, InstallIDFile, strings.NewReader(fresh))
	switch {
	case err == nil, errors.Is(err, fsx.ErrNotDurable):
		// Not durable: the id is published, it may only be lost in a crash,
		// which a later run handles like a first run.
		return fresh, nil
	case errors.Is(err, fs.ErrExist):
		// Another first run won the race: use its id.
		return s.readInstallID(state)
	default:
		return "", fmt.Errorf("vault: install id: %w", err)
	}
}

// installIDPresent reports whether something exists at install-id.
func (*Store) installIDPresent(state *fsx.Root) bool {
	_, err := state.Lstat(InstallIDFile)
	return !errors.Is(err, fs.ErrNotExist)
}

// readInstallID returns the install id, or "" when the file is missing,
// malformed or not a regular file. Other errors are returned.
func (s *Store) readInstallID(state *fsx.Root) (string, error) {
	f, err := s.openInstallID(state, InstallIDFile)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, fsx.ErrNotRegular):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("vault: install id: %w", err)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxInstallIDRead))
	_ = f.Close() // read-only; the read result is the one reported
	if err != nil {
		return "", fmt.Errorf("vault: install id: %w", err)
	}
	if !validInstallID(string(b)) {
		return "", nil
	}
	return string(b), nil
}

// newKey returns a fresh random key, encoded for the keyring and decoded.
func (s *Store) newKey() (secret.Secret, Key, error) {
	var raw [KeySize]byte
	defer clear(raw[:])
	if _, err := io.ReadFull(s.rand, raw[:]); err != nil {
		return secret.Secret{}, Key{}, fmt.Errorf("read key: %w", err)
	}
	enc := make([]byte, base64.RawURLEncoding.EncodedLen(KeySize))
	base64.RawURLEncoding.Encode(enc, raw[:])
	encoded := secret.New(enc) // takes ownership: Wipe clears enc
	key, err := ParseKey(encoded)
	if err != nil {
		encoded.Wipe()
		return secret.Secret{}, Key{}, err
	}
	return encoded, key, nil
}

func (s *Store) ref(id string) secret.Ref { return sessionRef(s.installID, id) }

func sessionRef(installID, id string) secret.Ref {
	return secret.Ref{Scheme: secret.SchemeKeyring, Item: KeyringService, Field: installID + "/" + id}
}

// checkID refuses anything ValidConnectorID refuses, and anything SafeName
// would change.
func checkID(id string) error {
	if !ValidConnectorID(id) || fsx.SafeName(id) != id {
		return fmt.Errorf("%w: connector id", ErrInvalidArgument)
	}
	return nil
}
