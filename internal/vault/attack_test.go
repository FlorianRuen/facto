//go:build unix

// Red-team attacks on the session store (J1 task T27): session files (and
// their keys) swapped between connectors, truncated or extended at every
// length, replaced by symlinks, FIFOs or hard links, a symlinked
// sessions/ or install-id, and a file sealed under another install id. A
// test passes when the attack is defeated: no blob from another connector
// or install is ever returned, nothing is read or written through a
// link, and the canary blob never appears in an error. Everything is
// synthetic; blobs are testsecrets canaries.
package vault_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
	"github.com/FlorianRuen/facto/internal/vault"
)

// noBlob loads id and fails if any blob comes back or the error quotes
// one of the canaries.
func noBlob(t *testing.T, s *vault.Store, id string, canaries ...string) error {
	t.Helper()
	got, err := s.Load(t.Context(), id)
	if err == nil || !got.IsZero() {
		t.Fatalf("Load(%q) returned a blob (err %v): an attacker-controlled file was accepted", id, err)
	}
	for _, c := range canaries {
		if strings.Contains(err.Error(), c) {
			t.Fatalf("Load(%q) error quotes a blob", id)
		}
	}
	return err
}

// TestAttack_VaultSessionSwappedBetweenConnectors: copying connector a's
// file, and even its key, to connector b (ids chosen to collide in a naive
// AAD encoding) never yields a's blob for b; the foreign file is removed
// and a's own session still loads.
func TestAttack_VaultSessionSwappedBetweenConnectors(t *testing.T) {
	t.Parallel()
	for _, pair := range [][2]string{{"edf", "ileo"}, {"a", "a-b"}, {"a-b", "ab"}, {"bouygues", "bouygues-telecom"}, {"x1", "x"}} {
		t.Run(pair[0]+"->"+pair[1], func(t *testing.T) {
			t.Parallel()
			f := newPersistent(t)
			src, dst := pair[0], pair[1]
			blobSrc := testsecrets.Canary(t, testsecrets.Cookie)
			blobDst := testsecrets.Canary(t, testsecrets.Session)
			mustSave(t, f.store, src, blobSrc)
			mustSave(t, f.store, dst, blobDst)
			id := f.installID(t)

			put(t, f.dir, "sessions/"+dst+".sess", readBytes(t, f.sessPath(src)))
			if err := noBlob(t, f.store, dst, blobSrc, blobDst); !errors.Is(err, vault.ErrNoSession) {
				t.Errorf("Load(%s) with %s's file = %v, want ErrNoSession", dst, src, err)
			}
			if exists(t, f.sessPath(dst)) {
				t.Errorf("foreign file kept at %s", dst)
			}

			// File and key both copied: the AAD binds the connector id.
			mustSave(t, f.store, dst, blobDst)
			v, _ := f.keys.get(sessionRef(id, src))
			f.keys.put(sessionRef(id, dst), v)
			put(t, f.dir, "sessions/"+dst+".sess", readBytes(t, f.sessPath(src)))
			if err := noBlob(t, f.store, dst, blobSrc, blobDst); !errors.Is(err, vault.ErrNoSession) {
				t.Errorf("Load(%s) with %s's file and key = %v, want ErrNoSession", dst, src, err)
			}
			mustLoad(t, f.store, src, blobSrc)
		})
	}
}

// TestAttack_VaultTruncatedOrExtendedAtEveryLength: a session file cut at
// every length, extended by trailing bytes, or with its header rewritten
// is ErrNoSession (removed), never a partial blob, never a panic.
func TestAttack_VaultTruncatedOrExtendedAtEveryLength(t *testing.T) {
	t.Parallel()
	f := newPersistent(t)
	blob := testsecrets.Canary(t, testsecrets.Cookie)
	mustSave(t, f.store, "edf", blob)
	orig := readBytes(t, f.sessPath("edf"))
	key, _ := f.keys.get(sessionRef(f.installID(t), "edf"))

	variants := map[string][]byte{}
	for n := 0; n < len(orig); n++ {
		variants["cut "+strconv.Itoa(n)] = orig[:n]
	}
	variants["extended by one byte"] = append(bytes.Clone(orig), 0)
	variants["extended by a copy"] = append(bytes.Clone(orig), orig...)
	variants["oversized"] = append(bytes.Clone(orig), bytes.Repeat([]byte{0}, vault.MaxFileSize)...)
	v2 := bytes.Clone(orig)
	v2[len(vault.Magic)] = 0x02
	variants["version 2 header"] = v2
	zeroNonce := bytes.Clone(orig)
	clear(zeroNonce[len(vault.Magic)+1 : vault.HeaderSize])
	variants["nonce zeroed"] = zeroNonce
	noTag := bytes.Clone(orig[:len(orig)-vault.Overhead])
	variants["tag stripped"] = noTag
	for name, data := range variants {
		put(t, f.dir, "sessions/edf.sess", data)
		f.keys.put(sessionRef(f.installID(t), "edf"), key)
		if err := noBlob(t, f.store, "edf", blob); !errors.Is(err, vault.ErrNoSession) {
			t.Errorf("%s: Load = %v, want ErrNoSession", name, err)
		}
		if exists(t, f.sessPath("edf")) {
			t.Errorf("%s: invalid file kept", name)
		}
	}
}

// TestAttack_VaultSessionFileReplacedByLinkOrFIFO: a session file that is
// a symlink (to another connector's valid file, with the key copied), a
// FIFO or a hard link to another connector's file never yields a blob;
// Load never blocks on the FIFO and never removes the link target.
func TestAttack_VaultSessionFileReplacedByLinkOrFIFO(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"symlink", "fifo", "hardlink", "dangling symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			f := newPersistent(t)
			blobA := testsecrets.Canary(t, testsecrets.Cookie)
			mustSave(t, f.store, "edf", blobA)
			mustSave(t, f.store, "ileo", "synthetic ileo blob")
			id := f.installID(t)
			v, _ := f.keys.get(sessionRef(id, "edf"))
			f.keys.put(sessionRef(id, "ileo"), v)
			target, link := f.sessPath("edf"), f.sessPath("ileo")
			before := readBytes(t, target)
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
			case "dangling symlink":
				if err := os.Symlink(filepath.Join(f.dir, "nowhere"), link); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(link, 0o600); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(target, link); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(link, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() {
				_, err := f.store.Load(t.Context(), "ileo")
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("Load(ileo) through a planted entry returned a blob")
				}
				if strings.Contains(err.Error(), blobA) {
					t.Fatal("error quotes the blob")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Load blocked on a planted session entry")
			}
			if got := readBytes(t, target); !bytes.Equal(got, before) {
				t.Error("link target changed")
			}
			mustLoad(t, f.store, "edf", blobA)
		})
	}
}

// TestAttack_VaultSymlinkedSessionsDirOrInstallID: a sessions/ directory
// planted as a symlink to another state dir's sessions, or an install-id
// planted as a symlink to another install's id, is never followed: no
// blob of the other install is returned and nothing is written there.
func TestAttack_VaultSymlinkedSessionsDirOrInstallID(t *testing.T) {
	t.Parallel()
	t.Run("sessions dir", func(t *testing.T) {
		t.Parallel()
		keys := newFakeKeys()
		dirA, dirB := newStateDir(t), newStateDir(t)
		a, _, _ := openStore(t, dirA, vault.Persistent, keys, nil)
		blobA := testsecrets.Canary(t, testsecrets.Cookie)
		mustSave(t, a, "edf", blobA)
		b, _, _ := openStore(t, dirB, vault.Persistent, keys, nil)
		// Same key under B's ref: only the AAD and the link check remain.
		v, _ := keys.get(sessionRef(readInstallID(t, dirA), "edf"))
		keys.put(sessionRef(readInstallID(t, dirB), "edf"), v)
		if err := os.Symlink(filepath.Join(dirA, "sessions"), filepath.Join(dirB, "sessions")); err != nil {
			t.Fatal(err)
		}
		snapA := snapshot(t, dirA)
		if got, err := b.Load(t.Context(), "edf"); err == nil || !got.IsZero() {
			t.Fatalf("Load through a symlinked sessions dir returned a blob (err %v)", err)
		}
		if err := b.Save(t.Context(), "ileo", testsecretsBlob(t)); err == nil {
			t.Error("Save through a symlinked sessions dir succeeded")
		}
		wantSameTree(t, snapA, snapshot(t, dirA))
	})
	t.Run("install-id", func(t *testing.T) {
		t.Parallel()
		keys := newFakeKeys()
		dirA, dirB := newStateDir(t), newStateDir(t)
		a, _, _ := openStore(t, dirA, vault.Persistent, keys, nil)
		blobA := testsecrets.Canary(t, testsecrets.Cookie)
		mustSave(t, a, "edf", blobA)
		// B gets A's session file and a symlinked install-id naming A.
		put(t, dirB, "sessions/edf.sess", readBytes(t, filepath.Join(dirA, "sessions", "edf.sess")))
		if err := os.Symlink(filepath.Join(dirA, vault.InstallIDFile), filepath.Join(dirB, vault.InstallIDFile)); err != nil {
			t.Fatal(err)
		}
		s, err := vault.NewStore(t.Context(), vault.Options{StateDir: dirB, Mode: vault.Persistent, Keyring: keys, Rand: randReader()})
		if err != nil {
			return // refused outright: fine
		}
		if s.Persistent() {
			if got, err := s.Load(t.Context(), "edf"); err == nil || !got.IsZero() {
				t.Fatal("a symlinked install-id let B open A's session")
			}
		}
		if fi, err := os.Lstat(filepath.Join(dirB, vault.InstallIDFile)); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("planted install-id link replaced or removed: %v", err)
		}
	})
}

func testsecretsBlob(t *testing.T) secret.Secret {
	t.Helper()
	return secret.FromString(testsecrets.Canary(t, testsecrets.Session))
}

func randReader() io.Reader { return rand.Reader }
