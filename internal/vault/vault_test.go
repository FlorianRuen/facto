// Tests for internal/vault (J1 T14, ADR 0009 "File format (version 1)").
//
// Expected API (package vault; tests are black-box, package vault_test):
//
//	// Format constants (ADR 0009).
//	const (
//		Magic         = "FACTOSES"        // 8 bytes
//		Version1      = 0x01              // version byte
//		NonceSize     = 24                // XChaCha20-Poly1305 nonce
//		HeaderSize    = 33                // magic + version + nonce
//		Overhead      = 16                // Poly1305 tag
//		MinFileSize   = 49                // HeaderSize + Overhead (empty plaintext; Seal refuses it)
//		MaxFileSize   = 1 << 20           // 1 MiB
//		MaxPlaintext  = MaxFileSize - HeaderSize - Overhead // 1 048 527
//		KeySize       = 32
//		EncodedKeyLen = 43                // base64url, no padding
//	)
//
//	// Sentinel errors.
//	var (
//		ErrInvalid         error // any format or authentication failure of a file; opaque, never carries file bytes
//		ErrMalformedKey    error // ParseKey input is not 43 chars of strict base64url giving 32 bytes; zero or wiped Key
//		ErrInvalidArgument error // bad install id (not 32 lowercase hex) or connector id (not ^[a-z0-9]+(-[a-z0-9]+)*$, 1..40 bytes)
//		ErrPlaintextSize   error // Seal: empty plaintext or more than MaxPlaintext bytes
//	)
//
//	// Key is a decoded 32-byte session key. Decision: a dedicated type rather than
//	// secret.Secret, so that Seal/Open cannot be handed an undecoded or
//	// wrong-length value and the decoded buffer has an owner that can wipe it.
//	// Every rendering (fmt verbs, JSON, text, slog) is masked like secret.Secret.
//	// The zero value is not a usable key (ErrMalformedKey).
//	type Key struct{ /* unexported */ }
//	func ParseKey(encoded secret.Secret) (Key, error) // base64.RawURLEncoding.Strict(), exactly 32 bytes
//	func (k Key) Wipe()                               // zeroes the 32 bytes for every copy; Seal/Open then refuse it
//
//	// Sealer seals with nonces read from an injected random source.
//	type Sealer struct{ /* unexported */ }
//	// NewSealer refuses a nil reader with ErrInvalidArgument (J1 T16, from the
//	// T14 review) instead of panicking at the first Seal.
//	func NewSealer(rand io.Reader) (*Sealer, error) // production passes crypto/rand.Reader
//	func (s *Sealer) Seal(ctx context.Context, installID, id string, key Key, plaintext []byte) ([]byte, error)
//
//	// Seal is NewSealer(crypto/rand.Reader).Seal. It wipes plaintext after a
//	// successful seal. The result is the complete v1 file.
//	func Seal(ctx context.Context, installID, id string, key Key, plaintext []byte) ([]byte, error)
//
//	// Open reads file through io.LimitReader(file, MaxFileSize+1), checks size,
//	// magic, version, then AEAD-opens in place with AAD = magic‖version‖installID‖id.
//	// On any failure it returns a zero secret.Secret. A read I/O error is wrapped
//	// (%w) and is not ErrInvalid.
//	func Open(ctx context.Context, installID, id string, key Key, file io.Reader) (secret.Secret, error)
package vault_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/vault"
)

// Synthetic identifiers. Install ids are 32 lowercase hex chars (ADR 0009).
const (
	testInstall  = "0123456789abcdef0123456789abcdef"
	otherInstall = "0123456789abcdef0123456789abcdee"
	testID       = "fakeprovider"
)

// fixedKeyBytes is the synthetic key used by the golden file: 0x00..0x1f.
func fixedKeyBytes() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func encodeKey(raw []byte) secret.Secret {
	return secret.FromString(base64.RawURLEncoding.EncodeToString(raw))
}

func mustKey(t *testing.T, raw []byte) vault.Key {
	t.Helper()
	k, err := vault.ParseKey(encodeKey(raw))
	if err != nil {
		t.Fatalf("ParseKey(valid 32-byte key): %v", err)
	}
	return k
}

// mustSeal seals a copy of pt (Seal wipes its input).
func mustSeal(t *testing.T, id string, key vault.Key, pt []byte) []byte {
	t.Helper()
	file, err := vault.Seal(t.Context(), testInstall, id, key, bytes.Clone(pt))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return file
}

func openBytes(t *testing.T, install, id string, key vault.Key, file []byte) (secret.Secret, error) {
	t.Helper()
	return vault.Open(t.Context(), install, id, key, bytes.NewReader(file))
}

// wantInvalid asserts the opaque ErrInvalid and no plaintext.
func wantInvalid(t *testing.T, got secret.Secret, err error) {
	t.Helper()
	if !errors.Is(err, vault.ErrInvalid) {
		t.Fatalf("Open error = %v, want ErrInvalid", err)
	}
	if !got.IsZero() {
		t.Fatalf("Open returned plaintext alongside an error")
	}
}

// countingReader counts the bytes handed out by r.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// errOverread is returned by endlessReader once a reader that ignores
// io.LimitReader has pulled far more than MaxFileSize+1 bytes, so a missing
// limit fails the test instead of exhausting memory.
var errOverread = errors.New("test reader: read far past MaxFileSize+1")

// endlessReader yields fill "forever" (up to 4 MiB, then errOverread) and
// counts what it hands out.
type endlessReader struct {
	fill byte
	n    int64
}

func (e *endlessReader) Read(p []byte) (int, error) {
	if e.n >= 4*vault.MaxFileSize {
		return 0, errOverread
	}
	for i := range p {
		p[i] = e.fill
	}
	e.n += int64(len(p))
	return len(p), nil
}

// sequenceReader returns 0, 1, 2, ... (mod 256) and records every byte read.
type sequenceReader struct {
	next byte
	got  []byte
}

func (s *sequenceReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = s.next
		s.next++
	}
	s.got = append(s.got, p...)
	return len(p), nil
}

// errReader always fails.
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// independentV1 builds a file with chacha20poly1305 directly, following the
// ADR layout, with an arbitrary version byte. It lets the tests check the
// format without trusting vault.Seal.
func independentV1(t *testing.T, version byte, install, id string, key, nonce, pt []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatalf("NewX: %v", err)
	}
	hdr := append([]byte("FACTOSES"), version)
	aad := append(append(bytes.Clone(hdr), install...), id...)
	out := append(bytes.Clone(hdr), nonce...)
	return aead.Seal(out, nonce, pt, aad)
}

func TestFormat_Constants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		got, want int
	}{
		{"NonceSize", vault.NonceSize, 24},
		{"HeaderSize", vault.HeaderSize, 33},
		{"Overhead", vault.Overhead, 16},
		{"MinFileSize", vault.MinFileSize, 49},
		{"MaxFileSize", vault.MaxFileSize, 1 << 20},
		{"MaxPlaintext", vault.MaxPlaintext, 1_048_527},
		{"KeySize", vault.KeySize, 32},
		{"EncodedKeyLen", vault.EncodedKeyLen, 43},
		{"Version1", int(vault.Version1), 1},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
	if vault.Magic != "FACTOSES" {
		t.Errorf("Magic = %q, want FACTOSES", vault.Magic)
	}
}

func TestSealOpen_RoundTrip(t *testing.T) {
	t.Parallel()
	maxID := strings.Repeat("a", 40)
	tests := []struct {
		name     string
		id       string
		pt       []byte
		wantErr  error
		wantSize int
	}{
		{name: "small", id: testID, pt: []byte("synthetic cookie jar"), wantSize: 33 + 20 + 16},
		{name: "one byte", id: "edf", pt: []byte{0x00}, wantSize: vault.MinFileSize + 1},
		{name: "max size", id: testID, pt: bytes.Repeat([]byte{'s'}, vault.MaxPlaintext), wantSize: vault.MaxFileSize},
		{name: "40-byte connector id", id: maxID, pt: []byte("synthetic"), wantSize: 33 + 9 + 16},
		{name: "empty refused", id: testID, pt: []byte{}, wantErr: vault.ErrPlaintextSize},
		{name: "nil refused", id: testID, pt: nil, wantErr: vault.ErrPlaintextSize},
		{name: "max+1 refused", id: testID, pt: bytes.Repeat([]byte{'s'}, vault.MaxPlaintext+1), wantErr: vault.ErrPlaintextSize},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := mustKey(t, randBytes(t, 32))
			in := bytes.Clone(tc.pt)
			file, err := vault.Seal(t.Context(), testInstall, tc.id, key, in)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Seal error = %v, want %v", err, tc.wantErr)
				}
				if file != nil {
					t.Fatalf("Seal returned %d bytes alongside an error", len(file))
				}
				return
			}
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if len(file) != tc.wantSize {
				t.Fatalf("file size = %d, want %d", len(file), tc.wantSize)
			}
			if !bytes.HasPrefix(file, []byte("FACTOSES\x01")) {
				t.Fatalf("file header = %x, want FACTOSES 01", file[:9])
			}
			if !bytes.Equal(in, make([]byte, len(in))) {
				t.Fatalf("Seal did not wipe the plaintext buffer")
			}
			if len(tc.pt) >= 8 && bytes.Contains(file, tc.pt[:8]) {
				t.Fatalf("sealed file contains plaintext bytes")
			}
			got, err := openBytes(t, testInstall, tc.id, key, file)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if got.Expose() != string(tc.pt) {
				t.Fatalf("Open returned %d bytes, want the %d sealed bytes", len(got.Expose()), len(tc.pt))
			}
		})
	}
}

func TestSeal_GoldenV1(t *testing.T) {
	t.Parallel()
	const pt = "synthetic session blob v1\n"
	golden := readGoldenHex(t, "testdata/TestSeal_GoldenV1/v1.golden")

	nonce := make([]byte, 24)
	for i := range nonce {
		nonce[i] = byte(0x40 + i)
	}

	// The golden file itself is produced by chacha20poly1305 directly, so it
	// pins the format independently of vault.Seal.
	if ind := independentV1(t, 0x01, testInstall, testID, fixedKeyBytes(), nonce, []byte(pt)); !bytes.Equal(ind, golden) {
		t.Fatalf("golden file does not match the ADR 0009 v1 layout\n got: %x\nwant: %x", ind, golden)
	}

	s := mustSealer(t, bytes.NewReader(nonce))
	got, err := s.Seal(t.Context(), testInstall, testID, mustKey(t, fixedKeyBytes()), []byte(pt))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	writeGolden(t, "TestSeal_GoldenV1", "v1.golden", got)
	if !bytes.Equal(got, golden) {
		t.Fatalf("v1 format drifted (bump the version byte instead)\n got: %x\nwant: %x", got, golden)
	}

	plain, err := openBytes(t, testInstall, testID, mustKey(t, fixedKeyBytes()), golden)
	if err != nil {
		t.Fatalf("Open(golden): %v", err)
	}
	if plain.Expose() != pt {
		t.Fatalf("Open(golden) returned the wrong plaintext")
	}
}

func TestOpen_EveryByteFlipFails(t *testing.T) {
	t.Parallel()
	raw := randBytes(t, 32)
	key := mustKey(t, raw)
	file := mustSeal(t, testID, key, []byte("synthetic session"))
	region := func(i int) string {
		switch {
		case i < 8:
			return "magic"
		case i == 8:
			return "version"
		case i < 33:
			return "nonce"
		case i < len(file)-16:
			return "ciphertext"
		default:
			return "tag"
		}
	}
	for i := range file {
		for _, mask := range []byte{0x01, 0x80, 0xff} {
			t.Run(fmt.Sprintf("%s/byte%02d/mask%02x", region(i), i, mask), func(t *testing.T) {
				t.Parallel()
				bad := bytes.Clone(file)
				bad[i] ^= mask
				got, err := openBytes(t, testInstall, testID, key, bad)
				wantInvalid(t, got, err)
			})
		}
	}
	// Control: the untouched file opens.
	if _, err := openBytes(t, testInstall, testID, key, file); err != nil {
		t.Fatalf("Open(unmodified): %v", err)
	}
}

func TestOpen_WrongConnectorIDFails(t *testing.T) {
	t.Parallel()
	key := mustKey(t, randBytes(t, 32))
	file := mustSeal(t, "edf", key, []byte("synthetic session"))
	for _, id := range []string{"ileo", "ed", "edf-x", "edf0", "fakeprovider"} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			got, err := openBytes(t, testInstall, id, key, file)
			wantInvalid(t, got, err)
		})
	}
}

func TestOpen_OtherStateDirFileRejected(t *testing.T) {
	t.Parallel()
	key := mustKey(t, randBytes(t, 32))
	file := mustSeal(t, testID, key, []byte("synthetic session"))
	for _, install := range []string{
		otherInstall,
		"fedcba9876543210fedcba9876543210",
		"00000000000000000000000000000000",
	} {
		t.Run(install, func(t *testing.T) {
			t.Parallel()
			got, err := openBytes(t, install, testID, key, file)
			wantInvalid(t, got, err)
		})
	}
}

func TestOpen_WrongKeyFails(t *testing.T) {
	t.Parallel()
	raw := randBytes(t, 32)
	file := mustSeal(t, testID, mustKey(t, raw), []byte("synthetic session"))
	oneBit := bytes.Clone(raw)
	oneBit[31] ^= 0x01
	tests := []struct {
		name string
		raw  []byte
	}{
		{"random other key", randBytes(t, 32)},
		{"one bit differs", oneBit},
		{"all zero key", make([]byte, 32)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := openBytes(t, testInstall, testID, mustKey(t, tc.raw), file)
			wantInvalid(t, got, err)
		})
	}
}

func TestOpen_TruncatedOrOversizedRefused(t *testing.T) {
	t.Parallel()
	key := mustKey(t, randBytes(t, 32))
	valid := mustSeal(t, testID, key, []byte("synthetic session"))
	maxValid := mustSeal(t, testID, key, bytes.Repeat([]byte{'s'}, vault.MaxPlaintext))

	tests := []struct {
		name string
		file []byte
	}{
		{"empty", nil},
		{"one byte", []byte{'F'}},
		{"magic only", []byte("FACTOSES")},
		{"magic and version", []byte("FACTOSES\x01")},
		{"header only", valid[:33]},
		{"48 bytes", valid[:48]},
		{"valid minus one", valid[:len(valid)-1]},
		{"valid plus one", append(bytes.Clone(valid), 0x00)},
		{"max plus one", append(bytes.Clone(maxValid), 0x00)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := openBytes(t, testInstall, testID, key, tc.file)
			wantInvalid(t, got, err)
		})
	}

	t.Run("endless reader is not fully read", func(t *testing.T) {
		t.Parallel()
		r := &endlessReader{fill: 'A'}
		got, err := vault.Open(t.Context(), testInstall, testID, key, r)
		wantInvalid(t, got, err)
		if r.n > int64(vault.MaxFileSize)+1 {
			t.Fatalf("Open read %d bytes, want at most MaxFileSize+1 = %d", r.n, vault.MaxFileSize+1)
		}
	})

	t.Run("oversized valid prefix is not fully read", func(t *testing.T) {
		t.Parallel()
		r := &countingReader{r: io.MultiReader(bytes.NewReader(maxValid), &endlessReader{fill: 'B'})}
		got, err := vault.Open(t.Context(), testInstall, testID, key, r)
		wantInvalid(t, got, err)
		if r.n > int64(vault.MaxFileSize)+1 {
			t.Fatalf("Open read %d bytes, want at most %d", r.n, vault.MaxFileSize+1)
		}
	})

	t.Run("exactly max size opens", func(t *testing.T) {
		t.Parallel()
		got, err := openBytes(t, testInstall, testID, key, maxValid)
		if err != nil {
			t.Fatalf("Open(max size file): %v", err)
		}
		if len(got.Expose()) != vault.MaxPlaintext {
			t.Fatalf("plaintext size = %d, want %d", len(got.Expose()), vault.MaxPlaintext)
		}
	})
}

func TestOpen_ReadErrorIsNotInvalid(t *testing.T) {
	t.Parallel()
	ioErr := errors.New("synthetic read failure")
	key := mustKey(t, randBytes(t, 32))
	got, err := vault.Open(t.Context(), testInstall, testID, key, errReader{err: ioErr})
	if !errors.Is(err, ioErr) {
		t.Fatalf("Open error = %v, want wrapped read error", err)
	}
	if errors.Is(err, vault.ErrInvalid) {
		t.Fatalf("a read I/O error must not be ErrInvalid (the file would be removed)")
	}
	if !got.IsZero() {
		t.Fatalf("Open returned plaintext alongside an error")
	}
}

func TestOpen_UnknownVersionIsInvalid(t *testing.T) {
	t.Parallel()
	raw := randBytes(t, 32)
	key := mustKey(t, raw)
	nonce := randBytes(t, 24)
	pt := []byte("synthetic session")
	// Control: the independent builder with version 1 opens.
	if _, err := openBytes(t, testInstall, testID, key, independentV1(t, 0x01, testInstall, testID, raw, nonce, pt)); err != nil {
		t.Fatalf("Open(independent v1): %v", err)
	}
	// Files authenticated under another version byte (as a newer facto would
	// write them) are never parsed or accepted.
	for _, v := range []byte{0x00, 0x02, 0x10, 0x7f, 0x80, 0xff} {
		t.Run(fmt.Sprintf("v%#02x", v), func(t *testing.T) {
			t.Parallel()
			file := independentV1(t, v, testInstall, testID, raw, nonce, pt)
			got, err := openBytes(t, testInstall, testID, key, file)
			wantInvalid(t, got, err)
		})
	}
}

func TestSeal_FreshNonce(t *testing.T) {
	t.Parallel()
	key := mustKey(t, randBytes(t, 32))

	t.Run("nonce comes from the injected reader", func(t *testing.T) {
		t.Parallel()
		r := &sequenceReader{}
		s := mustSealer(t, r)
		var nonces [][]byte
		for range 20 {
			file, err := s.Seal(t.Context(), testInstall, testID, key, []byte("synthetic session"))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			nonces = append(nonces, file[9:33])
		}
		if len(r.got) != 20*24 {
			t.Fatalf("Sealer read %d random bytes for 20 seals, want %d (24 per seal)", len(r.got), 20*24)
		}
		for i, n := range nonces {
			if want := r.got[i*24 : (i+1)*24]; !bytes.Equal(n, want) {
				t.Fatalf("seal %d nonce = %x, want the injected bytes %x", i, n, want)
			}
		}
	})

	t.Run("no repeated nonce over many seals", func(t *testing.T) {
		t.Parallel()
		seen := make(map[string]int)
		for i := range 2000 {
			file := mustSeal(t, testID, key, []byte("synthetic session"))
			n := string(file[9:33])
			if j, dup := seen[n]; dup {
				t.Fatalf("seal %d reused the nonce of seal %d", i, j)
			}
			seen[n] = i
		}
	})

	t.Run("same input twice gives different files", func(t *testing.T) {
		t.Parallel()
		a := mustSeal(t, testID, key, []byte("synthetic session"))
		b := mustSeal(t, testID, key, []byte("synthetic session"))
		if bytes.Equal(a, b) {
			t.Fatalf("two seals of the same plaintext are identical")
		}
	})
}

func TestSeal_RandFailureRefuses(t *testing.T) {
	t.Parallel()
	key := mustKey(t, randBytes(t, 32))
	tests := []struct {
		name string
		r    io.Reader
	}{
		{"error", errReader{err: errors.New("synthetic entropy failure")}},
		{"short read then EOF", bytes.NewReader(make([]byte, 23))},
		{"empty", bytes.NewReader(nil)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			file, err := mustSealer(t, tc.r).Seal(t.Context(), testInstall, testID, key, []byte("synthetic session"))
			if err == nil {
				t.Fatalf("Seal succeeded without a full random nonce")
			}
			if file != nil {
				t.Fatalf("Seal returned %d bytes alongside an error", len(file))
			}
		})
	}
}

func TestSealOpen_BadArgumentsRefused(t *testing.T) {
	t.Parallel()
	key := mustKey(t, randBytes(t, 32))
	file := mustSeal(t, testID, key, []byte("synthetic session"))
	tests := []struct {
		name, install, id string
	}{
		{"empty id", testInstall, ""},
		{"uppercase id", testInstall, "EDF"},
		{"traversal id", testInstall, "../edf"},
		{"slash id", testInstall, "edf/x"},
		{"dot id", testInstall, "edf.sess"},
		{"leading dash", testInstall, "-edf"},
		{"trailing dash", testInstall, "edf-"},
		{"double dash", testInstall, "edf--x"},
		{"underscore", testInstall, "edf_x"},
		{"nul byte", testInstall, "edf\x00"},
		{"non ascii", testInstall, "édf"},
		{"41 bytes", testInstall, strings.Repeat("a", 41)},
		{"empty install", "", testID},
		{"short install", testInstall[:31], testID},
		{"long install", testInstall + "0", testID},
		{"uppercase install", strings.ToUpper(testInstall), testID},
		{"non hex install", "g123456789abcdef0123456789abcdef", testID},
		{"install with newline", testInstall[:31] + "\n", testID},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := vault.Seal(t.Context(), tc.install, tc.id, key, []byte("synthetic session"))
			if !errors.Is(err, vault.ErrInvalidArgument) {
				t.Fatalf("Seal error = %v, want ErrInvalidArgument", err)
			}
			if out != nil {
				t.Fatalf("Seal returned bytes alongside an error")
			}
			r := &countingReader{r: bytes.NewReader(file)}
			got, err := vault.Open(t.Context(), tc.install, tc.id, key, r)
			if !errors.Is(err, vault.ErrInvalidArgument) {
				t.Fatalf("Open error = %v, want ErrInvalidArgument", err)
			}
			if !got.IsZero() {
				t.Fatalf("Open returned plaintext alongside an error")
			}
			if r.n != 0 {
				t.Fatalf("Open read %d file bytes before validating its arguments", r.n)
			}
		})
	}
}

func TestSealOpen_UnusableKeyRefused(t *testing.T) {
	t.Parallel()
	good := mustKey(t, randBytes(t, 32))
	file := mustSeal(t, testID, good, []byte("synthetic session"))
	wiped := mustKey(t, randBytes(t, 32))
	wiped.Wipe()
	tests := []struct {
		name string
		key  vault.Key
	}{
		{"zero value", vault.Key{}},
		{"wiped", wiped},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := vault.Seal(t.Context(), testInstall, testID, tc.key, []byte("synthetic session"))
			if !errors.Is(err, vault.ErrMalformedKey) {
				t.Fatalf("Seal error = %v, want ErrMalformedKey", err)
			}
			if out != nil {
				t.Fatalf("Seal returned bytes alongside an error")
			}
			got, err := openBytes(t, testInstall, testID, tc.key, file)
			if !errors.Is(err, vault.ErrMalformedKey) {
				t.Fatalf("Open error = %v, want ErrMalformedKey", err)
			}
			if !got.IsZero() {
				t.Fatalf("Open returned plaintext alongside an error")
			}
		})
	}
}

func TestSealOpen_HonourCanceledContext(t *testing.T) {
	t.Parallel()
	key := mustKey(t, randBytes(t, 32))
	file := mustSeal(t, testID, key, []byte("synthetic session"))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	out, err := vault.Seal(ctx, testInstall, testID, key, []byte("synthetic session"))
	if !errors.Is(err, context.Canceled) || out != nil {
		t.Fatalf("Seal(canceled) = %d bytes, %v; want nil, context.Canceled", len(out), err)
	}
	r := &countingReader{r: bytes.NewReader(file)}
	got, err := vault.Open(ctx, testInstall, testID, key, r)
	if !errors.Is(err, context.Canceled) || !got.IsZero() {
		t.Fatalf("Open(canceled) error = %v; want context.Canceled and no plaintext", err)
	}
	if r.n != 0 {
		t.Fatalf("Open(canceled) read %d bytes", r.n)
	}
}

func TestOpen_NoPartialOutputOnFailure(t *testing.T) {
	t.Parallel()
	raw := randBytes(t, 32)
	key := mustKey(t, raw)
	pt := bytes.Repeat([]byte("synthetic-plaintext-"), 64)
	file := mustSeal(t, testID, key, pt)
	tagFlip := bytes.Clone(file)
	tagFlip[len(tagFlip)-1] ^= 0x01
	ctFlip := bytes.Clone(file)
	ctFlip[40] ^= 0x01
	tests := []struct {
		name    string
		install string
		id      string
		key     vault.Key
		file    []byte
	}{
		{"tag flipped", testInstall, testID, key, tagFlip},
		{"ciphertext flipped", testInstall, testID, key, ctFlip},
		{"wrong key", testInstall, testID, mustKey(t, randBytes(t, 32)), file},
		{"wrong id", testInstall, "edf", key, file},
		{"wrong install", otherInstall, testID, key, file},
		{"truncated", testInstall, testID, key, file[:len(file)-1]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := openBytes(t, tc.install, tc.id, tc.key, tc.file)
			wantInvalid(t, got, err)
			if got.Expose() != "" {
				t.Fatalf("Open exposed %d bytes on failure", len(got.Expose()))
			}
		})
	}
}

func readGoldenHex(t *testing.T, path string) []byte {
	t.Helper()
	data, err := readTestdata(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	b, err := decodeHexLines(data)
	if err != nil {
		t.Fatalf("decode golden %s: %v", path, err)
	}
	return b
}
