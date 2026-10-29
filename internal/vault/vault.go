// Package vault seals and opens persisted supplier sessions with
// XChaCha20-Poly1305 (docs/adr/0009-vault-aead.md).
//
// A version 1 file is magic ‖ version ‖ nonce ‖ ciphertext‖tag. The
// additional data binds the file to its state directory and connector:
// AAD = magic ‖ version ‖ install id ‖ connector id. Every format or
// authentication failure of a file is the single opaque ErrInvalid. The
// plaintext encoding is owned by the session store and is opaque here.
package vault

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/FlorianRuen/facto/internal/secret"
)

// Format constants (ADR 0009, "File format (version 1)").
const (
	// Magic opens every session file.
	Magic = "FACTOSES"
	// Version1 is the only format version this binary reads and writes.
	Version1 byte = 0x01
	// NonceSize is the XChaCha20-Poly1305 nonce size.
	NonceSize = 24
	// HeaderSize is magic + version + nonce.
	HeaderSize = len(Magic) + 1 + NonceSize
	// Overhead is the Poly1305 tag size.
	Overhead = 16
	// MinFileSize is the size of a file sealing an empty plaintext (which
	// Seal refuses).
	MinFileSize = HeaderSize + Overhead
	// MaxFileSize caps a session file (1 MiB).
	MaxFileSize = 1 << 20
	// MaxPlaintext is the largest plaintext Seal accepts.
	MaxPlaintext = MaxFileSize - HeaderSize - Overhead
	// KeySize is the decoded key size.
	KeySize = 32
	// EncodedKeyLen is the length of a key in unpadded base64url.
	EncodedKeyLen = 43

	installIDLen   = 32
	maxConnectorID = 40
)

// Sentinel errors.
var (
	// ErrInvalid is any format or authentication failure of a file. It is
	// opaque: it never says which check failed nor carries file bytes.
	ErrInvalid = errors.New("vault: invalid session file")
	// ErrMalformedKey is a key that is not 43 chars of strict base64url
	// giving 32 bytes, or a zero or wiped Key.
	ErrMalformedKey = errors.New("vault: malformed session key")
	// ErrInvalidArgument is a bad install id (not 32 lowercase hex chars) or
	// connector id (not ^[a-z0-9]+(-[a-z0-9]+)*$, 1 to 40 bytes).
	ErrInvalidArgument = errors.New("vault: invalid argument")
	// ErrPlaintextSize is an empty plaintext or one over MaxPlaintext bytes.
	ErrPlaintextSize = errors.New("vault: plaintext size out of range")
)

// Sealer seals with nonces read from an injected random source. It is safe
// for concurrent use when its random source is.
type Sealer struct {
	rand io.Reader
}

// NewSealer returns a Sealer reading nonces from r. Production passes
// crypto/rand.Reader.
func NewSealer(r io.Reader) *Sealer {
	return &Sealer{rand: r}
}

// Seal is NewSealer(crypto/rand.Reader).Seal.
func Seal(ctx context.Context, installID, id string, key Key, plaintext []byte) ([]byte, error) {
	return NewSealer(rand.Reader).Seal(ctx, installID, id, key, plaintext)
}

// Seal encrypts plaintext under key with a fresh nonce and returns the
// complete version 1 file. It wipes plaintext after a successful seal. On
// error it returns nil and leaves plaintext untouched.
func (s *Sealer) Seal(ctx context.Context, installID, id string, key Key, plaintext []byte) ([]byte, error) {
	if err := checkArgs(installID, id); err != nil {
		return nil, err
	}
	aead, err := key.aead()
	if err != nil {
		return nil, err
	}
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintext {
		return nil, ErrPlaintextSize
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("vault: seal: %w", err)
	}

	out := make([]byte, HeaderSize, HeaderSize+len(plaintext)+Overhead)
	copy(out, Magic)
	out[len(Magic)] = Version1
	nonce := out[len(Magic)+1 : HeaderSize]
	if _, err := io.ReadFull(s.rand, nonce); err != nil {
		return nil, fmt.Errorf("vault: read nonce: %w", err)
	}
	out = aead.Seal(out, nonce, plaintext, additionalData(installID, id))
	clear(plaintext)
	return out, nil
}

// Open reads file through io.LimitReader(file, MaxFileSize+1), checks its
// size, magic and version, then authenticates and decrypts it in place. Any
// format or authentication failure is ErrInvalid; a read error is wrapped
// and is not ErrInvalid. On any error the returned Secret is zero. The
// caller wipes the returned Secret after use.
func Open(ctx context.Context, installID, id string, key Key, file io.Reader) (secret.Secret, error) {
	if err := checkArgs(installID, id); err != nil {
		return secret.Secret{}, err
	}
	aead, err := key.aead()
	if err != nil {
		return secret.Secret{}, err
	}
	if err := ctx.Err(); err != nil {
		return secret.Secret{}, fmt.Errorf("vault: open: %w", err)
	}

	data, err := io.ReadAll(io.LimitReader(file, MaxFileSize+1))
	if err != nil {
		return secret.Secret{}, fmt.Errorf("vault: read session file: %w", err)
	}
	if len(data) < MinFileSize || len(data) > MaxFileSize ||
		string(data[:len(Magic)]) != Magic ||
		data[len(Magic)] != Version1 {
		return secret.Secret{}, ErrInvalid
	}
	nonce := data[len(Magic)+1 : HeaderSize]
	ct := data[HeaderSize:]
	pt, err := aead.Open(ct[:0], nonce, ct, additionalData(installID, id))
	if err != nil {
		// Never return partial output: clear whatever was written in place.
		clear(ct)
		return secret.Secret{}, ErrInvalid
	}
	return secret.New(pt), nil
}

// additionalData returns magic ‖ version ‖ install id ‖ connector id. The
// first three fields are fixed-length, so the encoding is unambiguous.
func additionalData(installID, id string) []byte {
	aad := make([]byte, 0, len(Magic)+1+len(installID)+len(id))
	aad = append(aad, Magic...)
	aad = append(aad, Version1)
	aad = append(aad, installID...)
	return append(aad, id...)
}

func checkArgs(installID, id string) error {
	if !validInstallID(installID) || !validConnectorID(id) {
		return ErrInvalidArgument
	}
	return nil
}

// validInstallID reports whether s is exactly 32 lowercase hex chars.
func validInstallID(s string) bool {
	if len(s) != installIDLen {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validConnectorID reports whether s matches the registry rule
// ^[a-z0-9]+(-[a-z0-9]+)*$ and is at most 40 bytes.
func validConnectorID(s string) bool {
	if s == "" || len(s) > maxConnectorID {
		return false
	}
	prevDash := true // refuses a leading dash
	for i := range len(s) {
		c := s[i]
		switch {
		case c == '-':
			if prevDash {
				return false
			}
			prevDash = true
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			prevDash = false
		default:
			return false
		}
	}
	return !prevDash
}
