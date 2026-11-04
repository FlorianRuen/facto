package vault

import (
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/FlorianRuen/facto/internal/secret"
)

// keyBox is the shared storage behind a Key and its copies.
type keyBox struct {
	mu    sync.RWMutex
	b     [KeySize]byte
	valid bool
}

// Key is a decoded 32-byte session key (ADR 0009, "Key encoding").
//
// It is a dedicated type rather than a secret.Secret so that Seal and Open
// cannot be handed an undecoded or wrong-length value, and so that the
// decoded buffer has an owner that can wipe it. Copies share the same
// storage: Wipe on any copy wipes every copy. Every rendering (fmt verbs,
// JSON, text, slog) produces secret.Masked. The zero value is not a usable
// key: Seal and Open refuse it with ErrMalformedKey. Safe for concurrent use.
type Key struct {
	p *keyBox
}

// ParseKey decodes a keyring value: exactly EncodedKeyLen characters of
// unpadded base64url (base64.RawURLEncoding.Strict()) giving exactly KeySize
// bytes. Anything else returns ErrMalformedKey and an unusable Key; the error
// never carries the input.
func ParseKey(encoded secret.Secret) (Key, error) {
	// Expose makes an immutable string copy of the encoded key that cannot be
	// wiped: accepted as best effort (ADR 0009, "Wiping is best effort").
	src := []byte(encoded.Expose())
	defer clear(src)
	if len(src) != EncodedKeyLen {
		return Key{}, ErrMalformedKey
	}
	// The newline-ignoring base64 decoder could still decode fewer bytes from
	// 43 characters, hence the exact length check on n.
	box := &keyBox{}
	n, err := base64.RawURLEncoding.Strict().Decode(box.b[:], src)
	if err != nil || n != KeySize {
		clear(box.b[:])
		return Key{}, ErrMalformedKey
	}
	box.valid = true
	return Key{p: box}, nil
}

// Wipe zeroes the key bytes for every copy of k; Seal and Open then refuse
// it with ErrMalformedKey. Idempotent and safe on the zero value.
func (k Key) Wipe() {
	if k.p == nil {
		return
	}
	k.p.mu.Lock()
	defer k.p.mu.Unlock()
	clear(k.p.b[:])
	k.p.valid = false
}

// aead builds the XChaCha20-Poly1305 instance for k. chacha20poly1305.NewX
// keeps its own copy of the key, which facto cannot wipe (best effort, ADR
// 0009); it becomes unreachable once the AEAD goes out of scope.
func (k Key) aead() (cipher.AEAD, error) {
	if k.p == nil {
		return nil, ErrMalformedKey
	}
	k.p.mu.RLock()
	defer k.p.mu.RUnlock()
	if !k.p.valid {
		return nil, ErrMalformedKey
	}
	a, err := chacha20poly1305.NewX(k.p.b[:])
	if err != nil {
		return nil, fmt.Errorf("vault: new aead: %w", err)
	}
	return a, nil
}

// String returns secret.Masked.
func (Key) String() string { return secret.Masked }

// GoString returns secret.Masked, so %#v never shows the key.
func (Key) GoString() string { return secret.Masked }

// Format writes secret.Masked whatever the verb, width or flags.
func (Key) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(secret.Masked))
}

// MarshalJSON returns the JSON string "***".
func (Key) MarshalJSON() ([]byte, error) {
	return []byte(`"` + secret.Masked + `"`), nil
}

// MarshalText returns secret.Masked.
func (Key) MarshalText() ([]byte, error) {
	return []byte(secret.Masked), nil
}

// LogValue implements slog.LogValuer and returns secret.Masked.
func (Key) LogValue() slog.Value {
	return slog.StringValue(secret.Masked)
}
