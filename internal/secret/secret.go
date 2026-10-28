// Package secret holds sensitive values and resolves the references that
// point to them (docs/spec.md, "Security and credentials").
//
// A Secret never renders its value: every fmt verb, JSON, text, XML and slog
// rendering produces Masked. The value is only reachable through Expose, which
// must be called at the last call site and never stored. Configuration holds
// references (bw://<uuid>/<field>, keyring://<service>/<key>), parsed by
// ParseRef and dispatched by a Resolver to the Provider of their scheme.
//
// The package imports only the standard library: it stays masked through the
// redacting logx handler because it implements slog.LogValuer.
package secret

import (
	"fmt"
	"log/slog"
	"sync"
)

// Masked is what every rendering of a Secret produces.
const Masked = "***"

// box is the shared storage behind a Secret and its copies.
type box struct {
	mu sync.RWMutex
	b  []byte
}

// Secret holds a sensitive value. The zero value is an empty secret.
//
// Copies share the same storage, so Wipe on any copy clears every copy.
// String, GoString, Format (every verb and flag), MarshalJSON, MarshalText
// and LogValue all produce Masked. When a Secret sits in an unexported struct
// field, fmt prints the internal pointer, never the bytes. Safe for
// concurrent use.
type Secret struct {
	p *box
}

// New wraps b without copying: the Secret takes ownership of b and Wipe
// zeroes its backing array. Callers must not keep or reuse b.
func New(b []byte) Secret {
	return Secret{p: &box{b: b}}
}

// FromString copies s into a new Secret. The string itself cannot be wiped;
// prefer New on a []byte the caller owns.
func FromString(s string) Secret {
	return New([]byte(s))
}

// Expose returns the value, or "" for an empty or wiped secret. Call it only
// at the last call site (input.Type(sec.Expose())) and never store the result.
func (s Secret) Expose() string {
	if s.p == nil {
		return ""
	}
	s.p.mu.RLock()
	defer s.p.mu.RUnlock()
	return string(s.p.b)
}

// IsZero reports whether the secret is empty: zero value, empty input, or
// wiped.
func (s Secret) IsZero() bool {
	if s.p == nil {
		return true
	}
	s.p.mu.RLock()
	defer s.p.mu.RUnlock()
	return len(s.p.b) == 0
}

// Wipe zeroes the bytes (best effort: strings returned by Expose are not
// reachable) and empties the secret for every copy. Idempotent and safe on
// the zero value.
func (s Secret) Wipe() {
	if s.p == nil {
		return
	}
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	clear(s.p.b)
	s.p.b = nil
}

// String returns Masked.
func (s Secret) String() string { return Masked }

// GoString returns Masked, so %#v never shows the value.
func (s Secret) GoString() string { return Masked }

// Format writes Masked whatever the verb, width or flags.
func (s Secret) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(Masked))
}

// MarshalJSON returns the JSON string "***".
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + Masked + `"`), nil
}

// MarshalText returns Masked. encoding/xml and other text encoders use it.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(Masked), nil
}

// LogValue implements slog.LogValuer and returns Masked.
func (s Secret) LogValue() slog.Value {
	return slog.StringValue(Masked)
}
