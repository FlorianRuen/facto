// Tests for package secret core (J0 task T10): the Secret value type, secret
// references and the scheme-dispatching Resolver. Spec: docs/spec.md
// "Security and credentials" (Password managers; Data in memory and in
// output). Providers (keyring T18, Bitwarden T19) and config (T13) build on
// this API. Resolver tests live in resolver_test.go, ParseRef in ref_test.go.
//
// Import rule: secret imports only the standard library (log/slog for
// LogValuer). It must NOT import internal/logx: logx honours slog.LogValuer,
// which is how a Secret stays masked through the redacting handler, so logx
// needs no knowledge of secret either. These tests use the stdlib slog
// handlers only.
//
// Expected API (implementer: follow exactly):
//
//	// Masked is what every rendering of a Secret produces.
//	const Masked = "***"
//
//	// Secret holds a sensitive value. The zero value is an empty secret.
//	// Copies share the same storage (the struct holds a pointer), so Wipe on
//	// any copy clears every copy. Rendering never shows the value:
//	// String, GoString, Format (every verb and flag), MarshalJSON,
//	// MarshalText and LogValue all produce Masked (MarshalJSON: `"***"`).
//	// Printing a struct that holds a Secret in an unexported field must not
//	// show the value either (fmt then prints the internal pointer, never
//	// the bytes). Safe for concurrent use.
//	type Secret struct{ /* unexported pointer */ }
//
//	// New wraps b WITHOUT copying: the Secret takes ownership and Wipe
//	// zeroes b's backing array. Callers must not keep or reuse b.
//	func New(b []byte) Secret
//	// FromString copies s into a new Secret (the string itself cannot be
//	// wiped; prefer New on a []byte the caller owns).
//	func FromString(s string) Secret
//	// Expose returns the value. Call it only at the last call site
//	// (input.Type(sec.Expose())) and never store the result. "" after Wipe.
//	func (s Secret) Expose() string
//	// IsZero reports whether the secret is empty (zero value, empty input,
//	// or wiped).
//	func (s Secret) IsZero() bool
//	// Wipe zeroes the bytes (best effort) and empties the secret for every
//	// copy. Idempotent; safe on the zero value.
//	func (s Secret) Wipe()
//	func (s Secret) String() string
//	func (s Secret) GoString() string
//	func (s Secret) Format(f fmt.State, verb rune)
//	func (s Secret) MarshalJSON() ([]byte, error)
//	func (s Secret) MarshalText() ([]byte, error)
//	func (s Secret) LogValue() slog.Value // slog.StringValue(Masked)
//
//	// Ref is a parsed, canonical secret reference. Refs are not secret.
//	type Ref struct {
//	    Scheme string // "bw" or "keyring"
//	    Item   string // bw: item UUID, lowercase canonical form; keyring: service
//	    Field  string // bw: "username" | "password" | "totp"; keyring: key (may contain "/")
//	}
//	// String returns the canonical form: "bw://<uuid>/<field>",
//	// "keyring://<service>/<key>". ParseRef(r.String()) == r.
//	func (r Ref) String() string
//
//	// ParseRef parses a reference. Accepted forms, nothing else:
//	//   bw://<uuid>/<username|password|totp>
//	//       uuid: 8-4-4-4-12 hex digits, any case, normalized to lowercase.
//	//       Items are resolved by UUID only: a name is refused.
//	//   keyring://<service>/<key>
//	//       service: one segment; key: one or more segments separated by "/"
//	//       (docs/spec.md: keyring://facto/ileo/login → service "facto",
//	//       key "ileo/login"). Segments match [A-Za-z0-9._-]+ and are neither
//	//       "." nor "..".
//	// Scheme is lowercase; no surrounding whitespace, userinfo, port, query,
//	// fragment, percent-encoding, empty segment or trailing "/".
//	// Every failure wraps ErrInvalidRef and its message never contains the
//	// input (a plaintext password pasted in the config must not be echoed).
//	func ParseRef(s string) (Ref, error)
//
//	// Provider resolves references of one scheme ("bw", "keyring"…).
//	// (docs/spec.md calls it SecretProvider / SecretRef.)
//	type Provider interface {
//	    Scheme() string
//	    Resolve(ctx context.Context, ref Ref) (Secret, error)
//	    Close() error // locks, wipes session keys
//	}
//
//	// Resolver dispatches references to the provider registered for their
//	// scheme. Safe for concurrent use. Its Resolve method is the one
//	// connector.SecretResolver will require: Resolve(ctx, ref string) (Secret, error).
//	type Resolver struct{ /* unexported */ }
//
//	// NewResolver registers providers by Scheme(). A nil provider or a scheme
//	// not matching ^[a-z][a-z0-9]*$ wraps ErrInvalidProvider; two providers
//	// with the same scheme wrap ErrDuplicateScheme.
//	func NewResolver(providers ...Provider) (*Resolver, error)
//	// Resolve parses ref (ParseRef rules, ErrInvalidRef) then calls ResolveRef.
//	func (r *Resolver) Resolve(ctx context.Context, ref string) (Secret, error)
//	// ResolveRef calls the provider for ref.Scheme. Errors:
//	//   - ctx already done: wraps ctx.Err(); the provider is not called.
//	//   - after CloseAll: wraps ErrClosed; the provider is not called.
//	//   - no provider for the scheme: wraps ErrNoProvider.
//	//   - provider error: wrapped with %w (errors.Is keeps working, e.g.
//	//     ErrSecretNotFound). If the provider returned a non-empty Secret
//	//     together with an error, that Secret is wiped and the zero Secret
//	//     is returned.
//	func (r *Resolver) ResolveRef(ctx context.Context, ref Ref) (Secret, error)
//	// CloseAll closes every provider exactly once, even when some fail, and
//	// returns their errors joined (errors.Join, errors.Is works on each).
//	// Later calls return nil and close nothing.
//	func (r *Resolver) CloseAll() error
//
//	var (
//	    ErrInvalidRef      = errors.New("secret: invalid reference")
//	    ErrNoProvider      = errors.New("secret: no provider for scheme")
//	    ErrDuplicateScheme = errors.New("secret: duplicate provider scheme")
//	    ErrInvalidProvider = errors.New("secret: invalid provider")
//	    ErrClosed          = errors.New("secret: resolver closed")
//	    ErrSecretNotFound  = errors.New("secret: secret not found") // returned by providers (T18, T19)
//	)
package secret_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// renderings returns every way a Secret could reach a log, a report or an
// error, labelled for failure messages.
func renderings(t *testing.T, s secret.Secret) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, verb := range []string{"%v", "%s", "%+v", "%#v", "%q", "%x", "%X", "%d", "%10s", "%-8v", "%T"} {
		out["fmt "+verb] = fmt.Sprintf(verb, s)
		out["fmt ptr "+verb] = fmt.Sprintf(verb, &s)
	}
	out["Sprint"] = fmt.Sprint(s)
	out["Sprintln"] = fmt.Sprintln("value", s)
	out["String"] = s.String()
	out["GoString"] = s.GoString()

	type exported struct {
		User   string
		Secret secret.Secret
		Ptr    *secret.Secret
	}
	type unexported struct {
		user string
		pw   secret.Secret
	}
	ex := exported{User: "user-1", Secret: s, Ptr: &s}
	un := unexported{user: "user-1", pw: s}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		out["struct exported "+verb] = fmt.Sprintf(verb, ex)
		out["struct unexported "+verb] = fmt.Sprintf(verb, un)
		out["slice "+verb] = fmt.Sprintf(verb, []secret.Secret{s, s})
		out["map "+verb] = fmt.Sprintf(verb, map[string]secret.Secret{"pw": s})
	}

	out["json"] = mustJSON(t, s)
	out["json struct"] = mustJSON(t, ex)
	out["json map"] = mustJSON(t, map[string]any{"pw": s, "nested": map[string]any{"pw": &s}})

	txt, err := s.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	out["MarshalText"] = string(txt)
	x, err := xml.Marshal(struct {
		XMLName xml.Name      `xml:"cfg"`
		Attr    secret.Secret `xml:"pw,attr"`
		Elem    secret.Secret `xml:"elem"`
	}{Attr: s, Elem: s})
	if err != nil {
		t.Fatalf("xml.Marshal: %v", err)
	}
	out["xml"] = string(x)

	out["LogValue"] = s.LogValue().String()
	handlers := map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	}
	for name, h := range handlers {
		var buf bytes.Buffer
		l := slog.New(h(&buf))
		l.Info("login", "password", s, slog.Any("any", s), slog.Group("g", "inner", s), "ptr", &s)
		l.With("with", s).WithGroup("grp").Info("again", "s", s)
		out["slog "+name] = buf.String()
	}

	inner := errors.New("supplier rejected credentials")
	out["error %v"] = fmt.Errorf("login with %v: %w", s, inner).Error()
	out["error %s"] = fmt.Errorf("login with %s: %w", s, inner).Error()
	out["error %q"] = fmt.Errorf("login with %q: %w", s, inner).Error()
	out["error wrapped twice"] = fmt.Errorf("run: %w", fmt.Errorf("login %+v: %w", s, inner)).Error()
	return out
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(b)
}

func TestSecret_NeverFormatsValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
	}{
		{name: "ascii", value: "s3cr3t-Value-for-test"},
		{name: "short", value: "zq"},
		{name: "mask lookalike", value: "***-not-the-mask-***"},
		{name: "unicode", value: "mot-de-passe-éàü-Ω"},
		{name: "quotes and newline", value: "a\"b\nc'd"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := secret.FromString(tc.value)
			if got := s.Expose(); got != tc.value {
				t.Fatalf("Expose() = %q, want %q", got, tc.value)
			}
			forbidden := []string{
				tc.value,
				fmt.Sprintf("%q", tc.value),
				hex.EncodeToString([]byte(tc.value)),
				strings.ToUpper(hex.EncodeToString([]byte(tc.value))),
				fmt.Sprintf("%d", []byte(tc.value)), // "[115 51 …]": the bytes printed as numbers
			}
			for label, got := range renderings(t, s) {
				for _, f := range forbidden {
					if strings.Contains(got, f) {
						t.Errorf("%s leaks the value (%q) in %q", label, f, got)
					}
				}
			}
		})
	}
}

func TestSecret_RendersMask(t *testing.T) {
	t.Parallel()
	s := secret.FromString("value-that-must-stay-hidden")
	txt, txtErr := s.MarshalText()
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "Masked constant", got: secret.Masked, want: "***"},
		{name: "String", got: s.String(), want: "***"},
		{name: "GoString", got: s.GoString(), want: "***"},
		{name: "%v", got: fmt.Sprintf("%v", s), want: "***"},
		{name: "%s", got: fmt.Sprintf("%s", s), want: "***"},
		{name: "%+v", got: fmt.Sprintf("%+v", s), want: "***"},
		{name: "%#v", got: fmt.Sprintf("%#v", s), want: "***"},
		{name: "LogValue", got: s.LogValue().String(), want: "***"},
		{name: "MarshalText", got: string(txt), want: "***"},
		{name: "json", got: mustJSON(t, s), want: `"***"`},
		{name: "json struct", got: mustJSON(t, struct{ P secret.Secret }{s}), want: `{"P":"***"}`},
		{name: "zero value", got: fmt.Sprint(secret.Secret{}), want: "***"},
		{name: "zero value json", got: mustJSON(t, secret.Secret{}), want: `"***"`},
	}
	if txtErr != nil {
		t.Fatalf("MarshalText: %v", txtErr)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.got != tc.want {
				t.Errorf("got %q, want %q", tc.got, tc.want)
			}
		})
	}
	if k := s.LogValue().Kind(); k != slog.KindString {
		t.Errorf("LogValue().Kind() = %v, want String", k)
	}
}

func TestSecret_ExposeAndIsZero(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		secret   secret.Secret
		want     string
		wantZero bool
	}{
		{name: "zero value", secret: secret.Secret{}, want: "", wantZero: true},
		{name: "empty string", secret: secret.FromString(""), want: "", wantZero: true},
		{name: "empty bytes", secret: secret.New([]byte{}), want: "", wantZero: true},
		{name: "nil bytes", secret: secret.New(nil), want: "", wantZero: true},
		{name: "from string", secret: secret.FromString("abc"), want: "abc"},
		{name: "from bytes", secret: secret.New([]byte("def")), want: "def"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.secret.Expose(); got != tc.want {
				t.Errorf("Expose() = %q, want %q", got, tc.want)
			}
			if got := tc.secret.IsZero(); got != tc.wantZero {
				t.Errorf("IsZero() = %v, want %v", got, tc.wantZero)
			}
		})
	}
}

func TestSecret_FromStringCopies(t *testing.T) {
	t.Parallel()
	b := []byte("original-value")
	s := secret.FromString(string(b))
	b[0] = 'X'
	if got := s.Expose(); got != "original-value" {
		t.Errorf("Expose() = %q after mutating the source, want %q", got, "original-value")
	}
}

func TestSecret_WipeZeroes(t *testing.T) {
	t.Parallel()
	b := []byte("wipe-me-please-0123456789")
	n := len(b)
	s := secret.New(b)
	cp := s // copies share storage
	type holder struct{ s secret.Secret }
	h := holder{s: s}

	s.Wipe()

	if !bytes.Equal(b[:n], make([]byte, n)) {
		t.Errorf("backing array after Wipe = %q, want %d zero bytes", b[:n], n)
	}
	for label, v := range map[string]secret.Secret{"original": s, "copy": cp, "field": h.s} {
		if got := v.Expose(); got != "" {
			t.Errorf("%s: Expose() after Wipe = %q, want \"\"", label, got)
		}
		if !v.IsZero() {
			t.Errorf("%s: IsZero() after Wipe = false, want true", label)
		}
		if got := v.String(); got != "***" {
			t.Errorf("%s: String() after Wipe = %q, want \"***\"", label, got)
		}
	}

	// Idempotent, and safe on a copy and on the zero value.
	s.Wipe()
	cp.Wipe()
	secret.Secret{}.Wipe()
}

func TestSecret_ConcurrentExposeAndWipe(t *testing.T) {
	t.Parallel()
	// Run with -race: Wipe and Expose on copies must not race.
	s := secret.FromString("concurrent-value")
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			c := s
			for range 100 {
				if v := c.Expose(); v != "" && v != "concurrent-value" {
					t.Errorf("Expose() = %q during Wipe, want the value or \"\"", v)
				}
				_ = c.IsZero()
			}
		})
	}
	s.Wipe()
	wg.Wait()
	if got := s.Expose(); got != "" {
		t.Errorf("Expose() after Wipe = %q, want \"\"", got)
	}
}

// TestSecret_CanaryNeverWritten renders a canary Secret every possible way,
// plus ParseRef errors on canary input, and writes the result under
// ArtifactDir: make leakcheck greps it.
func TestSecret_CanaryNeverWritten(t *testing.T) {
	t.Parallel()
	canary := testsecrets.Canary(t, testsecrets.Password)
	s := secret.FromString(canary)

	var report strings.Builder
	for label, got := range renderings(t, s) {
		fmt.Fprintf(&report, "%s\t%s\n", label, got)
	}
	for _, in := range []string{
		canary,
		"bw://" + canary + "/password",
		"bw://3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90/" + canary,
		"keyring://facto/" + canary + "?x",
		"keyring://" + canary + ":443/key",
	} {
		_, err := secret.ParseRef(in)
		if err == nil {
			t.Fatalf("ParseRef(canary input) = nil error, want ErrInvalidRef")
		}
		fmt.Fprintf(&report, "ParseRef error\t%v\n", err)
	}

	writeArtifact(t, "secret-renderings.txt", report.String())
	// Name the offending renderings without printing the canary itself.
	for line := range strings.Lines(report.String()) {
		if strings.Contains(line, canary) {
			label, _, _ := strings.Cut(line, "\t")
			t.Errorf("canary leaked through %s", label)
		}
	}
}

func writeArtifact(t *testing.T, name, content string) {
	t.Helper()
	r, err := fsx.Open(testsecrets.ArtifactDir(t))
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(t.Context(), name, []byte(content)); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
}
