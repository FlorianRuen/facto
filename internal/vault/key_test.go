package vault_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
	"github.com/FlorianRuen/facto/internal/vault"
)

const urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func TestKey_ValidParses(t *testing.T) {
	t.Parallel()
	enc := base64.RawURLEncoding.EncodeToString(fixedKeyBytes())
	if len(enc) != vault.EncodedKeyLen {
		t.Fatalf("precondition: encoded length %d", len(enc))
	}
	if _, err := vault.ParseKey(secret.FromString(enc)); err != nil {
		t.Fatalf("ParseKey(valid): %v", err)
	}
}

func TestKey_MalformedIsRejected(t *testing.T) {
	t.Parallel()
	raw := fixedKeyBytes()
	valid := base64.RawURLEncoding.EncodeToString(raw)

	// Std alphabet: 0xfb 0xff bytes encode to '+' and '/' in std, '-' and '_' in url.
	stdRaw := bytes.Repeat([]byte{0xfb, 0xff}, 16)
	std := base64.RawStdEncoding.EncodeToString(stdRaw)
	if !strings.ContainsAny(std, "+/") {
		t.Fatalf("precondition: std encoding %q has no + or /", std)
	}

	// Non-zero trailing bits: the last of 43 chars carries 4 data bits and 2
	// padding bits that must be zero; set one of them.
	last := strings.IndexByte(urlAlphabet, valid[42])
	if last&0x3 != 0 {
		t.Fatalf("precondition: valid encoding has non-zero trailing bits")
	}
	trailing := valid[:42] + string(urlAlphabet[last|0x1])

	tests := []struct {
		name string
		enc  secret.Secret
	}{
		{"zero secret", secret.Secret{}},
		{"empty", secret.FromString("")},
		{"padding", secret.FromString(base64.URLEncoding.EncodeToString(raw))},
		{"std alphabet", secret.FromString(std)},
		{"42 chars", secret.FromString(valid[:42])},
		{"44 chars", secret.FromString(valid + "A")},
		{"non-zero trailing bits", secret.FromString(trailing)},
		{"16-byte key", secret.FromString(base64.RawURLEncoding.EncodeToString(raw[:16]))},
		{"31-byte key", secret.FromString(base64.RawURLEncoding.EncodeToString(raw[:31]))},
		{"33-byte key", secret.FromString(base64.RawURLEncoding.EncodeToString(append(bytes.Clone(raw), 0)))},
		{"64-byte key", secret.FromString(base64.RawURLEncoding.EncodeToString(append(bytes.Clone(raw), raw...)))},
		{"trailing newline", secret.FromString(valid + "\n")},
		{"leading space", secret.FromString(" " + valid)},
		{"inner newline", secret.FromString(valid[:20] + "\n" + valid[20:42])},
		{"hex encoded", secret.FromString(hex.EncodeToString(raw))},
		{"raw bytes", secret.New(bytes.Clone(raw))},
		{"invalid char", secret.FromString(valid[:42] + "*")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			k, err := vault.ParseKey(tc.enc)
			if !errors.Is(err, vault.ErrMalformedKey) {
				t.Fatalf("ParseKey error = %v, want ErrMalformedKey", err)
			}
			// The returned key must be unusable.
			if _, serr := vault.Seal(t.Context(), testInstall, testID, k, []byte("synthetic")); !errors.Is(serr, vault.ErrMalformedKey) {
				t.Fatalf("Seal with the key returned by a failed ParseKey: %v, want ErrMalformedKey", serr)
			}
		})
	}
}

func TestKey_NeverRendered(t *testing.T) {
	t.Parallel()
	art := testsecrets.ArtifactDir(t)

	t.Run("decoded key", func(t *testing.T) {
		t.Parallel()
		raw := randBytes(t, 32)
		enc := base64.RawURLEncoding.EncodeToString(raw)
		key := mustKey(t, raw)
		forbidden := []string{
			enc,
			base64.RawStdEncoding.EncodeToString(raw),
			hex.EncodeToString(raw),
			strings.ToUpper(hex.EncodeToString(raw)),
			string(raw),
			fmt.Sprintf("%d", raw),
		}
		out := renderAll(t, key)
		writeArtifact(t, art, "decoded-key.txt", []byte(out))
		for _, f := range forbidden {
			if strings.Contains(out, f) {
				t.Fatalf("a rendering of Key leaked key material:\n%s", out)
			}
		}
	})

	t.Run("canary key input never echoed", func(t *testing.T) {
		t.Parallel()
		canary := testsecrets.Canary(t, testsecrets.Token)
		// 43 chars of the canary: right length, wrong content (contains '-' and
		// upper case, may decode to 32 bytes with bad trailing bits or not).
		inputs := []string{canary, canary[:43], canary + "=", "  " + canary}
		for i, in := range inputs {
			k, err := vault.ParseKey(secret.FromString(in))
			if err == nil {
				// A 43-char canary prefix can be valid base64url: then the key
				// must still never render it.
				out := renderAll(t, k)
				writeArtifact(t, art, fmt.Sprintf("canary-key-%d.txt", i), []byte(out))
				if strings.Contains(out, in) || strings.Contains(out, testsecrets.Prefix) {
					t.Fatalf("Key rendering leaked its encoded input")
				}
				continue
			}
			out := renderAll(t, err)
			writeArtifact(t, art, fmt.Sprintf("canary-key-err-%d.txt", i), []byte(out))
			if strings.Contains(out, testsecrets.Prefix) || strings.Contains(out, canary[13:]) {
				t.Fatalf("ParseKey error echoed its input:\n%s", out)
			}
		}
	})
}

// renderAll renders v through every fmt verb, JSON (bare and nested) and
// slog text and JSON handlers.
func renderAll(t *testing.T, v any) string {
	t.Helper()
	var b strings.Builder
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T"} {
		fmt.Fprintf(&b, verb+"\n", v)
	}
	fmt.Fprintln(&b, v)
	type wrapper struct {
		V   any
		Ptr *any
	}
	for _, x := range []any{v, wrapper{V: v, Ptr: &v}, map[string]any{"k": v}} {
		if js, err := json.Marshal(x); err == nil {
			b.Write(js)
			b.WriteByte('\n')
		}
	}
	var logs bytes.Buffer
	for _, h := range []slog.Handler{
		slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}),
		slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}),
	} {
		l := slog.New(h)
		l.Info("vault", "v", v)
		l.Info("vault", slog.Any("any", v), slog.Group("g", "v", v))
	}
	b.Write(logs.Bytes())
	return b.String()
}
