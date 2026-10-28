package secret_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/secret"
)

// Synthetic item UUID (the spec's example, not a real vault item).
const itemUUID = "3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90"

func TestParseRef(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want secret.Ref
	}{
		{name: "bw username", in: "bw://" + itemUUID + "/username", want: secret.Ref{Scheme: "bw", Item: itemUUID, Field: "username"}},
		{name: "bw password", in: "bw://" + itemUUID + "/password", want: secret.Ref{Scheme: "bw", Item: itemUUID, Field: "password"}},
		{name: "bw totp", in: "bw://" + itemUUID + "/totp", want: secret.Ref{Scheme: "bw", Item: itemUUID, Field: "totp"}},
		{
			name: "bw uppercase uuid normalized",
			in:   "bw://" + strings.ToUpper(itemUUID) + "/password",
			want: secret.Ref{Scheme: "bw", Item: itemUUID, Field: "password"},
		},
		{name: "keyring service and key", in: "keyring://facto/ileo-password", want: secret.Ref{Scheme: "keyring", Item: "facto", Field: "ileo-password"}},
		{name: "keyring nested key (spec example)", in: "keyring://facto/ileo/login", want: secret.Ref{Scheme: "keyring", Item: "facto", Field: "ileo/login"}},
		{name: "keyring dots and underscores", in: "keyring://facto.app/drive_refresh.token", want: secret.Ref{Scheme: "keyring", Item: "facto.app", Field: "drive_refresh.token"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := secret.ParseRef(tc.in)
			if err != nil {
				t.Fatalf("ParseRef(%q) error = %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseRef(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
			// Canonical round trip.
			again, err := secret.ParseRef(got.String())
			if err != nil || again != got {
				t.Errorf("ParseRef(%q.String() = %q) = %+v, %v; want %+v", tc.in, got.String(), again, err, got)
			}
		})
	}
}

func TestRef_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ref  secret.Ref
		want string
	}{
		{ref: secret.Ref{Scheme: "bw", Item: itemUUID, Field: "totp"}, want: "bw://" + itemUUID + "/totp"},
		{ref: secret.Ref{Scheme: "keyring", Item: "facto", Field: "ileo/login"}, want: "keyring://facto/ileo/login"},
	}
	for _, tc := range tests {
		if got := tc.ref.String(); got != tc.want {
			t.Errorf("%+v.String() = %q, want %q", tc.ref, got, tc.want)
		}
	}
}

func TestParseRef_Rejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
	}{
		// Plaintext values instead of references.
		{name: "empty", in: ""},
		{name: "plaintext password", in: "hunter2-Plaintext"},
		{name: "plaintext with colon", in: "user:hunter2"},
		{name: "plaintext looking like a path", in: "facto/ileo/login"},
		{name: "plaintext with slashes", in: "//" + itemUUID + "/password"},

		// Unknown or malformed schemes.
		{name: "unknown scheme op", in: "op://vault/item/password"},
		{name: "unknown scheme pass", in: "pass://facto/ileo"},
		{name: "https url", in: "https://vault.example.test/" + itemUUID + "/password"},
		{name: "file url", in: "file:///etc/hostname"},
		{name: "uppercase scheme", in: "BW://" + itemUUID + "/password"},
		{name: "missing slashes", in: "bw:" + itemUUID + "/password"},
		{name: "single slash", in: "bw:/" + itemUUID + "/password"},
		{name: "leading space", in: " bw://" + itemUUID + "/password"},
		{name: "trailing newline", in: "bw://" + itemUUID + "/password\n"},

		// Bitwarden: UUID only, known field only.
		{name: "bw item name instead of uuid", in: "bw://EDF Login/password"},
		{name: "bw slug name instead of uuid", in: "bw://edf-login/password"},
		{name: "bw uuid without dashes", in: "bw://3f2a9c1e5b7d4e8a9c217d4e5f6a8b90/password"},
		{name: "bw uuid too short", in: "bw://3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b9/password"},
		{name: "bw uuid non hex", in: "bw://3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8bzz/password"},
		{name: "bw uuid braces", in: "bw://{" + itemUUID + "}/password"},
		{name: "bw unknown field", in: "bw://" + itemUUID + "/notes"},
		{name: "bw uppercase field", in: "bw://" + itemUUID + "/Password"},
		{name: "bw missing field", in: "bw://" + itemUUID},
		{name: "bw empty field", in: "bw://" + itemUUID + "/"},
		{name: "bw extra segment", in: "bw://" + itemUUID + "/password/extra"},
		{name: "bw custom field path", in: "bw://" + itemUUID + "/fields/pin"},
		{name: "bw query", in: "bw://" + itemUUID + "/password?raw=1"},
		{name: "bw fragment", in: "bw://" + itemUUID + "/password#x"},
		{name: "bw userinfo", in: "bw://user@" + itemUUID + "/password"},
		{name: "bw port", in: "bw://" + itemUUID + ":8087/password"},
		{name: "bw percent encoded", in: "bw://" + itemUUID + "/pass%77ord"},

		// Keyring.
		{name: "keyring missing key", in: "keyring://facto"},
		{name: "keyring empty key", in: "keyring://facto/"},
		{name: "keyring empty service", in: "keyring:///ileo"},
		{name: "keyring empty segment", in: "keyring://facto/ileo//login"},
		{name: "keyring trailing slash", in: "keyring://facto/ileo/"},
		{name: "keyring dotdot segment", in: "keyring://facto/../ssh"},
		{name: "keyring dot segment", in: "keyring://facto/./ileo"},
		{name: "keyring dotdot service", in: "keyring://../ileo"},
		{name: "keyring space", in: "keyring://facto/ileo login"},
		{name: "keyring query", in: "keyring://facto/ileo?x=1"},
		{name: "keyring fragment", in: "keyring://facto/ileo#x"},
		{name: "keyring userinfo", in: "keyring://me@facto/ileo"},
		{name: "keyring port", in: "keyring://facto:1/ileo"},
		{name: "keyring backslash", in: `keyring://facto/ileo\login`},
		{name: "keyring NUL", in: "keyring://facto/ileo\x00"},
		{name: "keyring percent", in: "keyring://facto/%2e%2e"},
		{name: "keyring unicode", in: "keyring://facto/ïleo"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := secret.ParseRef(tc.in)
			if !errors.Is(err, secret.ErrInvalidRef) {
				t.Fatalf("ParseRef(%q) = %+v, %v; want error wrapping ErrInvalidRef", tc.in, got, err)
			}
			if got != (secret.Ref{}) {
				t.Errorf("ParseRef(%q) returned %+v with an error, want the zero Ref", tc.in, got)
			}
			if tc.in != "" && strings.Contains(err.Error(), strings.TrimSpace(tc.in)) {
				t.Errorf("error %q echoes the input", err)
			}
		})
	}
}

func TestParseRef_ErrorNeverEchoesPlaintext(t *testing.T) {
	t.Parallel()
	// A user who pastes a password instead of a reference must not see it
	// echoed in an error (which ends up in logs and reports).
	const plaintext = "Zz9-plaintext-pw-QQ7"
	for _, in := range []string{
		plaintext,
		"bw://" + plaintext + "/password",
		"bw://" + itemUUID + "/" + plaintext,
		"keyring://facto/" + plaintext + "?",
		"keyring://" + plaintext + ":1/key",
		"op://" + plaintext,
	} {
		_, err := secret.ParseRef(in)
		if err == nil {
			t.Fatalf("ParseRef(%q) = nil error", in)
		}
		if strings.Contains(err.Error(), plaintext) {
			t.Errorf("ParseRef error %q contains the input value", err)
		}
	}
}
