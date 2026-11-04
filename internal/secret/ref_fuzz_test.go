package secret_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// fuzzValueMarker is replaced by a canary in every fuzz input, so the fuzzer
// can move a would-be secret anywhere in a reference.
const fuzzValueMarker = "@V@"

// reasonAlphabet holds every byte the fixed ParseRef reasons are made of
// (lowercase letters, digits, space and ":/(),-"). An input holding any
// other byte can only appear in an error message if the input was echoed.
const reasonAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789 :/(),-"

// FuzzParseRef (SEC-J0-24): ParseRef never panics; an accepted reference is
// canonical (its String() parses back to the same Ref, and equals the input
// up to the case of the bw UUID); a refused one wraps ErrInvalidRef, returns
// the zero Ref and never echoes the input.
func FuzzParseRef(f *testing.F) {
	const uuid = "3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90" // synthetic, as in ref_test.go
	for _, s := range []string{
		// Accepted (TestParseRef).
		"bw://" + uuid + "/username",
		"bw://" + uuid + "/password",
		"bw://" + uuid + "/totp",
		"bw://" + strings.ToUpper(uuid) + "/password",
		"keyring://facto/ileo-password",
		"keyring://facto/ileo/login",
		"keyring://facto.app/drive_refresh.token",
		"keyring://facto/" + fuzzValueMarker,
		// Refused (TestParseRef_Rejects).
		"",
		"hunter2-Plaintext",
		"user:hunter2",
		"facto/ileo/login",
		"//" + uuid + "/password",
		"op://vault/item/password",
		"https://vault.example.test/" + uuid + "/password",
		"BW://" + uuid + "/password",
		"bw:/" + uuid + "/password",
		" bw://" + uuid + "/password",
		"bw://" + uuid + "/password\n",
		"bw://EDF Login/password",
		"bw://{" + uuid + "}/password",
		"bw://" + uuid + "/notes",
		"bw://" + uuid,
		"bw://" + uuid + "/",
		"bw://" + uuid + "/password/extra",
		"bw://" + uuid + "/password?raw=1",
		"bw://user@" + uuid + "/password",
		"bw://" + uuid + ":8087/password",
		"bw://" + uuid + "/pass%77ord",
		"bw://" + fuzzValueMarker + "/password",
		"keyring://facto",
		"keyring:///ileo",
		"keyring://facto/ileo//login",
		"keyring://facto/../ssh",
		"keyring://facto/ileo login",
		"keyring://me@facto/ileo",
		`keyring://facto/ileo\login`,
		"keyring://facto/ileo\x00",
		"keyring://facto/%2e%2e",
		"keyring://facto/ïleo",
		"keyring://" + fuzzValueMarker + "@facto/x",
		fuzzValueMarker,
	} {
		f.Add(s)
	}
	canary := testsecrets.Canary(f, testsecrets.Password)
	tail := canary[strings.LastIndex(canary, "-")+1:]

	f.Fuzz(func(t *testing.T, raw string) {
		for _, s := range []string{raw, strings.ReplaceAll(raw, fuzzValueMarker, canary)} {
			ref, err := secret.ParseRef(s)
			if err != nil {
				checkRefused(t, s, ref, err, canary, tail)
				continue
			}
			checkCanonical(t, s, ref)
		}
	})
}

func checkRefused(t *testing.T, s string, ref secret.Ref, err error, canary, tail string) {
	t.Helper()
	if !errors.Is(err, secret.ErrInvalidRef) {
		t.Fatalf("ParseRef(%q) error = %v, want ErrInvalidRef", s, err)
	}
	if ref != (secret.Ref{}) {
		t.Fatalf("ParseRef(%q) = %+v with an error, want the zero Ref", s, ref)
	}
	msg := err.Error()
	if strings.Contains(s, canary) && (strings.Contains(msg, canary) || strings.Contains(msg, tail)) {
		t.Fatalf("ParseRef error %q echoes the canary", msg)
	}
	if strings.Trim(s, reasonAlphabet) != "" && strings.Contains(msg, s) {
		t.Fatalf("ParseRef(%q) error %q echoes the input", s, msg)
	}
}

func checkCanonical(t *testing.T, s string, ref secret.Ref) {
	t.Helper()
	// bw and keyring in release builds; the e2e build adds its test scheme.
	if ref.Scheme == "" || !strings.HasPrefix(s, ref.Scheme+"://") {
		t.Fatalf("ParseRef(%q) accepted scheme %q", s, ref.Scheme)
	}
	c := ref.String()
	switch ref.Scheme {
	case secret.SchemeBitwarden:
		if !strings.EqualFold(c, s) {
			t.Fatalf("ParseRef(%q).String() = %q, want the input up to UUID case", s, c)
		}
	default:
		if c != s {
			t.Fatalf("ParseRef(%q).String() = %q, want the input", s, c)
		}
	}
	again, err := secret.ParseRef(c)
	if err != nil || again != ref {
		t.Fatalf("ParseRef(%q) = %+v, %v; want %+v (round trip of %q)", c, again, err, ref, s)
	}
	if again.String() != c {
		t.Fatalf("String not stable: %q then %q", c, again.String())
	}
}
