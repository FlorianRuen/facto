package normalize_test

import (
	"regexp"
	"testing"

	"github.com/FlorianRuen/facto/internal/normalize"
)

// slugRE is the only shape Slug may return (empty allowed).
var slugRE = regexp.MustCompile(`^([a-z0-9]+(-[a-z0-9]+)*)?$`)

// TestSlug_Transliterates: hand-written transliteration table (no x/text),
// lowercase ASCII, single hyphens between words.
func TestSlug_Transliterates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"already a slug", "edf", "edf"},
		{"uppercase", "EDF", "edf"},
		{"acute accents", "Bouygues Télécom", "bouygues-telecom"},
		{"circumflex", "Impôts", "impots"},
		{"cedilla", "Façade", "facade"},
		{"capital cedilla", "Ça va", "ca-va"},
		{"oe ligature", "cœur", "coeur"},
		{"capital oe ligature", "Œuvre", "oeuvre"},
		{"ae ligature", "Æsir et ærø", "aesir-et-aero"},
		{"sharp s", "Straße", "strasse"},
		{"capital sharp s", "STRAẞE", "strasse"},
		{"diaeresis", "naïve Noël", "naive-noel"},
		{"tilde", "Ñandú", "nandu"},
		{"polish", "Łódź", "lodz"},
		{"turkish dotted capital i", "İzmir", "izmir"},
		{"french a", "àâäáãå ÀÂÄÁÃÅ", "aaaaaa-aaaaaa"},
		{"french e", "èéêë ÈÉÊË", "eeee-eeee"},
		{"french i", "ìíîï ÌÍÎÏ", "iiii-iiii"},
		{"french o", "òóôöõø ÒÓÔÖÕØ", "oooooo-oooooo"},
		{"french u", "ùúûü ÙÚÛÜ", "uuuu-uuuu"},
		{"y", "ÿý Ÿ", "yy-y"},
		{"decomposed accents (NFD)", "Télécom", "telecom"},
		{"apostrophe and comma", "Client lunch, Lyon", "client-lunch-lyon"},
		{"elision", "Régie d'Exemple", "regie-d-exemple"},
		{"surrounding spaces and punctuation", "  --Hello!!  World--  ", "hello-world"},
		{"underscore is a field separator", "a__b_c", "a-b-c"},
		{"slash", "a/b", "a-b"},
		{"invoice number with slashes", "INV/2026/001", "inv-2026-001"},
		{"traversal", "../../.ssh", "ssh"},
		{"backslash traversal", `..\..\Windows`, "windows"},
		{"NUL", "a\x00b", "a-b"},
		{"controls", "a\r\n\tb\x7f", "a-b"},
		{"currency symbol", "€ 12", "12"},
		{"non-Latin script only", "東京", ""},
		{"mixed scripts", "東京 EDF", "edf"},
		{"bidi override", "a\u202eb", "a-b"},
		{"empty", "", ""},
		{"only separators", " /._- ", ""},
		{"digits and hyphen kept", "2026-04", "2026-04"},
		{"invalid UTF-8", "a\xffb", "a-b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := normalize.Slug(tc.in)
			if got != tc.want {
				t.Fatalf("Slug(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if again := normalize.Slug(got); again != got {
				t.Fatalf("Slug not idempotent: Slug(%q) = %q", got, again)
			}
		})
	}
}

// FuzzSlug: any input gives a well-formed slug, and Slug is idempotent.
func FuzzSlug(f *testing.F) {
	for _, s := range []string{"", "Bouygues Télécom", "../../.ssh", "a\x00b", "Œuvre ẞ", "東京", "a\xffb", "é", "İ"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := normalize.Slug(s)
		if !slugRE.MatchString(got) {
			t.Fatalf("Slug(%q) = %q, not a slug", s, got)
		}
		if again := normalize.Slug(got); again != got {
			t.Fatalf("Slug not idempotent on %q: %q then %q", s, got, again)
		}
	})
}
