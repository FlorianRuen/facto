package fixtures_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fixtures"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

func kinds(fs []fixtures.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Kind)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func TestScan_FindsPersonalDataAndSecrets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		kind string
	}{
		{"email", `{"email":"jean.dupont@orange.fr"}`, "email"},
		{"french mobile", "Tel : 06 12 34 56 78", "phone"},
		{"french intl phone", "+33 6 12 34 56 78", "phone"},
		{"iban", "IBAN FR76 3000 6000 0112 3456 7890 189", "iban"},
		{"iban compact", "FR7630006000011234567890189", "iban"},
		{"card", "4970 1012 3456 7893", "card"},
		{"nir", "NIR 1 85 05 78 006 084 91", "nir"},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl", "token"},
		{"bearer", "Authorization: Bearer abcdefghijklmnopqrstuvwx", "token"},
		{"secret field", `{"password":"hunter2-real"}`, "secret-field"},
		{"secret form", "csrf_token=Zx81jAq0aa&page=1", "secret-field"},
		{"canary", testsecrets.Canary(t, testsecrets.Password), "canary"},
		{"street address", "12 rue des Lilas", "address"},
		{"postcode city", "75011 PARIS", "address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := fixtures.ScanText("f.txt", tt.in)
			if !slices.Contains(kinds(got), tt.kind) {
				t.Fatalf("ScanText(%q) kinds = %q, want %s", tt.in, kinds(got), tt.kind)
			}
			for _, f := range got {
				if strings.Contains(f.String(), tt.in) && len(tt.in) > 8 {
					t.Errorf("finding quotes the matched value: %s", f)
				}
			}
		})
	}
}

func TestScan_SyntheticValuesPass(t *testing.T) {
	t.Parallel()
	clean := []string{
		`{"email":"user-0001@example.org","phone":"+33 6 00 00 00 01"}`,
		`IBAN FR00 0000 0000 0000 0000 0000 000`,
		`{"password":"[redacted]","csrf_token":"[redacted]"}`,
		"csrf_token=%5Bredacted%5D&page=1",
		`{"id":"FP-2026-0001","amount_cents":8412,"issued_at":"2026-03-14","contract":"CTR-0001"}`,
		`<p>1 rue de l'Exemple, 00000 Ville-Exemple</p>`,
		`version 1.2.3.4 build 20260314`,
		`<img width="1234567890">`,
		`Authorization: Bearer [redacted]`,
	}
	for _, s := range clean {
		if got := fixtures.ScanText("f.txt", s); len(got) != 0 {
			t.Errorf("ScanText(%q) = %v, want no finding", s, got)
		}
	}
}

func TestScan_LuhnAndIBANChecksumsAvoidFalsePositives(t *testing.T) {
	t.Parallel()
	// 16 digits failing Luhn: an invoice reference, not a card.
	if got := fixtures.ScanText("f", "Ref 1234 5678 9012 3456"); slices.Contains(kinds(got), "card") {
		t.Errorf("non-Luhn number reported as a card: %v", got)
	}
	// FR + digits with a wrong checksum: not an IBAN.
	if got := fixtures.ScanText("f", "FR1230006000011234567890189"); slices.Contains(kinds(got), "iban") {
		t.Errorf("bad-checksum IBAN reported: %v", got)
	}
}

func TestScan_FindingsCarryFileAndLine(t *testing.T) {
	t.Parallel()
	got := fixtures.ScanText("dir/page.html", "ok\nok\nmail me: a.person@gmail.com\n")
	if len(got) != 1 || got[0].File != "dir/page.html" || got[0].Line != 3 {
		t.Fatalf("findings = %+v, want one at dir/page.html:3", got)
	}
	if s := got[0].String(); !strings.Contains(s, "dir/page.html:3") || strings.Contains(s, "a.person@gmail.com") {
		t.Fatalf("String() = %q, want place without the value", s)
	}
}
