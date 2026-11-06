package fixtures_test

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/fixtures"
)

// realistic is a synthetic page that looks like a real supplier page:
// every value below is invented, none belongs to a real person.
const realistic = `<html><body>
<h1>Bonjour Marie Lambert</h1>
<p>Titulaire : Mme Marie LAMBERT</p>
<p>Adresse : 14 rue des Acacias, 69003 LYON</p>
<p>Email : marie.lambert@free.fr - Tel : 06 71 22 43 98</p>
<p>Contrat n° 4012345678 - Référence client : 98765432101</p>
<p>IBAN : FR76 3000 6000 0112 3456 7890 189</p>
<p>Facture du 14/03/2026, montant 84,12 € TTC</p>
</body></html>`

const realisticJSON = `{"customer":{"firstName":"Marie","lastName":"Lambert","email":"marie.lambert@free.fr",
"phone":"+33671224398","address":{"street":"14 rue des Acacias","zip":"69003","city":"Lyon"}},
"contract_number":"4012345678","invoices":[{"id":"FA-2026-03-4012345678","date":"2026-03-14","amount":84.12,"amount_cents":8412}]}`

func TestSanitize_RemovesPersonalDataAndScansClean(t *testing.T) {
	t.Parallel()
	s := fixtures.NewSanitizer([]byte("test-seed"))
	html := s.Text(realistic)
	js := s.Text(realisticJSON)
	for _, leaked := range []string{
		"Marie", "Lambert", "LAMBERT", "Acacias", "69003", "marie.lambert", "06 71 22 43 98",
		"+33671224398", "4012345678", "98765432101", "FR76 3000", "84,12", "8412", "14/03/2026", "2026-03-14",
	} {
		if strings.Contains(html, leaked) || strings.Contains(js, leaked) {
			t.Errorf("sanitized output still holds %q:\n%s\n%s", leaked, html, js)
		}
	}
	if f := fixtures.ScanText("page.html", html); len(f) != 0 {
		t.Errorf("scan of sanitized HTML: %v\n%s", f, html)
	}
	if f := fixtures.ScanText("data.json", js); len(f) != 0 {
		t.Errorf("scan of sanitized JSON: %v\n%s", f, js)
	}
	// Formats preserved: a date stays a date, an amount an amount, the
	// JSON stays valid-looking, ids keep their shape.
	for _, re := range []string{`\d{2}/\d{2}/\d{4}`, `\d+,\d{2} €`, `IBAN : FR\d{2}( 0000){5} 000`} {
		if !regexp.MustCompile(re).MatchString(html) {
			t.Errorf("format %s lost:\n%s", re, html)
		}
	}
	if !regexp.MustCompile(`"date":"\d{4}-\d{2}-\d{2}"`).MatchString(js) || !regexp.MustCompile(`"id":"FA-\d{4}-\d{2}-\d{10}"`).MatchString(js) {
		t.Errorf("JSON formats lost:\n%s", js)
	}
}

func TestSanitize_ConsistentAcrossFilesAndDeterministic(t *testing.T) {
	t.Parallel()
	a := fixtures.NewSanitizer([]byte("seed-1"))
	x := a.Text(`{"contract_number":"4012345678"}`)
	y := a.Text(`<a href="/contracts/4012345678/invoices">Contrat 4012345678</a>`)
	n := regexp.MustCompile(`\d{10}`).FindString(x)
	if n == "" || strings.Count(y, n) != 2 {
		t.Fatalf("the same contract number maps differently across files: %s / %s", x, y)
	}
	b := fixtures.NewSanitizer([]byte("seed-1"))
	if got := b.Text(`{"contract_number":"4012345678"}`); got != x {
		t.Fatalf("not deterministic for one seed: %s vs %s", got, x)
	}
	c := fixtures.NewSanitizer([]byte("seed-2"))
	if got := c.Text(`{"contract_number":"4012345678"}`); got == x {
		t.Fatalf("different seeds gave the same mapping")
	}
}

func TestSanitize_KeepsStructureAndHarmlessText(t *testing.T) {
	t.Parallel()
	s := fixtures.NewSanitizer([]byte("k"))
	in := `{"status":"paid","currency":"EUR","page":1,"next_page":null,"type":"invoice","lang":"fr"}`
	if got := s.Text(in); got != in {
		t.Fatalf("harmless JSON changed:\n%s\n%s", in, got)
	}
	html := `<form id="login-form"><input id="username" name="username"><button>Se connecter</button></form>`
	if got := s.Text(html); got != html {
		t.Fatalf("harmless HTML changed:\n%s\n%s", html, got)
	}
}

func TestSanitize_Idempotent(t *testing.T) {
	t.Parallel()
	s := fixtures.NewSanitizer([]byte("k"))
	once := s.Text(realistic)
	if twice := s.Text(once); twice != once {
		t.Fatalf("second pass changed the output:\n%s\n%s", once, twice)
	}
}

// TestSanitize_DatesKeepOrderAndIntervals: one offset for the whole set,
// so period_start <= period_end still holds and a 30-day period stays 30.
func TestSanitize_DatesKeepOrderAndIntervals(t *testing.T) {
	t.Parallel()
	s := fixtures.NewSanitizer([]byte("dates"))
	got := s.Text(`{"period_start":"2025-01-01","period_end":"2025-01-31","issued_at":"2025-02-15"} 14/03/2026`)
	re := regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
	ds := re.FindAllString(got, -1)
	if len(ds) != 3 || ds[0] >= ds[1] || ds[1] >= ds[2] {
		t.Fatalf("dates out of order: %s", got)
	}
	a, _ := time.Parse(time.DateOnly, ds[0])
	b, _ := time.Parse(time.DateOnly, ds[1])
	if b.Sub(a) != 30*24*time.Hour {
		t.Fatalf("interval changed: %s", got)
	}
	if strings.Contains(got, "2025-01-01") || strings.Contains(got, "14/03/2026") {
		t.Fatalf("dates kept: %s", got)
	}
}
