// Package fixtures holds the logic of the fixture tools (scripts/harslim,
// scripts/fixtures/sanitize.sh, scripts/fixtures/scan.sh, scripts/fakepdf;
// .claude/skills/fixtures-from-har): slimming a redacted HAR into fixture
// files, replacing personal data with synthetic format-preserving values,
// and scanning a fixture tree for personal data or secrets left behind.
//
// Synthetic values are recognisable on purpose: example.org/.com/.net/.test
// emails, all-zero IBANs, "+33 6 00 00 00 NN" phones, "00000" postcodes and
// "rue de l'Exemple" addresses. The scanner lets those through and nothing
// else that looks personal.
package fixtures

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/FlorianRuen/facto/internal/har"
)

// Finding is one place where a fixture still looks personal or secret. It
// never carries the matched value.
type Finding struct {
	File string
	Line int
	Kind string // email, phone, iban, card, nir, token, secret-field, canary, address
}

func (f Finding) String() string { return fmt.Sprintf("%s:%d: %s", f.File, f.Line, f.Kind) }

var (
	emailRE = regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@([a-z0-9-]+\.)+[a-z]{2,}\b`)
	// French phone numbers: 0X XX XX XX XX or +33 X XX XX XX XX, any
	// separator among space, dot, dash or none.
	phoneRE = regexp.MustCompile(`(?:\+33\s?|\b0)[1-9](?:[\s.-]?\d{2}){4}\b`)
	ibanRE  = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,3})?\b`)
	cardRE  = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	// NIR: sex 1/2, year, month, department (2 digits or 2A/2B), commune,
	// order, key; spaces optional.
	nirRE    = regexp.MustCompile(`\b[12]\s?\d{2}\s?(?:0[1-9]|1[0-2]|[2-9]\d)\s?(?:\d{2}|2[AB])\s?\d{3}\s?\d{3}\s?\d{2}\b`)
	jwtRE    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}`)
	bearerRE = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{8,})`)
	streetRE = regexp.MustCompile(`(?i)\b\d{1,4}\s?(?:bis|ter)?,?\s+(?:rue|avenue|av\.|boulevard|bd|chemin|all[ée]e|impasse|place|route|quai|cours|square)\s+(?:d[eu']\s?|des\s|de\sla\s|l')?[\p{L}][\p{L}' -]{2,}`)
	// A postcode followed by a city name in capitals (as on invoices).
	cityRE = regexp.MustCompile(`\b(\d{5})\s+[\p{Lu}][\p{Lu}' -]{2,}\b`)
	// secret fields with a value: JSON "name":"value" and form name=value.
	jsonFieldRE       = regexp.MustCompile(`"([A-Za-z0-9_.\[\]-]{2,64})"\s*:\s*"([^"]*)"`)
	jsonNumberFieldRE = regexp.MustCompile(`"([A-Za-z0-9_.-]{2,64})"\s*:\s*(-?\d+(?:\.\d+)?)`)
	nameValueRE       = regexp.MustCompile(`"name"\s*:\s*"([^"]{1,64})"\s*,\s*"value"\s*:\s*"([^"]*)"`)
	valueNameRE       = regexp.MustCompile(`"value"\s*:\s*"([^"]*)"\s*,\s*"name"\s*:\s*"([^"]{1,64})"`)
	blockArgRE        = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]{0,63})\s*:\s*"""(.*?)"""`)
	formFieldRE       = regexp.MustCompile(`(?:^|[?&\s])([A-Za-z0-9_.\[\]%-]{2,64})=([^&\s"'<>]*)`)
	// multipartFieldRE is a multipart/form-data part: its name, then (past
	// its header lines and the blank line) its value; raw or JSON-escaped
	// (flow.json keeps request bodies as JSON strings). It spans lines,
	// so it runs on the whole text (SEC-J2-3).
	multipartFieldRE = regexp.MustCompile(`(?is)form-data;\s*name=\\?"([^"\\]{1,64})\\?".{0,300}?(?:\\r\\n\\r\\n|\\n\\n|\r\n\r\n|\n\n)((?:[^\r\n\\]|\\[^rn])*)`)
)

// syntheticEmailDomains are reserved for examples (RFC 2606, RFC 6761).
var syntheticEmailDomains = []string{"example.org", "example.com", "example.net", "example.test", "example", "invalid", "localhost"}

// ScanText returns the findings of one text file.
func ScanText(file, text string) []Finding {
	var out []Finding
	for i, line := range strings.Split(text, "\n") {
		for _, k := range scanLine(line) {
			out = append(out, Finding{File: file, Line: i + 1, Kind: k})
		}
	}
	for _, m := range multipartFieldRE.FindAllStringSubmatchIndex(text, -1) {
		name, value := text[m[2]:m[3]], text[m[4]:m[5]]
		if har.SecretField(name) && !placeholder(value) {
			out = append(out, Finding{File: file, Line: strings.Count(text[:m[0]], "\n") + 1, Kind: "secret-field"})
		}
	}
	return out
}

// scanLine returns the kinds found in one line, each once.
func scanLine(line string) []string {
	var kinds []string
	add := func(k string) {
		for _, x := range kinds {
			if x == k {
				return
			}
		}
		kinds = append(kinds, k)
	}
	if strings.Contains(line, "FACTO-CANARY-") {
		add("canary")
	}
	for _, m := range emailRE.FindAllString(line, -1) {
		if !syntheticEmail(m) {
			add("email")
		}
	}
	for _, m := range phoneRE.FindAllString(line, -1) {
		if !syntheticPhone(m) {
			add("phone")
		}
	}
	for _, m := range ibanRE.FindAllString(line, -1) {
		if validIBAN(m) && !allZeroDigits(m[4:]) {
			add("iban")
		}
	}
	for _, m := range cardRE.FindAllString(line, -1) {
		d := digits(m)
		if len(d) >= 13 && len(d) <= 19 && luhn(d) && !allZeroDigits(d) && cardPrefix(d) {
			add("card")
		}
	}
	for _, m := range nirRE.FindAllString(line, -1) {
		if validNIR(m) {
			add("nir")
		}
	}
	if jwtRE.MatchString(line) {
		add("token")
	}
	for _, m := range bearerRE.FindAllStringSubmatch(line, -1) {
		if m[1] != har.Redacted && !strings.HasPrefix(m[1], "[") {
			add("token")
		}
	}
	// A JSON body kept as a JSON string (flow.json), possibly nested:
	// scan it unescaped too, up to three levels (SEC-J2-8, SEC-J2-12).
	jsonLine := line
	for u := line; strings.Contains(u, `\"`) && strings.Count(jsonLine, "\n") < 3; {
		u = strings.NewReplacer(`\\`, `\`, `\"`, `"`).Replace(u)
		jsonLine += "\n" + u
	}
	// A credential under a neutral name: {"name":"password","value":…},
	// OpenAM {"name":"IDToken2","value":…}, either order (SEC-J2-10).
	for _, re := range []*regexp.Regexp{nameValueRE, valueNameRE} {
		for _, m := range re.FindAllStringSubmatch(jsonLine, -1) {
			name, value := m[1], m[2]
			if re == valueNameRE {
				name, value = m[2], m[1]
			}
			if credentialName(name) && !placeholder(value) {
				add("secret-field")
			}
		}
	}
	// GraphQL block strings: password: """…""" (SEC-J2-12).
	for _, m := range blockArgRE.FindAllStringSubmatch(jsonLine, -1) {
		if credentialName(m[1]) && !placeholder(m[2]) {
			add("secret-field")
		}
	}
	for _, m := range jsonFieldRE.FindAllStringSubmatch(jsonLine, -1) {
		if har.SecretField(m[1]) && !placeholder(m[2]) {
			add("secret-field")
		}
		if k := personalJSONField(m[1], m[2]); k != "" {
			add(k)
		}
	}
	for _, m := range jsonNumberFieldRE.FindAllStringSubmatch(line, -1) {
		if k := personalJSONField(m[1], m[2]); k != "" {
			add(k)
		}
	}
	for _, m := range formFieldRE.FindAllStringSubmatch(line, -1) {
		name := strings.ReplaceAll(strings.ReplaceAll(m[1], "%5B", "["), "%5D", "]")
		if har.SecretField(name) && !placeholder(m[2]) {
			add("secret-field")
		}
	}
	for _, m := range streetRE.FindAllString(line, -1) {
		if !strings.Contains(strings.ToLower(m), "exemple") && !strings.Contains(strings.ToLower(m), "example") {
			add("address")
		}
	}
	for _, m := range cityRE.FindAllStringSubmatch(line, -1) {
		if m[1] != "00000" {
			add("address")
		}
	}
	return kinds
}

// placeholder reports a value that is clearly not a secret: empty,
// redacted, or a template marker.
func placeholder(v string) bool {
	v = strings.TrimSpace(v)
	switch {
	case v == "", v == har.Redacted, v == "%5Bredacted%5D", v == "[synthetic]":
		return true
	case strings.HasPrefix(v, "{{") || strings.HasPrefix(v, "${"):
		return true
	}
	return false
}

func syntheticEmail(m string) bool {
	_, dom, _ := strings.Cut(strings.ToLower(m), "@")
	for _, s := range syntheticEmailDomains {
		if dom == s || strings.HasSuffix(dom, "."+s) {
			return true
		}
	}
	return false
}

// syntheticPhone accepts the reserved fiction ranges the sanitizer emits:
// 06 00 00 00 NN and +33 6 00 00 00 NN.
func syntheticPhone(m string) bool {
	d := digits(m)
	d = strings.TrimPrefix(d, "33")
	d = strings.TrimPrefix(d, "0")
	return len(d) == 9 && strings.HasPrefix(d[1:], "000000")
}

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func allZeroDigits(s string) bool {
	d := digits(s)
	return d != "" && strings.Trim(d, "0") == ""
}

func luhn(d string) bool {
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// cardPrefix keeps the issuer ranges of real cards (Visa, Mastercard,
// Amex, CB): a Luhn-valid 16-digit invoice number rarely starts so.
func cardPrefix(d string) bool {
	switch d[0] {
	case '4':
		return true
	case '5':
		return d[1] >= '1' && d[1] <= '5'
	case '2':
		return d[1] >= '2' && d[1] <= '7'
	case '3':
		return d[1] == '4' || d[1] == '7'
	}
	return false
}

// validIBAN checks the ISO 13616 mod-97 checksum.
func validIBAN(s string) bool {
	s = strings.ReplaceAll(strings.ToUpper(s), " ", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	r := s[4:] + s[:4]
	mod := 0
	for _, c := range r {
		switch {
		case c >= '0' && c <= '9':
			mod = (mod*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			v := int(c-'A') + 10
			mod = (mod*100 + v) % 97
		default:
			return false
		}
	}
	return mod == 1
}

// validNIR checks the NIR key: 97 - (number mod 97), Corsica 2A/2B mapped
// to 19/18 as INSEE does.
func validNIR(s string) bool {
	s = strings.ReplaceAll(strings.ToUpper(s), " ", "")
	if len(s) != 15 {
		return false
	}
	body := strings.NewReplacer("2A", "19", "2B", "18").Replace(s[:13])
	mod := 0
	for _, c := range body {
		if c < '0' || c > '9' {
			return false
		}
		mod = (mod*10 + int(c-'0')) % 97
	}
	key := int(s[13]-'0')*10 + int(s[14]-'0')
	return 97-mod == key
}

// personalJSONField reports the kind of a JSON field whose name says it is
// personal and whose value is not synthetic: precise coordinates (more
// than 2 decimals, not 0), phone numbers in any format.
func personalJSONField(name, value string) string {
	n := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(name))
	switch n {
	case "lat", "latitude", "lng", "lon", "long", "longitude":
		if _, dec, ok := strings.Cut(value, "."); ok && len(dec) > 2 && strings.Trim(dec, "0") != "" {
			return "coordinates"
		}
	}
	if strings.Contains(n, "phone") || n == "tel" || n == "mobile" {
		if d := digits(value); len(d) >= 8 && !syntheticPhone(value) {
			return "phone"
		}
	}
	return ""
}

// idTokenRE is an OpenAM callback input name (IDToken1, IDToken2…).
var idTokenRE = regexp.MustCompile(`(?i)^IDToken[0-9]+$`)

// credentialName reports a name whose value is a secret: a secret field
// or an OpenAM IDToken input. Login fields are left out: after
// sanitize.sh they hold synthetic addresses, which the email rule checks.
func credentialName(name string) bool {
	return har.SecretField(name) || idTokenRE.MatchString(name)
}
