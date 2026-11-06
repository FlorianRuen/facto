package fixtures

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Sanitizer replaces personal data with synthetic, format-preserving
// values. The same input value always gives the same output for one key
// (an HMAC-SHA256 of the value), across every file sanitized with it, so
// ids and references still match between a list page and its PDF URL.
// Learn the names first (Learn on every file), then call Text.
type Sanitizer struct {
	key   []byte
	names map[string]string // learned personal words -> replacement
	seq   map[string]int    // per-kind counters for readable synthetics
	memo  map[string]string // kind+value -> replacement
}

// NewSanitizer returns a sanitizer keyed by key.
func NewSanitizer(key []byte) *Sanitizer {
	return &Sanitizer{key: slices.Clone(key), names: map[string]string{}, seq: map[string]int{}, memo: map[string]string{}}
}

// nameFields hold a person's name in JSON bodies (normalized: lowercase,
// no separator).
var nameFields = []string{
	"firstname", "lastname", "givenname", "familyname", "surname", "fullname", "name", "displayname",
	"nom", "prenom", "nomcomplet", "titulaire", "holder", "accountholder", "owner", "customername",
	"contactname", "birthname", "nomdenaissance",
}

// addressFields hold an address part in JSON bodies.
var addressFields = []string{"street", "streetaddress", "address", "address1", "address2", "addressline1", "addressline2", "rue", "adresse", "voie", "city", "ville", "commune", "locality"}

// Learn records the personal words of a JSON or HTML text: values of name
// and address fields, and capitalised words after a civility or greeting.
func (s *Sanitizer) Learn(text string) {
	var v any
	if json.Unmarshal([]byte(text), &v) == nil {
		s.learnJSON(v)
	}
	for _, m := range civilityRE.FindAllStringSubmatch(text, -1) {
		for w := range strings.FieldsSeq(m[2]) {
			s.learnWord(w)
		}
	}
}

func (s *Sanitizer) learnJSON(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			str, ok := val.(string)
			n := normalizeKey(k)
			switch {
			case ok && slices.Contains(nameFields, n):
				for w := range strings.FieldsSeq(str) {
					s.learnWord(w)
				}
			case ok && slices.Contains(addressFields, n):
				for w := range strings.FieldsSeq(str) {
					if len([]rune(w)) >= 4 && unicode.IsLetter([]rune(w)[0]) && !commonWord(w) {
						s.learnWord(w)
					}
				}
			default:
				s.learnJSON(val)
			}
		}
	case []any:
		for _, e := range x {
			s.learnJSON(e)
		}
	}
}

// learnWord adds a personal word (and its case variants) to the names.
func (s *Sanitizer) learnWord(w string) {
	w = strings.Trim(w, ".,;:()\"'")
	if len([]rune(w)) < 2 || !unicode.IsLetter([]rune(w)[0]) || commonWord(w) {
		return
	}
	key := strings.ToLower(w)
	if _, ok := s.names[key]; ok {
		return
	}
	s.seq["name"]++
	repl := "Nom" + string(rune('A'+(s.seq["name"]-1)%26))
	if s.seq["name"] > 26 {
		repl += strconv.Itoa(s.seq["name"])
	}
	s.names[key] = repl
}

// commonWord are capitalised words that are never personal.
func commonWord(w string) bool {
	switch strings.ToLower(w) {
	case "rue", "avenue", "boulevard", "chemin", "allée", "allee", "impasse", "place", "route", "quai", "cours",
		"des", "du", "de", "la", "le", "les", "et", "bis", "ter", "france", "paris", "lyon", "marseille",
		"mme", "mr", "m", "madame", "monsieur", "mademoiselle", "mlle", "client", "cliente", "nomexemple":
		return true
	}
	return strings.HasPrefix(strings.ToLower(w), "nom") && len(w) <= 6
}

func normalizeKey(k string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(k) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var (
	civilityRE = regexp.MustCompile(`(?i)\b(M\.|Mme|Mlle|Monsieur|Madame|Mademoiselle|Bonjour|Titulaire\s*:)\s+((?:[\p{Lu}][\p{L}'-]+\s?){1,3})`)
	// Dates: ISO and French formats.
	isoDateRE = regexp.MustCompile(`\b(\d{4})-(\d{2})-(\d{2})\b`)
	frDateRE  = regexp.MustCompile(`\b(\d{2})/(\d{2})/(\d{4})\b`)
	// Amounts with a decimal comma or point and two decimals.
	amountRE = regexp.MustCompile(`\b(\d{1,7})([.,])(\d{2})\b`)
	// JSON integer cents fields.
	centsRE = regexp.MustCompile(`("[A-Za-z_]*(?:cents|amount|montant|total|price|prix)[A-Za-z_]*"\s*:\s*)(-?\d+)\b`)
	// Long digit runs: references, contract and customer numbers.
	digitsRE = regexp.MustCompile(`\d{6,}`)
)

// Text returns the sanitized text. Learn should have seen every file of the
// set first, so a name learned in one file is replaced in all.
func (s *Sanitizer) Text(text string) string {
	s.Learn(text)
	text = emailRE.ReplaceAllStringFunc(text, func(m string) string {
		if syntheticEmail(m) {
			return m
		}
		return s.memoized("email", strings.ToLower(m), func(n int) string { return fmt.Sprintf("user-%04d@example.org", n) })
	})
	text = ibanRE.ReplaceAllStringFunc(text, func(m string) string {
		if !validIBAN(m) || allZeroDigits(m[4:]) {
			return m
		}
		return syntheticIBAN(m)
	})
	text = cardRE.ReplaceAllStringFunc(text, func(m string) string {
		d := digits(m)
		if len(d) < 13 || len(d) > 19 || !luhn(d) || !cardPrefix(d) || allZeroDigits(d) {
			return m
		}
		return zeroDigits(m)
	})
	text = nirRE.ReplaceAllStringFunc(text, func(m string) string {
		if !validNIR(m) {
			return m
		}
		return zeroDigits(m)
	})
	text = phoneRE.ReplaceAllStringFunc(text, func(m string) string {
		if syntheticPhone(m) {
			return m
		}
		n := s.memoized("phone", digits(m), func(n int) string { return fmt.Sprintf("%02d", n%100) })
		return syntheticPhoneLike(m, n)
	})
	text = streetRE.ReplaceAllStringFunc(text, func(m string) string {
		if strings.Contains(strings.ToLower(m), "exemple") {
			return m
		}
		return "1 rue de l'Exemple"
	})
	text = cityRE.ReplaceAllStringFunc(text, func(m string) string {
		if strings.HasPrefix(m, "00000") {
			return m
		}
		return "00000 VILLE-EXEMPLE"
	})
	text = s.replaceZipFields(text)
	text = isoDateRE.ReplaceAllStringFunc(text, func(m string) string {
		p := isoDateRE.FindStringSubmatch(m)
		y, mo, d := s.shiftDate(p[1], p[2], p[3])
		return y + "-" + mo + "-" + d
	})
	text = frDateRE.ReplaceAllStringFunc(text, func(m string) string {
		p := frDateRE.FindStringSubmatch(m)
		y, mo, d := s.shiftDate(p[3], p[2], p[1])
		return d + "/" + mo + "/" + y
	})
	text = centsRE.ReplaceAllStringFunc(text, func(m string) string {
		p := centsRE.FindStringSubmatch(m)
		return p[1] + s.cents(p[2])
	})
	text = amountRE.ReplaceAllStringFunc(text, func(m string) string {
		p := amountRE.FindStringSubmatch(m)
		return p[1] + p[2] + s.centsOf(p[1], p[3])
	})
	text = digitsRE.ReplaceAllStringFunc(text, func(m string) string {
		if allZeroDigits(m) || looksLikeTimestamp(m) {
			return m
		}
		return s.keyedDigits("ref", m, len(m))
	})
	return s.replaceNames(text)
}

// replaceZipFields replaces JSON zip/postcode values.
var zipFieldRE = regexp.MustCompile(`("(?i:zip|zipcode|postcode|postalcode|codepostal|cp|code_postal|postal_code)"\s*:\s*")(\d{5})(")`)

func (s *Sanitizer) replaceZipFields(text string) string {
	return zipFieldRE.ReplaceAllString(text, `${1}00000${3}`)
}

// replaceNames replaces every learned word, whole words only, any case.
func (s *Sanitizer) replaceNames(text string) string {
	if len(s.names) == 0 {
		return text
	}
	words := make([]string, 0, len(s.names))
	for w := range s.names {
		words = append(words, regexp.QuoteMeta(w))
	}
	slices.SortFunc(words, func(a, b string) int { return len(b) - len(a) })
	re := regexp.MustCompile(`(?i)(^|[^\p{L}])(` + strings.Join(words, "|") + `)([^\p{L}]|$)`)
	// Two passes: adjacent matches share a boundary character.
	for range 2 {
		text = re.ReplaceAllStringFunc(text, func(m string) string {
			p := re.FindStringSubmatch(m)
			r := s.names[strings.ToLower(p[2])]
			if strings.ToUpper(p[2]) == p[2] {
				r = strings.ToUpper(r)
			}
			return p[1] + r + p[3]
		})
	}
	return text
}

// memoized returns the replacement of value of kind, numbering new ones.
func (s *Sanitizer) memoized(kind, value string, mk func(n int) string) string {
	k := kind + "\x00" + value
	if r, ok := s.memo[k]; ok {
		return r
	}
	s.seq[kind]++
	r := mk(s.seq[kind])
	s.memo[k] = r
	return r
}

func (s *Sanitizer) mac(kind, value string) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return h.Sum(nil)
}

// keyedDigits returns n digits derived from value; a synthetic value is
// stable (sanitizing twice changes nothing) because it is memoized under
// both the input and the output.
func (s *Sanitizer) keyedDigits(kind, value string, n int) string {
	k := kind + "\x00" + value
	if r, ok := s.memo[k]; ok {
		return r
	}
	if s.memo[kind+"\x00out\x00"+value] != "" {
		return value[len(value)-n:]
	}
	sum := s.mac(kind, value)
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		b.WriteByte('0' + sum[i%len(sum)]%10)
		if i%len(sum) == len(sum)-1 {
			sum = s.mac(kind, string(sum))
		}
	}
	r := b.String()
	// A reference never gets a leading zero it did not have (keeps width
	// and numeric parsing).
	if n > 1 && r[0] == '0' && value[0] != '0' {
		r = "1" + r[1:]
	}
	s.memo[k] = r
	s.memo[kind+"\x00out\x00"+r] = r
	return r
}

// centsOf returns the synthetic cents of the amount euros.cents; an
// amount this sanitizer produced keeps its cents (idempotence).
func (s *Sanitizer) centsOf(euros, cents string) string {
	in := "amount\x00" + euros + "." + cents
	if r, ok := s.memo[in]; ok {
		return r
	}
	if _, ok := s.memo["amount\x00out\x00"+euros+"."+cents]; ok {
		return cents
	}
	r := s.keyedDigits("cents", euros+cents, 2)
	s.memo[in] = r
	s.memo["amount\x00out\x00"+euros+"."+r] = r
	return r
}

// cents keeps the euros of an integer cents value and replaces its cents.
func (s *Sanitizer) cents(v string) string {
	neg := strings.HasPrefix(v, "-")
	v = strings.TrimPrefix(v, "-")
	if len(v) < 3 {
		return map[bool]string{true: "-", false: ""}[neg] + v
	}
	out := v[:len(v)-2] + s.centsOf(v[:len(v)-2], v[len(v)-2:])
	if neg {
		out = "-" + out
	}
	return out
}

// shiftDate moves every date by the same keyed offset (1-27 days back):
// order and intervals between dates are kept (period_start <= period_end),
// the format too. A date this sanitizer produced is left alone.
func (s *Sanitizer) shiftDate(y, m, d string) (string, string, string) {
	t, err := time.Parse(time.DateOnly, y+"-"+m+"-"+d)
	if err != nil {
		return y, m, d
	}
	k := t.Format(time.DateOnly)
	if r, ok := s.memo["date\x00"+k]; ok {
		return r[:4], r[5:7], r[8:]
	}
	if _, ok := s.memo["date\x00out\x00"+k]; ok {
		return y, m, d
	}
	sum := s.mac("date-offset", "")
	days := int(binary.BigEndian.Uint16(sum[0:2]))%27 + 1
	r := t.AddDate(0, 0, -days).Format(time.DateOnly)
	s.memo["date\x00"+k] = r
	s.memo["date\x00out\x00"+r] = r
	return r[:4], r[5:7], r[8:]
}

// looksLikeTimestamp keeps Unix timestamps (10 or 13 digits starting with
// 1): they date a page, they identify nobody.
func looksLikeTimestamp(d string) bool {
	return (len(d) == 10 || len(d) == 13) && d[0] == '1' && d[1] >= '6' && d[1] <= '9'
}

// syntheticIBAN keeps the country and layout and zeroes the account, with
// a valid checksum.
func syntheticIBAN(m string) string {
	z := zeroDigits(m[4:])
	compact := strings.ToUpper(strings.ReplaceAll(m[:2]+"00"+z, " ", ""))
	r := compact[4:] + compact[:4]
	mod := 0
	for _, c := range r {
		if c >= 'A' && c <= 'Z' {
			mod = (mod*100 + int(c-'A') + 10) % 97
		} else {
			mod = (mod*10 + int(c-'0')) % 97
		}
	}
	return fmt.Sprintf("%s%02d%s", m[:2], 98-mod, z)
}

// zeroDigits replaces every digit and letter (after the first two letters
// of an IBAN body, letters are bank codes) with 0, keeping the layout.
func zeroDigits(s string) string {
	b := []byte(s)
	for i, c := range b {
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') {
			b[i] = '0'
		}
	}
	return string(b)
}

// syntheticPhoneLike keeps the layout of m with the fiction number
// 06 00 00 00 nn (or +33 6 00 00 00 nn).
func syntheticPhoneLike(m, nn string) string {
	repl := "06000000" + nn // 10 digits
	if strings.HasPrefix(m, "+33") {
		repl = "336000000" + nn // 11 digits
	}
	out := []byte(m)
	j := 0
	for i, c := range out {
		if c >= '0' && c <= '9' {
			if j >= len(repl) {
				// Unexpected layout: drop the extra digits' meaning.
				out[i] = '0'
				continue
			}
			out[i] = repl[j]
			j++
		}
	}
	return string(out)
}
