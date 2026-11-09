package har

import (
	"regexp"
	"strings"
)

// Names in request bodies (SEC-J2-13). Request bodies keep their names and
// lose their values; but a page can put data where a name is expected (a
// raw base64 "login:secret" body reads as one urlencoded name, a JSON
// object can be keyed by an email). A name is kept only when it looks like
// a field name; any other becomes Redacted (tainted file-wide).

// fieldNameRE is an identifier-shaped name: an optional "@" or "$" (JSON-LD,
// GraphQL), a letter or "_", then letters, digits, "_", ".", "[", "]", ":"
// or "-"; 64 characters at most.
var fieldNameRE = regexp.MustCompile(`^[@$]?[A-Za-z_][A-Za-z0-9_.\[\]:-]{0,63}$`)

// redactedNameRE is a name this package wrote ("[redacted]", or
// "[redacted-2]" when a JSON object needs several distinct keys).
var redactedNameRE = regexp.MustCompile(`^\[redacted(?:-[0-9]+)?\]$`)

// fieldName reports whether name looks like a field name and not like
// data: identifier-shaped and not a random-looking token.
func fieldName(name string) bool {
	if redactedNameRE.MatchString(name) {
		return true
	}
	return fieldNameRE.MatchString(name) && !dataLike(name)
}

// dataLike reports a random-looking token. A field name is made of words
// (camelCase or separated parts, a digit run here and there: IDToken2,
// ctl00_MainContent, iso8601Date); a generated token is not:
//   - hex of 16+ characters or a UUID (CSRF field names, hashes);
//   - a lowercase run of 32+ characters with no separator;
//   - several digit runs between letters: mixed case with 2+
//     (Zq7Canary91xPw), any case with 3+ in 12+ characters (session ids);
//   - case flipping on most letters (base64url: kXpQzRmWtYvLsNbH…),
//     where camelCase flips once per word.
func dataLike(s string) bool {
	if len(s) < 8 {
		return false
	}
	// Hex tokens (CSRF field names, hashes) and UUIDs (SEC-J2-15).
	if (len(s) >= 16 && hexTokenRE.MatchString(s)) || uuidRE.MatchString(s) {
		return true
	}
	// A long lowercase run with no separator is not a field name
	// (camelCase names keep an upper-case letter).
	if len(s) >= 32 && !strings.ContainsAny(s, "_.-[]:ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return true
	}
	upper, lower, digitRuns, flips := 0, 0, 0, 0
	prevDigit, prevCase := false, byte(0) // prevCase: 'u', 'l' or 0
	for i := range len(s) {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		if isDigit && !prevDigit {
			digitRuns++
		}
		prevDigit = isDigit
		var cs byte
		switch {
		case c >= 'A' && c <= 'Z':
			upper++
			cs = 'u'
		case c >= 'a' && c <= 'z':
			lower++
			cs = 'l'
		default:
			continue
		}
		if prevCase != 0 && cs != prevCase {
			flips++
		}
		prevCase = cs
	}
	switch {
	case upper > 0 && lower > 0 && digitRuns >= 2:
		return true
	case len(s) >= 12 && digitRuns >= 3:
		return true
	case flips >= 8 && flips*3 >= upper+lower:
		return true
	}
	return false
}

// hexTokenRE is 16+ hex digits mixing digits and letters; uuidRE a UUID.
var (
	hexTokenRE = regexp.MustCompile(`^(?i)(?:[0-9a-f]*[0-9][0-9a-f]*[a-f][0-9a-f]*|[0-9a-f]*[a-f][0-9a-f]*[0-9][0-9a-f]*)$`)
	uuidRE     = regexp.MustCompile(`^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// gqlNumberRE is a GraphQL-ish number token not glued to a name: sign,
// leading dot, hex or underscore forms included (redacted whole).
var gqlNumberRE = regexp.MustCompile(`(^|[^A-Za-z0-9_$])[+-]?\.?[0-9][A-Za-z0-9_.]*`)

// gqlStringRE is a GraphQL string literal (block or quoted).
var gqlStringRE = regexp.MustCompile(`"""(?s:.*?)"""|"(?:[^"\\\n]|\\.)*"`)

// gqlArgsRE is one argument list (no nested parentheses).
var gqlArgsRE = regexp.MustCompile(`\([^()]*\)`)

// gqlEnumArgRE is a name, ":", then a bare identifier: an enum argument
// value, or (after a "$variable") a type, which is kept.
var gqlEnumArgRE = regexp.MustCompile(`(\$?[A-Za-z_][A-Za-z0-9_]*)(\s*:\s*)([A-Za-z_][A-Za-z0-9_]*)`)

// gqlIdentRE is an identifier left in a redacted document.
var gqlIdentRE = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// gqlResidueRE is what a redacted document may still contain once its
// redacted literals are taken out: names, variables, punctuation.
var gqlResidueRE = regexp.MustCompile(`^[A-Za-z0-9_$!:(){}\[\],=@.|&\s-]*$`)

// redactGraphQL redacts every literal of a GraphQL document (strings,
// numbers, enum argument values) and checks that what is left is a
// document: no comment, no other quote, no digit-led token, no
// random-looking name. ok is false otherwise; the caller then redacts the
// whole string.
func redactGraphQL(doc string) (string, bool) {
	out := gqlStringRE.ReplaceAllStringFunc(doc, func(m string) string {
		if strings.HasPrefix(m, `"""`) {
			return `"""` + Redacted + `"""`
		}
		return `"` + Redacted + `"`
	})
	out = gqlNumberRE.ReplaceAllString(out, "${1}"+Redacted)
	out = gqlArgsRE.ReplaceAllStringFunc(out, func(args string) string {
		return gqlEnumArgRE.ReplaceAllStringFunc(args, func(m string) string {
			p := gqlEnumArgRE.FindStringSubmatch(m)
			if strings.HasPrefix(p[1], "$") {
				return m // a variable definition: its type
			}
			switch p[3] {
			case "true", "false", "null":
				return m
			}
			return p[1] + p[2] + Redacted
		})
	})
	rest := strings.NewReplacer(`"""`+Redacted+`"""`, " ", `"`+Redacted+`"`, " ", Redacted, " ").Replace(out)
	if !gqlResidueRE.MatchString(rest) || gqlNumberRE.MatchString(rest) {
		return "", false
	}
	for _, id := range gqlIdentRE.FindAllString(rest, -1) {
		if dataLike(id) {
			return "", false
		}
	}
	return out, true
}
