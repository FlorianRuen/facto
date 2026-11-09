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

// dataLike reports a random-looking token: 8 characters or more mixing
// upper and lower case letters with at least two digits (base64, a
// generated secret). Field names have at most one digit in practice
// (IDToken2, address2Line).
func dataLike(s string) bool {
	if len(s) < 8 {
		return false
	}
	upper, lower, digits := 0, 0, 0
	for i := range len(s) {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z':
			upper++
		case c >= 'a' && c <= 'z':
			lower++
		case c >= '0' && c <= '9':
			digits++
		}
	}
	return upper > 0 && lower > 0 && digits >= 2
}

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
