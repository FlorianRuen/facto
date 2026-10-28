package normalize

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
)

var (
	slugRE    = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	amountRE  = regexp.MustCompile(`^(-?)(0|[1-9][0-9]*)-([0-9]{2})([A-Z]{3})$`)
	versionRE = regexp.MustCompile(`^v[0-9]+$`)
	extRE     = regexp.MustCompile(`^[A-Za-z0-9]{1,8}$`)
)

// parseLabel returns the kind of an en or fr label.
func parseLabel(s string) (connector.DocKind, bool) {
	for _, labels := range kindLabels {
		for k, l := range labels {
			if k != 0 && l == s {
				return connector.DocKind(k), true
			}
		}
	}
	return 0, false
}

// ParseName parses a base file name rendered with DefaultFileTemplate, with en
// or fr kind labels:
//
//	<date 2006-01-02>[_<provider>]_<kind label>[_<amount>][_<ref>][_v<n>][.<ext>]
//
// provider and ref are slugs, amount is "84-12EUR", n >= 2 (a final "_v<digits>"
// field is always the version), ext is 1–8 ASCII letters or digits. When the
// field after the date is a kind label and the next one is not, there is no
// provider. The returned Doc has Date at 00:00 UTC, Currency only with an
// amount, Category "", Version 1 without suffix and a lowercase Ext. Any name
// containing a separator or NUL, or not following the grammar, is refused with
// an error wrapping ErrNotCompliant and a zero Doc.
func ParseName(name string) (Doc, error) {
	d, why := parseName(name)
	if why != "" {
		return Doc{}, fmt.Errorf("%w: %q: %s", ErrNotCompliant, name, why)
	}
	return d, nil
}

// parseName implements ParseName; on refusal it returns a non-empty reason.
func parseName(name string) (Doc, string) {
	if strings.ContainsAny(name, "/\\\x00") {
		return Doc{}, "path separator or NUL"
	}
	stem, ext, hasExt := strings.Cut(name, ".")
	if hasExt && !extRE.MatchString(ext) {
		return Doc{}, "bad extension"
	}
	fields := strings.Split(stem, "_")
	for _, f := range fields {
		if f == "" {
			return Doc{}, "empty field"
		}
	}

	d := Doc{Ext: strings.ToLower(ext), Version: 1}
	date, err := time.Parse(time.DateOnly, fields[0])
	if err != nil || date.Format(time.DateOnly) != fields[0] {
		return Doc{}, "bad date"
	}
	d.Date = date
	rest := fields[1:]

	if last := len(rest) - 1; last >= 0 && versionRE.MatchString(rest[last]) {
		digits := rest[last][1:]
		v, err := strconv.Atoi(digits)
		if err != nil || v < 2 || digits[0] == '0' {
			return Doc{}, "bad version"
		}
		d.Version = v
		rest = rest[:last]
	}

	if len(rest) == 0 {
		return Doc{}, "no kind"
	}
	if k, ok := parseLabel(rest[0]); ok && (len(rest) == 1 || !isLabel(rest[1])) {
		d.Kind, rest = k, rest[1:]
	} else {
		if !slugRE.MatchString(rest[0]) || len(rest) < 2 {
			return Doc{}, "bad provider or no kind"
		}
		k, ok := parseLabel(rest[1])
		if !ok {
			return Doc{}, "unknown kind label"
		}
		d.Provider, d.Kind, rest = rest[0], k, rest[2:]
	}

	if len(rest) > 0 {
		if m := amountRE.FindStringSubmatch(rest[0]); m != nil {
			cents, err := strconv.ParseInt(m[1]+m[2]+m[3], 10, 64)
			if err != nil {
				return Doc{}, "amount out of range"
			}
			d.AmountCents, d.Currency = &cents, m[4]
			rest = rest[1:]
		}
	}
	if len(rest) > 0 {
		if !slugRE.MatchString(rest[0]) {
			return Doc{}, "bad ref"
		}
		d.Ref, rest = rest[0], rest[1:]
	}
	if len(rest) > 0 {
		return Doc{}, "too many fields"
	}
	return d, ""
}

func isLabel(s string) bool {
	_, ok := parseLabel(s)
	return ok
}
