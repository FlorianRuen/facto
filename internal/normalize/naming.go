// Package normalize turns supplier documents into stable names and decides
// whether a document is new: slugs, file and folder templates, the parser for
// names facto rendered itself (inbox inference) and the dedup rules. See
// docs/spec.md "Normalization and naming" and ADR 0007 (D3, D4).
//
// Every value that reaches a path is a slug or a fixed-shape string (date,
// amount, version), and every rendered path component also goes through
// fsx.SafeName: supplier input can never add a separator, a dot segment or a
// Windows device name.
package normalize

import (
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
)

// Default templates (docs/spec.md "Configuration").
const (
	DefaultFileTemplate = "{date:2006-01-02}_{provider}_{kind}[_{amount}][_{ref}]"
	DefaultDirTemplate  = "{year}/{category}/{provider}"
)

// defaultCategory is the category of a document without one (ADR 0007 D4).
const defaultCategory = "other"

// maxExtLen is the longest extension Render keeps, in bytes, dot excluded.
const maxExtLen = 8

var (
	// ErrBadTemplate reports template syntax or content refused by NewNamer.
	ErrBadTemplate = errors.New("normalize: bad template")
	// ErrUnknownLanguage reports a Config.Language other than "", "en" or "fr".
	ErrUnknownLanguage = errors.New("normalize: unknown language")
	// ErrInvalidDoc reports a Doc Render refuses: zero Date, invalid Kind, or
	// a file stem that renders empty.
	ErrInvalidDoc = errors.New("normalize: invalid document")
	// ErrNotCompliant reports a name ParseName does not recognise as rendered
	// with DefaultFileTemplate.
	ErrNotCompliant = errors.New("normalize: name not compliant")
)

// kindLabels holds the kind labels used in names, per language, indexed by
// connector.DocKind. The DocKind ids stay English; TaxNotice is the property
// tax notice.
var kindLabels = map[string][]string{
	"en": {
		connector.Invoice:     "invoice",
		connector.Receipt:     "receipt",
		connector.RentReceipt: "rent-receipt",
		connector.TaxNotice:   "property-tax-notice",
		connector.Statement:   "statement",
	},
	"fr": {
		connector.Invoice:     "facture",
		connector.Receipt:     "recu",
		connector.RentReceipt: "quittance-de-loyer",
		connector.TaxNotice:   "avis-de-taxe-fonciere",
		connector.Statement:   "releve",
	},
}

// label returns the label of k in labels, or "" for an invalid kind.
func label(labels []string, k connector.DocKind) string {
	if k <= 0 || int(k) >= len(labels) {
		return ""
	}
	return labels[k]
}

// Doc holds the fields a name is rendered from. Render never mutates it.
type Doc struct {
	// Provider is the connector id or the Factur-X seller; optional; slugged.
	Provider string
	// Category is used by dir templates; slugged; "" renders as "other".
	Category string
	// Kind is required; rendered as its language label.
	Kind connector.DocKind
	// Date is required (IssuedAt); rendered in UTC.
	Date time.Time
	// AmountCents is optional.
	AmountCents *int64
	// Currency is the ISO 4217 code; uppercased; the amount is omitted unless
	// it is three ASCII letters.
	Currency string
	// Ref is optional (ProviderID or receipt description); slugged.
	Ref string
	// Ext is the file extension ("pdf", ".pdf", "PDF"): lowercased, only
	// [a-z0-9] kept, at most 8 bytes; "" means no extension.
	Ext string
	// Version 0 or 1 adds no suffix; n >= 2 adds "_v<n>" before the extension.
	Version int
}

// Path is a rendered location relative to the output root.
type Path struct {
	// Dir is slash-separated; every segment is non-empty, not a dot segment
	// and equal to its fsx.SafeName.
	Dir string
	// File is one component equal to its fsx.SafeName, at most
	// fsx.MaxNameLen bytes.
	File string
}

// Rel returns path.Join(Dir, File).
func (p Path) Rel() string { return path.Join(p.Dir, p.File) }

// Config selects the templates and the kind label language.
type Config struct {
	File     string // file template; "" = DefaultFileTemplate
	Dir      string // dir template; "" = DefaultDirTemplate
	Language string // "en" (default when "") or "fr"
}

// field is a template placeholder.
type field int

const (
	fLiteral field = iota
	fDate
	fYear
	fProvider
	fCategory
	fKind
	fAmount
	fRef
)

var fieldNames = map[string]field{
	"date": fDate, "year": fYear, "provider": fProvider, "category": fCategory,
	"kind": fKind, "amount": fAmount, "ref": fRef,
}

// token is a literal or a placeholder.
type token struct {
	field field
	text  string // literal text, or the date layout
}

// group is a run of tokens; an optional group renders only when all its
// placeholders are non-empty.
type group struct {
	tokens   []token
	optional bool
}

// segment is one path component of a template.
type segment []group

// Namer renders names. It is immutable and safe for concurrent use.
type Namer struct {
	file   segment
	dir    []segment
	labels []string
}

// NewNamer validates cfg and compiles its templates. Template language:
//   - placeholders {date} (layout "2006-01-02"), {date:<Go layout>}, {year},
//     {provider}, {category}, {kind}, {amount}, {ref}; every value is a Slug
//     except {amount} ("84-12EUR") and {year} (decimal);
//   - "[ … ]" is an optional group, rendered only when every placeholder in it
//     is non-empty; groups do not nest;
//   - literal text is [a-z0-9_-]; dir templates also allow '/' between
//     segments, outside groups, with no leading, trailing or doubled '/'.
//
// Errors wrap ErrBadTemplate or ErrUnknownLanguage; the Namer is then nil.
func NewNamer(cfg Config) (*Namer, error) {
	lang := cfg.Language
	if lang == "" {
		lang = "en"
	}
	labels, ok := kindLabels[lang]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownLanguage, cfg.Language)
	}
	fileTmpl, dirTmpl := cfg.File, cfg.Dir
	if fileTmpl == "" {
		fileTmpl = DefaultFileTemplate
	}
	if dirTmpl == "" {
		dirTmpl = DefaultDirTemplate
	}
	file, err := parseTemplate(fileTmpl, false)
	if err != nil {
		return nil, fmt.Errorf("file template: %w", err)
	}
	dir, err := parseTemplate(dirTmpl, true)
	if err != nil {
		return nil, fmt.Errorf("dir template: %w", err)
	}
	return &Namer{file: file[0], dir: dir, labels: labels}, nil
}

// parseTemplate compiles a template into segments (always one for a file
// template).
func parseTemplate(tmpl string, isDir bool) ([]segment, error) {
	var (
		segs    []segment
		cur     segment
		grp     = group{}
		inGroup bool
	)
	flush := func() {
		if len(grp.tokens) > 0 || grp.optional {
			cur = append(cur, grp)
		}
		grp = group{}
	}
	endSegment := func() error {
		flush()
		if len(cur) == 0 {
			return fmt.Errorf("%w: empty path segment in %q", ErrBadTemplate, tmpl)
		}
		segs = append(segs, cur)
		cur = nil
		return nil
	}
	for i := 0; i < len(tmpl); i++ {
		c := tmpl[i]
		switch {
		case c == '{':
			end := strings.IndexByte(tmpl[i:], '}')
			if end < 0 {
				return nil, fmt.Errorf("%w: unclosed '{' in %q", ErrBadTemplate, tmpl)
			}
			tok, err := parsePlaceholder(tmpl[i+1 : i+end])
			if err != nil {
				return nil, err
			}
			grp.tokens = append(grp.tokens, tok)
			i += end
		case c == '}':
			return nil, fmt.Errorf("%w: stray '}' in %q", ErrBadTemplate, tmpl)
		case c == '[':
			if inGroup {
				return nil, fmt.Errorf("%w: nested '[' in %q", ErrBadTemplate, tmpl)
			}
			flush()
			grp.optional, inGroup = true, true
		case c == ']':
			if !inGroup {
				return nil, fmt.Errorf("%w: stray ']' in %q", ErrBadTemplate, tmpl)
			}
			flush()
			inGroup = false
		case c == '/' && isDir && !inGroup:
			if err := endSegment(); err != nil {
				return nil, err
			}
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '_', c == '-':
			grp.tokens = append(grp.tokens, token{field: fLiteral, text: string(c)})
		default:
			return nil, fmt.Errorf("%w: character %q not allowed in %q", ErrBadTemplate, c, tmpl)
		}
	}
	if inGroup {
		return nil, fmt.Errorf("%w: unclosed '[' in %q", ErrBadTemplate, tmpl)
	}
	if err := endSegment(); err != nil {
		return nil, err
	}
	return segs, nil
}

// parsePlaceholder parses the inside of "{…}".
func parsePlaceholder(s string) (token, error) {
	if strings.ContainsAny(s, "{[]") {
		return token{}, fmt.Errorf("%w: unclosed '{' before {%s}", ErrBadTemplate, s)
	}
	name, layout, hasLayout := strings.Cut(s, ":")
	f, ok := fieldNames[name]
	if !ok {
		return token{}, fmt.Errorf("%w: unknown placeholder {%s}", ErrBadTemplate, s)
	}
	if hasLayout && (f != fDate || layout == "") {
		return token{}, fmt.Errorf("%w: placeholder {%s} takes no such argument", ErrBadTemplate, s)
	}
	if f == fDate && !hasLayout {
		layout = time.DateOnly
	}
	return token{field: f, text: layout}, nil
}

// values are the rendered field values of one Doc.
type values struct {
	date     time.Time
	year     string
	provider string
	category string
	kind     string
	amount   string
	ref      string
}

func (v *values) get(t token) string {
	switch t.field {
	case fDate:
		return Slug(v.date.Format(t.text))
	case fYear:
		return v.year
	case fProvider:
		return v.provider
	case fCategory:
		return v.category
	case fKind:
		return v.kind
	case fAmount:
		return v.amount
	case fRef:
		return v.ref
	case fLiteral:
		return t.text
	}
	return ""
}

// render renders a segment: optional groups with an empty placeholder are
// dropped, runs of '_' collapse to one and leading/trailing '_' are trimmed.
func (s segment) render(v *values) string {
	var b strings.Builder
	for _, g := range s {
		var gb strings.Builder
		complete := true
		for _, t := range g.tokens {
			val := v.get(t)
			if t.field != fLiteral && val == "" {
				complete = false
			}
			gb.WriteString(val)
		}
		if g.optional && !complete {
			continue
		}
		b.WriteString(gb.String())
	}
	return strings.Trim(collapseUnderscores(b.String()), "_")
}

func collapseUnderscores(s string) string {
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	return s
}

// formatAmount renders cents as "84-12EUR" ("-10-50EUR" when negative), or ""
// when there is no amount or the currency is not three ASCII letters.
func formatAmount(cents *int64, currency string) string {
	if cents == nil {
		return ""
	}
	cur := []byte(currency)
	if len(cur) != 3 {
		return ""
	}
	for i, c := range cur {
		if 'a' <= c && c <= 'z' {
			c -= 'a' - 'A'
			cur[i] = c
		}
		if c < 'A' || c > 'Z' {
			return ""
		}
	}
	// Decimal digits rather than arithmetic: no overflow on math.MinInt64.
	digits := strconv.FormatInt(*cents, 10)
	sign := ""
	if digits[0] == '-' {
		sign, digits = "-", digits[1:]
	}
	if len(digits) < 3 {
		digits = strings.Repeat("0", 3-len(digits)) + digits
	}
	return sign + digits[:len(digits)-2] + "-" + digits[len(digits)-2:] + string(cur)
}

// normalizeExt lowercases ext and keeps at most maxExtLen ASCII letters and
// digits.
func normalizeExt(ext string) string {
	var b strings.Builder
	for i := 0; i < len(ext) && b.Len() < maxExtLen; i++ {
		c := ext[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if 'a' <= c && c <= 'z' || '0' <= c && c <= '9' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Render renders d's directory and file name. Missing optional fields are
// omitted with their separator; an empty Category is "other". A file name
// longer than fsx.MaxNameLen is shortened by truncating the stem; the "_vN"
// suffix and the extension are always kept. Errors wrap ErrInvalidDoc and
// come with a zero Path.
func (n *Namer) Render(d Doc) (Path, error) {
	if d.Date.IsZero() {
		return Path{}, fmt.Errorf("%w: zero date", ErrInvalidDoc)
	}
	kind := label(n.labels, d.Kind)
	if kind == "" {
		return Path{}, fmt.Errorf("%w: kind %v", ErrInvalidDoc, d.Kind)
	}
	date := d.Date.UTC()
	v := values{
		date:     date,
		year:     strconv.Itoa(date.Year()),
		provider: Slug(d.Provider),
		category: Slug(d.Category),
		kind:     kind,
		amount:   formatAmount(d.AmountCents, d.Currency),
		ref:      Slug(d.Ref),
	}
	if v.category == "" {
		v.category = defaultCategory
	}

	stem := n.file.render(&v)
	if stem == "" {
		return Path{}, fmt.Errorf("%w: empty file name", ErrInvalidDoc)
	}
	suffix := ""
	if d.Version >= 2 {
		suffix = "_v" + strconv.Itoa(d.Version)
	}
	if ext := normalizeExt(d.Ext); ext != "" {
		suffix += "." + ext
	}
	if room := fsx.MaxNameLen - len(suffix); len(stem) > room {
		// The stem is ASCII (slugs, digits, amount, literals): cutting on a
		// byte is cutting on a rune.
		stem = strings.TrimRight(stem[:max(room, 0)], "_-")
		if stem == "" {
			return Path{}, fmt.Errorf("%w: file name too long", ErrInvalidDoc)
		}
	}
	file := fsx.SafeName(stem + suffix)

	segs := make([]string, 0, len(n.dir))
	for _, s := range n.dir {
		seg := s.render(&v)
		if len(seg) > fsx.MaxNameLen {
			seg = strings.TrimRight(seg[:fsx.MaxNameLen], "_-")
		}
		if seg == "" {
			continue
		}
		segs = append(segs, fsx.SafeName(seg))
	}
	return Path{Dir: strings.Join(segs, "/"), File: file}, nil
}
