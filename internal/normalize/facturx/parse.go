// Package facturx reads the CII (Cross Industry Invoice) XML embedded in
// Factur-X / ZUGFeRD PDFs and extracts the header fields facto uses for
// naming: profile, type code, number, issue date, seller, currency and grand
// total.
//
// The input is untrusted. ParseCII caps its size, refuses every XML directive
// (so no DOCTYPE, no entity declaration, no external entity, no entity
// expansion bomb), only knows the five predefined XML entities, refuses
// encodings other than UTF-8 and matches elements by namespace URI along their
// exact path, never by prefix.
package facturx

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// MaxSize is the largest CII document ParseCII accepts, in bytes. Real
// Factur-X XML weighs a few KiB to a few hundred KiB.
const MaxSize = 4 << 20

// maxDepth caps element nesting; CII header paths are 6 levels deep and line
// items stay well under this.
const maxDepth = 64

var (
	// ErrTooLarge reports an input longer than MaxSize.
	ErrTooLarge = errors.New("facturx: document too large")
	// ErrUnsafeXML reports a directive (<!DOCTYPE …>, <!ENTITY …>) anywhere
	// in the document.
	ErrUnsafeXML = errors.New("facturx: unsafe xml (directive)")
	// ErrNotCII reports a root element other than rsm:CrossIndustryInvoice.
	ErrNotCII = errors.New("facturx: not a CII document")
	// ErrInvalid reports malformed XML or a malformed field value.
	ErrInvalid = errors.New("facturx: invalid document")
)

// Profile is the Factur-X profile declared by the guideline ID.
type Profile string

// Factur-X profiles.
const (
	ProfileMinimum  Profile = "minimum"
	ProfileBasicWL  Profile = "basicwl"
	ProfileBasic    Profile = "basic"
	ProfileEN16931  Profile = "en16931"
	ProfileExtended Profile = "extended"
)

var profiles = map[string]Profile{
	"urn:factur-x.eu:1p0:minimum":                                     ProfileMinimum,
	"urn:factur-x.eu:1p0:basicwl":                                     ProfileBasicWL,
	"urn:cen.eu:en16931:2017#compliant#urn:factur-x.eu:1p0:basic":     ProfileBasic,
	"urn:cen.eu:en16931:2017":                                         ProfileEN16931,
	"urn:cen.eu:en16931:2017#conformant#urn:factur-x.eu:1p0:extended": ProfileExtended,
}

// Invoice holds the header fields facto uses. A missing element leaves the
// zero value.
type Invoice struct {
	// Profile from ExchangedDocumentContext/GuidelineSpecifiedDocumentContextParameter/ID;
	// "" when missing or unrecognised.
	Profile Profile
	// TypeCode from ExchangedDocument/TypeCode ("380" invoice, "381" credit note…).
	TypeCode string
	// Number from ExchangedDocument/ID.
	Number string
	// IssueDate from ExchangedDocument/IssueDateTime/DateTimeString
	// (format 102, YYYYMMDD), UTC midnight.
	IssueDate time.Time
	// SellerName from ApplicableHeaderTradeAgreement/SellerTradeParty/Name.
	SellerName string
	// Currency from ApplicableHeaderTradeSettlement/InvoiceCurrencyCode.
	Currency string
	// GrandTotalCents from SpecifiedTradeSettlementHeaderMonetarySummation/GrandTotalAmount.
	GrandTotalCents *int64
}

const (
	nsRSM = "urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100"
	nsRAM = "urn:un:unece:uncefact:data:standard:ReusableAggregateBusinessInformationEntity:100"
	nsUDT = "urn:un:unece:uncefact:data:standard:UnqualifiedDataType:100"
)

// field identifies an extracted element.
type field int

const (
	fProfile field = iota + 1
	fTypeCode
	fNumber
	fIssueDate
	fSeller
	fCurrency
	fGrandTotal
)

// fieldPaths maps element paths below the root (namespace URIs abbreviated by
// nsTag) to fields.
var fieldPaths = map[string]field{
	"rsm:ExchangedDocumentContext/ram:GuidelineSpecifiedDocumentContextParameter/ram:ID":                                                           fProfile,
	"rsm:ExchangedDocument/ram:TypeCode":                                                                                                           fTypeCode,
	"rsm:ExchangedDocument/ram:ID":                                                                                                                 fNumber,
	"rsm:ExchangedDocument/ram:IssueDateTime/udt:DateTimeString":                                                                                   fIssueDate,
	"rsm:SupplyChainTradeTransaction/ram:ApplicableHeaderTradeAgreement/ram:SellerTradeParty/ram:Name":                                             fSeller,
	"rsm:SupplyChainTradeTransaction/ram:ApplicableHeaderTradeSettlement/ram:InvoiceCurrencyCode":                                                  fCurrency,
	"rsm:SupplyChainTradeTransaction/ram:ApplicableHeaderTradeSettlement/ram:SpecifiedTradeSettlementHeaderMonetarySummation/ram:GrandTotalAmount": fGrandTotal,
}

// nsTag abbreviates the CII namespaces; any other namespace gets a tag that
// no field path uses.
func nsTag(space string) string {
	switch space {
	case nsRSM:
		return "rsm"
	case nsRAM:
		return "ram"
	case nsUDT:
		return "udt"
	default:
		return "?"
	}
}

// ParseCII parses a CII document of at most MaxSize bytes. Errors wrap
// ErrTooLarge, ErrUnsafeXML, ErrNotCII, ErrInvalid or the reader's error; on
// error the returned Invoice is always the zero value.
//
// Parsing is fail-closed: a malformed value in any extracted field, even an
// optional one (an unparsable issue date or grand total, say), fails the whole
// parse with ErrInvalid instead of returning the other fields. Callers then
// fall back to the next naming source rather than file a half-read invoice.
func ParseCII(r io.Reader) (Invoice, error) {
	buf, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return Invoice{}, fmt.Errorf("facturx: read: %w", err)
	}
	if len(buf) > MaxSize {
		return Invoice{}, fmt.Errorf("%w: more than %d bytes", ErrTooLarge, MaxSize)
	}
	raw, err := scan(buf)
	if err != nil {
		return Invoice{}, err
	}
	inv, err := raw.invoice()
	if err != nil {
		return Invoice{}, err
	}
	return inv, nil
}

// rawFields holds the trimmed text of each field found (first occurrence).
type rawFields struct {
	text       map[field]string
	dateFormat string
}

// scan walks the token stream once, enforcing the safety rules, and collects
// the raw text of the wanted elements.
func scan(buf []byte) (rawFields, error) {
	d := xml.NewDecoder(bytes.NewReader(buf))
	d.Strict = true // undefined entities are errors; d.Entity stays nil
	raw := rawFields{text: map[field]string{}}

	var (
		stack    []string // element path below the root
		seenRoot bool
		inRoot   bool
		cur      field // field being read, 0 if none
		curDepth int
		text     strings.Builder
	)
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return rawFields{}, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			return rawFields{}, ErrUnsafeXML
		case xml.StartElement:
			if !inRoot {
				if seenRoot {
					return rawFields{}, fmt.Errorf("%w: content after the root element", ErrInvalid)
				}
				if t.Name.Space != nsRSM || t.Name.Local != "CrossIndustryInvoice" {
					return rawFields{}, ErrNotCII
				}
				seenRoot, inRoot = true, true
				continue
			}
			if len(stack) >= maxDepth {
				return rawFields{}, fmt.Errorf("%w: nesting deeper than %d", ErrInvalid, maxDepth)
			}
			stack = append(stack, nsTag(t.Name.Space)+":"+t.Name.Local)
			if cur != 0 {
				continue // nested element inside a field: its text is ignored
			}
			f, ok := fieldPaths[strings.Join(stack, "/")]
			if !ok {
				continue
			}
			if _, done := raw.text[f]; done {
				continue // first occurrence wins
			}
			cur, curDepth = f, len(stack)
			text.Reset()
			if f == fIssueDate {
				raw.dateFormat = attr(t, "format")
			}
		case xml.EndElement:
			// The decoder checks element balance: an end tag outside the
			// root cannot reach here.
			if len(stack) == 0 {
				inRoot = false
				continue
			}
			if cur != 0 && len(stack) == curDepth {
				raw.text[cur] = strings.TrimSpace(text.String())
				cur = 0
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if !inRoot {
				if len(bytes.TrimSpace(t)) > 0 {
					return rawFields{}, fmt.Errorf("%w: text outside the root element", ErrInvalid)
				}
				continue
			}
			if cur != 0 && len(stack) == curDepth {
				text.Write(t)
			}
		case xml.Comment, xml.ProcInst:
			// The decoder already rejects non-UTF-8 encoding declarations.
		}
	}
	if !seenRoot {
		return rawFields{}, fmt.Errorf("%w: no root element", ErrInvalid)
	}
	return raw, nil
}

func attr(t xml.StartElement, local string) string {
	for _, a := range t.Attr {
		if a.Name.Space == "" && a.Name.Local == local {
			return strings.TrimSpace(a.Value)
		}
	}
	return ""
}

var (
	currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)
	amountRe   = regexp.MustCompile(`^(-?)([0-9]+)(?:\.([0-9]+))?$`)
	date102Re  = regexp.MustCompile(`^[0-9]{8}$`)
)

// invoice validates and converts the raw fields.
func (raw rawFields) invoice() (Invoice, error) {
	var inv Invoice
	if v, ok := raw.text[fProfile]; ok {
		inv.Profile = profiles[v]
	}
	inv.TypeCode = raw.text[fTypeCode]
	inv.Number = raw.text[fNumber]
	inv.SellerName = raw.text[fSeller]
	if v, ok := raw.text[fIssueDate]; ok {
		d, err := parseDate102(raw.dateFormat, v)
		if err != nil {
			return Invoice{}, err
		}
		inv.IssueDate = d
	}
	if v, ok := raw.text[fCurrency]; ok {
		if !currencyRe.MatchString(v) {
			return Invoice{}, fmt.Errorf("%w: currency %q", ErrInvalid, v)
		}
		inv.Currency = v
	}
	if v, ok := raw.text[fGrandTotal]; ok {
		c, err := parseCents(v)
		if err != nil {
			return Invoice{}, err
		}
		inv.GrandTotalCents = &c
	}
	return inv, nil
}

func parseDate102(format, v string) (time.Time, error) {
	if format != "102" {
		return time.Time{}, fmt.Errorf("%w: issue date format %q, want 102", ErrInvalid, format)
	}
	if !date102Re.MatchString(v) {
		return time.Time{}, fmt.Errorf("%w: issue date %q", ErrInvalid, v)
	}
	d, err := time.ParseInLocation("20060102", v, time.UTC)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: issue date %q", ErrInvalid, v)
	}
	return d, nil
}

// parseCents converts a CII decimal amount to cents. At most two non-zero
// decimals are accepted; no exponent, no thousands separator, no '+'.
func parseCents(v string) (int64, error) {
	m := amountRe.FindStringSubmatch(v)
	if m == nil {
		return 0, fmt.Errorf("%w: amount %q", ErrInvalid, v)
	}
	sign, whole, frac := m[1], m[2], strings.TrimRight(m[3], "0")
	if len(frac) > 2 {
		return 0, fmt.Errorf("%w: amount %q has more than 2 decimals", ErrInvalid, v)
	}
	frac += strings.Repeat("0", 2-len(frac))
	c, err := strconv.ParseInt(sign+whole+frac, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: amount %q out of range", ErrInvalid, v)
	}
	return c, nil
}
