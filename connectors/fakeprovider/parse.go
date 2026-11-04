package fakeprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
)

// maxAbsCents bounds |amount_cents| (one million euros).
const maxAbsCents = 100_000_000

// pdfMime is the only document type the site serves.
const pdfMime = "application/pdf"

// wirePage is one /api/invoices answer. Pointers and RawMessage tell a
// missing or null member from an empty one.
type wirePage struct {
	Invoices *[]wireItem     `json:"invoices"`
	NextPage json.RawMessage `json:"next_page"`
}

type wireItem struct {
	ID          string  `json:"id"`
	Contract    string  `json:"contract"`
	IssuedAt    string  `json:"issued_at"`
	PeriodStart *string `json:"period_start"`
	PeriodEnd   *string `json:"period_end"`
	AmountCents *int64  `json:"amount_cents"`
	Currency    *string `json:"currency"`
}

// wireMe is the /api/me answer.
type wireMe struct {
	Account string `json:"account"`
}

func newStrictDecoder(r io.Reader) *json.Decoder {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	return dec
}

// jsonError describes a decoding failure without the decoder's message,
// which may quote body values or unknown member names. A body cap hit keeps
// httpx.ErrBodyTooLarge in the chain; a read error keeps its (httpx
// sanitized) chain.
func jsonError(err error) error {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.Is(err, httpx.ErrBodyTooLarge):
		return fmt.Errorf("body over the size cap: %w", httpx.ErrBodyTooLarge)
	case errors.As(err, &syn):
		return fmt.Errorf("malformed JSON at offset %d", syn.Offset)
	case errors.As(err, &typ):
		// Field is a path through this package's wire types, never body data.
		return fmt.Errorf("JSON member %q has the wrong type", typ.Field)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return errors.New("empty or truncated JSON")
	case strings.HasPrefix(err.Error(), "json: "):
		return errors.New("unknown or invalid JSON member")
	default:
		return fmt.Errorf("read body: %w", err)
	}
}

// parsePage validates one list page. It returns the page items (not yet
// filtered by period) and the next page number, 0 for none. Errors name
// item indexes and JSON members, never their values.
func parsePage(r io.Reader) ([]wireItem, int, error) {
	var p wirePage
	if err := decodeStrict(r, &p); err != nil {
		return nil, 0, err
	}
	if p.Invoices == nil {
		return nil, 0, errors.New(`"invoices" missing or null`)
	}
	next := 0
	switch s := string(bytes.TrimSpace(p.NextPage)); s {
	case "":
		return nil, 0, errors.New(`"next_page" missing`)
	case "null":
	default:
		if err := json.Unmarshal(p.NextPage, &next); err != nil || next < 1 {
			return nil, 0, errors.New(`"next_page" is not a page number`)
		}
	}
	return *p.Invoices, next, nil
}

// parseDate parses a strict YYYY-MM-DD date, in UTC.
func parseDate(s string) (time.Time, bool) {
	if !dateRe.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// toRef validates one item and converts it. Errors name the member only.
func toRef(it wireItem) (connector.DocumentRef, error) {
	if !idRe.MatchString(it.ID) {
		return connector.DocumentRef{}, errors.New(`invalid "id"`)
	}
	if !contractRe.MatchString(it.Contract) {
		return connector.DocumentRef{}, errors.New(`invalid "contract"`)
	}
	issued, ok := parseDate(it.IssuedAt)
	if !ok {
		return connector.DocumentRef{}, errors.New(`invalid "issued_at"`)
	}
	ref := connector.DocumentRef{
		ProviderID: it.ID,
		Contract:   it.Contract,
		Kind:       connector.Invoice,
		IssuedAt:   issued,
		MimeType:   pdfMime,
	}
	switch {
	case it.PeriodStart == nil && it.PeriodEnd == nil:
	case it.PeriodStart == nil || it.PeriodEnd == nil:
		return connector.DocumentRef{}, errors.New(`"period_start" and "period_end" go together`)
	default:
		start, ok1 := parseDate(*it.PeriodStart)
		end, ok2 := parseDate(*it.PeriodEnd)
		if !ok1 || !ok2 || end.Before(start) {
			return connector.DocumentRef{}, errors.New(`invalid "period_start"/"period_end"`)
		}
		ref.PeriodStart, ref.PeriodEnd = start, end
	}
	if it.Currency != nil {
		if !currencyRe.MatchString(*it.Currency) {
			return connector.DocumentRef{}, errors.New(`invalid "currency"`)
		}
		ref.Currency = *it.Currency
	}
	if it.AmountCents != nil {
		a := *it.AmountCents
		if a > maxAbsCents || a < -maxAbsCents {
			return connector.DocumentRef{}, errors.New(`"amount_cents" over the cap`)
		}
		if it.Currency == nil {
			return connector.DocumentRef{}, errors.New(`"amount_cents" without "currency"`)
		}
		ref.AmountCents = &a
	}
	return ref, nil
}
