package wecasa

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/secret"
)

// Token block of the bookings page: window.wecasa = { token: '...', ... }.
var (
	blockRe    = regexp.MustCompile(`window\.wecasa\s*=\s*\{`)
	tokenKeyRe = regexp.MustCompile(`(?:^|[\s,{])token\s*:\s*`)
	tokenRe    = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{16,512}$`)
)

// parseToken returns the API token of the bookings page. It reads only
// inside the single window.wecasa = { ... } block: the value of its one
// token member, single- or double-quoted, of the strict token charset. No
// block, no token member or an empty token wraps ErrNeedsLogin (the
// session is gone); an ambiguous block or a token of another shape wraps
// ErrBroken. Errors never quote the page. The returned Secret owns a fresh
// copy: the caller may clear page.
func parseToken(page []byte) (secret.Secret, error) {
	blocks := blockRe.FindAllIndex(page, 2)
	switch len(blocks) {
	case 0:
		return secret.Secret{}, fmt.Errorf("%w: no window.wecasa block in the page", connector.ErrNeedsLogin)
	case 2:
		return secret.Secret{}, fmt.Errorf("%w: several window.wecasa blocks in the page", connector.ErrBroken)
	}
	body := page[blocks[0][1]:]
	end := bytes.IndexByte(body, '}')
	if end < 0 {
		return secret.Secret{}, fmt.Errorf("%w: window.wecasa block not closed", connector.ErrBroken)
	}
	body = body[:end]
	keys := tokenKeyRe.FindAllIndex(body, 2)
	switch len(keys) {
	case 0:
		return secret.Secret{}, fmt.Errorf("%w: no token in the window.wecasa block", connector.ErrNeedsLogin)
	case 2:
		return secret.Secret{}, fmt.Errorf("%w: several tokens in the window.wecasa block", connector.ErrBroken)
	}
	rest := body[keys[0][1]:]
	if len(rest) == 0 || (rest[0] != '\'' && rest[0] != '"') {
		return secret.Secret{}, fmt.Errorf("%w: token in the window.wecasa block is not a quoted string", connector.ErrBroken)
	}
	closing := bytes.IndexByte(rest[1:], rest[0])
	if closing < 0 {
		return secret.Secret{}, fmt.Errorf("%w: token in the window.wecasa block is not terminated", connector.ErrBroken)
	}
	val := rest[1 : 1+closing]
	if len(val) == 0 {
		return secret.Secret{}, fmt.Errorf("%w: empty token in the window.wecasa block", connector.ErrNeedsLogin)
	}
	if !tokenRe.Match(val) {
		return secret.Secret{}, fmt.Errorf("%w: token in the window.wecasa block has an unexpected shape", connector.ErrBroken)
	}
	return secret.New(bytes.Clone(val)), nil
}

// wireBooking is one item of GET /api/v1/customer/bookings/delivered.
// Only the members the connector reads; others are ignored.
type wireBooking struct {
	PublicID    string `json:"public_id"`
	Appointment string `json:"appointment"`
	Stage       string `json:"stage"`
	Type        string `json:"type"`
}

// wireOrder is GET /api/v1/customer/orders/<id>. Pointers and RawMessage
// tell a missing or null member from a zero one.
type wireOrder struct {
	Success *bool `json:"success"`
	Data    *struct {
		PublicID   string          `json:"public_id"`
		Invoices   *bool           `json:"invoices"`
		TotalPrice json.RawMessage `json:"total_price"`
		Currency   *string         `json:"currency"`
	} `json:"data"`
}

// wireUser is GET /api/v1/user, public_id only.
type wireUser struct {
	PublicID string `json:"public_id"`
}

// decode decodes exactly one JSON value from r into v; unknown members
// are ignored (the payloads carry many), trailing data is refused. Errors
// never carry the decoder's message (it may quote body values); a body cap
// hit keeps httpx.ErrBodyTooLarge in the chain.
func decode(r io.Reader, v any) error {
	dec := json.NewDecoder(r)
	if err := dec.Decode(v); err != nil {
		return jsonError(err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return jsonError(err)
		}
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

// jsonError describes a decoding failure without the decoder's message.
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
		return errors.New("invalid JSON value")
	default:
		return fmt.Errorf("read body: %w", err)
	}
}

// invoiced reports whether b is an invoiced order: type "order", stage
// "Done". Other items are skipped without validation.
func (b wireBooking) invoiced() bool {
	return b.Type == "order" && b.Stage == "Done"
}

// issuedAt validates the id and the appointment of an invoiced booking.
// Errors name the member, never its value.
func (b wireBooking) issuedAt() (time.Time, error) {
	if !idRe.MatchString(b.PublicID) {
		return time.Time{}, errors.New(`invalid "public_id"`)
	}
	t, err := time.Parse(time.RFC3339, b.Appointment)
	if err != nil {
		return time.Time{}, errors.New(`invalid "appointment"`)
	}
	return t.UTC(), nil
}

// orderAmount validates an order answer for id. It reports whether the
// order has an invoice and its amount (nil when the order has no price).
// Errors name the member, never its value.
func orderAmount(o wireOrder, id string) (bool, *int64, string, error) {
	if o.Success == nil || !*o.Success {
		return false, nil, "", errors.New(`"success" is not true`)
	}
	d := o.Data
	if d == nil {
		return false, nil, "", errors.New(`"data" missing or null`)
	}
	if d.PublicID != id {
		return false, nil, "", errors.New(`"public_id" is not the listed order`)
	}
	if d.Invoices == nil {
		return false, nil, "", errors.New(`"invoices" missing or null`)
	}
	if !*d.Invoices {
		return false, nil, "", nil
	}
	raw := string(bytes.TrimSpace(d.TotalPrice))
	if raw == "" || raw == "null" {
		return true, nil, "", nil
	}
	cents, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || cents < 0 || cents > maxAbsCents {
		return false, nil, "", errors.New(`invalid "total_price" (integer cents expected)`)
	}
	if d.Currency == nil || !currencyRe.MatchString(*d.Currency) {
		return false, nil, "", errors.New(`invalid "currency"`)
	}
	return true, &cents, *d.Currency, nil
}
