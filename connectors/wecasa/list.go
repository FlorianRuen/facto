package wecasa

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
)

// API paths (docs/connectors/wecasa.md).
const (
	pathDelivered = "/api/v1/customer/bookings/delivered"
	pathOrders    = "/api/v1/customer/orders/"
	pathUser      = "/api/v1/user"
	pathInvoice   = "/download_invoices"
)

// listed is one invoiced order of the delivered list.
type listed struct {
	id     string
	issued time.Time
}

// List returns one invoice per delivered order ("type": "order", "stage":
// "Done") whose appointment, in UTC, is in p and whose details say it has
// an invoice. Order details are fetched only for those orders. The list
// has no pagination. Malformed answers, a duplicate id and every cap wrap
// connector.ErrBroken (a body cap also httpx.ErrBodyTooLarge). On error
// the result is nil. Errors never echo body values.
func (c *Connector) List(ctx context.Context, s connector.Session, p connector.Period) ([]connector.DocumentRef, error) {
	sess, err := sessionOf(s)
	if err != nil {
		return nil, fmt.Errorf("wecasa: list: %w", err)
	}
	if !p.Start.Before(p.End) {
		return nil, errors.New("wecasa: list: empty or reversed period")
	}
	orders, err := c.delivered(ctx, sess, p)
	if err != nil {
		return nil, fmt.Errorf("wecasa: list: %w", err)
	}
	refs := []connector.DocumentRef{}
	for _, o := range orders {
		ref, ok, err := c.detail(ctx, sess, o)
		if err != nil {
			return nil, fmt.Errorf("wecasa: list: %w", err)
		}
		if ok {
			refs = append(refs, ref)
		}
	}
	return refs, nil
}

// delivered fetches the delivered list and keeps the invoiced orders of p.
func (c *Connector) delivered(ctx context.Context, sess *Session, p connector.Period) ([]listed, error) {
	r, err := sess.api(ctx, pathDelivered)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.body.Close() }()
	body, err := capped(pathDelivered, r, mimeJSON, c.opts.MaxListBytes)
	if err != nil {
		return nil, err
	}
	var items *[]wireBooking
	if err := decode(body, &items); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", connector.ErrBroken, pathDelivered, err)
	}
	if items == nil {
		return nil, fmt.Errorf("%w: %s: not a JSON array", connector.ErrBroken, pathDelivered)
	}
	if len(*items) > c.opts.MaxItems {
		return nil, fmt.Errorf("%w: %s: more than %d items", connector.ErrBroken, pathDelivered, c.opts.MaxItems)
	}
	var out []listed
	seen := map[string]struct{}{}
	for i, it := range *items {
		if !it.invoiced() {
			continue
		}
		issued, err := it.issuedAt()
		if err != nil {
			return nil, fmt.Errorf("%w: %s: item %d: %w", connector.ErrBroken, pathDelivered, i, err)
		}
		if _, dup := seen[it.PublicID]; dup {
			return nil, fmt.Errorf("%w: %s: item %d: duplicate id", connector.ErrBroken, pathDelivered, i)
		}
		seen[it.PublicID] = struct{}{}
		if p.Contains(issued) {
			out = append(out, listed{id: it.PublicID, issued: issued})
		}
	}
	return out, nil
}

// detail fetches one order and returns its ref, or false when the order
// has no invoice.
func (c *Connector) detail(ctx context.Context, sess *Session, o listed) (connector.DocumentRef, bool, error) {
	path := pathOrders + o.id
	r, err := sess.api(ctx, path)
	if err != nil {
		return connector.DocumentRef{}, false, err
	}
	defer func() { _ = r.body.Close() }()
	body, err := capped(path, r, mimeJSON, c.opts.MaxListBytes)
	if err != nil {
		return connector.DocumentRef{}, false, err
	}
	var w wireOrder
	if err := decode(body, &w); err != nil {
		return connector.DocumentRef{}, false, fmt.Errorf("%w: %s: %w", connector.ErrBroken, path, err)
	}
	ok, cents, currency, err := orderAmount(w, o.id)
	if err != nil {
		return connector.DocumentRef{}, false, fmt.Errorf("%w: %s: %w", connector.ErrBroken, path, err)
	}
	if !ok {
		return connector.DocumentRef{}, false, nil
	}
	return connector.DocumentRef{
		ProviderID:  o.id,
		Kind:        connector.Invoice,
		IssuedAt:    o.issued,
		AmountCents: cents,
		Currency:    currency,
		MimeType:    mimePDF,
	}, true, nil
}
