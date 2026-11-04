package fakeprovider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
)

const listPath = "/api/invoices"

// List returns the invoices issued in p, walking the pages from 1. Every
// malformed or oversized answer, a next_page other than page+1, a duplicate
// id, and every cap (body bytes, items, pages) wraps connector.ErrBroken; a
// body cap also matches httpx.ErrBodyTooLarge. Items issued outside p are
// dropped. On error the result is nil. Errors never echo body values.
func (c *Connector) List(ctx context.Context, s connector.Session, p connector.Period) ([]connector.DocumentRef, error) {
	sess, err := sessionOf(s)
	if err != nil {
		return nil, fmt.Errorf("fakeprovider: list: %w", err)
	}
	if !p.Start.Before(p.End) {
		return nil, errors.New("fakeprovider: list: empty or reversed period")
	}
	q := url.Values{
		"from": {p.Start.UTC().Format(time.DateOnly)},
		"to":   {p.End.UTC().Format(time.DateOnly)},
	}
	refs := []connector.DocumentRef{}
	seen := map[string]struct{}{}
	items := 0
	for page := 1; ; page++ {
		q.Set("page", strconv.Itoa(page))
		got, next, err := c.listPage(ctx, sess, q)
		if err != nil {
			return nil, fmt.Errorf("fakeprovider: list page %d: %w", page, err)
		}
		items += len(got)
		if items > c.opts.MaxItems {
			return nil, fmt.Errorf("%w: fakeprovider: list: more than %d items", connector.ErrBroken, c.opts.MaxItems)
		}
		for i, it := range got {
			ref, err := toRef(it)
			if err != nil {
				return nil, fmt.Errorf("%w: fakeprovider: list page %d item %d: %w", connector.ErrBroken, page, i, err)
			}
			if _, dup := seen[ref.ProviderID]; dup {
				return nil, fmt.Errorf("%w: fakeprovider: list page %d item %d: duplicate id", connector.ErrBroken, page, i)
			}
			seen[ref.ProviderID] = struct{}{}
			if p.Contains(ref.IssuedAt) {
				refs = append(refs, ref)
			}
		}
		switch {
		case next == 0:
			return refs, nil
		case next != page+1:
			return nil, fmt.Errorf("%w: fakeprovider: list page %d: next_page is not %d", connector.ErrBroken, page, page+1)
		case page >= c.opts.MaxPages:
			return nil, fmt.Errorf("%w: fakeprovider: list: more than %d pages", connector.ErrBroken, c.opts.MaxPages)
		}
	}
}

// listPage fetches and parses one page. Parse failures wrap ErrBroken.
func (c *Connector) listPage(ctx context.Context, sess *Session, q url.Values) ([]wireItem, int, error) {
	r, err := sess.get(ctx, listPath, q)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = r.body.Close() }()
	if r.ctype != "application/json" {
		return nil, 0, fmt.Errorf("%w: %s: content type is not application/json", connector.ErrBroken, listPath)
	}
	if r.length > c.opts.MaxListBytes {
		return nil, 0, fmt.Errorf("%w: %s: declared length over %d bytes: %w",
			connector.ErrBroken, listPath, c.opts.MaxListBytes, httpx.ErrBodyTooLarge)
	}
	items, next, err := parsePage(httpx.LimitBody(r.body, c.opts.MaxListBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %s: %w", connector.ErrBroken, listPath, err)
	}
	return items, next, nil
}
