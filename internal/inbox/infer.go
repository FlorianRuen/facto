package inbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/normalize/facturx"
)

// pdfHeaderWindow is how far into a file the "%PDF-" header is looked for:
// PDF readers tolerate leading garbage up to about this offset.
const pdfHeaderWindow = 1024

// guess is what infer found out about one file.
type guess struct {
	doc            normalize.Doc
	source         Source // "" when no source identified anything
	identified     bool
	invalidFacturX bool
}

// infer identifies a file from its content, its base name and the provider
// id of its subfolder ("" at the inbox root), in the precedence order
// documented on Scan. Only a canceled ctx makes it fail.
func (ib *Inbox) infer(ctx context.Context, data []byte, base, subProvider string) (guess, error) {
	var g guess
	d := &g.doc

	inv, ok, err := facturX(ctx, data)
	switch {
	case err != nil && ctx.Err() != nil:
		return guess{}, fmt.Errorf("factur-x: %w", ctx.Err())
	case err != nil:
		g.invalidFacturX = true
	case ok:
		g.source = SourceFacturX
		d.Provider = normalize.Slug(inv.SellerName)
		d.Date = inv.IssueDate
		if inv.GrandTotalCents != nil {
			cents := *inv.GrandTotalCents
			d.AmountCents, d.Currency = &cents, inv.Currency
		}
		d.Ref = normalize.Slug(inv.Number)
		d.Kind = connector.Invoice
	}

	named, err := normalize.ParseName(base)
	nameOK := err == nil
	if nameOK {
		if g.source == "" {
			g.source = SourceName
		}
		fillFromName(d, named)
	}

	if subProvider != "" {
		if g.source == "" {
			g.source = SourceSubfolder
		}
		if d.Provider == "" {
			d.Provider = subProvider
		}
		if k := ib.providers[subProvider].Kind; d.Kind == 0 && validKind(k) {
			d.Kind = k
		}
	}

	if d.Date.IsZero() {
		d.Date = dateInName(base)
	}
	if d.Kind == 0 {
		d.Kind = connector.Invoice
	}
	d.Ext = strings.ToLower(strings.TrimPrefix(path.Ext(base), "."))
	d.Category = ib.providers[d.Provider].Category
	d.Version = 0
	g.identified = nameOK || (!d.Date.IsZero() && d.Provider != "")
	return g, nil
}

// facturX extracts the Factur-X invoice embedded in data. ok=false with a
// nil error means there is none to use (not a PDF, unreadable PDF, no
// attachment); an error means an attachment was found but refused, or ctx
// was canceled. The error text is never reported: it may quote file content.
func facturX(ctx context.Context, data []byte) (facturx.Invoice, bool, error) {
	if !bytes.Contains(data[:min(len(data), pdfHeaderWindow)], []byte("%PDF-")) {
		return facturx.Invoice{}, false, nil
	}
	inv, err := facturx.Extract(ctx, bytes.NewReader(data))
	switch {
	case err == nil:
		return inv, true, nil
	case ctx.Err() == nil && (errors.Is(err, facturx.ErrNoFacturX) || errors.Is(err, facturx.ErrInvalidPDF)):
		return facturx.Invoice{}, false, nil
	default:
		return facturx.Invoice{}, false, fmt.Errorf("extract: %w", err)
	}
}

// fillFromName completes d with the fields of a parsed compliant name that
// a higher-precedence source left empty.
func fillFromName(d *normalize.Doc, named normalize.Doc) {
	if d.Provider == "" {
		d.Provider = named.Provider
	}
	if d.Date.IsZero() {
		d.Date = named.Date
	}
	if d.AmountCents == nil && named.AmountCents != nil {
		d.AmountCents, d.Currency = named.AmountCents, named.Currency
	}
	if d.Ref == "" {
		d.Ref = named.Ref
	}
	if d.Kind == 0 {
		d.Kind = named.Kind
	}
}

// dateInName returns the only ISO date (YYYY-MM-DD, valid calendar date, not
// glued to other digits) found in name, at 00:00 UTC. No date, or two
// different dates, give the zero time: facto never guesses a date.
func dateInName(name string) time.Time {
	const n = len(time.DateOnly)
	var found time.Time
	for i := 0; i+n <= len(name); i++ {
		s := name[i : i+n]
		if !isoShape(s) || (i > 0 && isDigit(name[i-1])) || (i+n < len(name) && isDigit(name[i+n])) {
			continue
		}
		t, err := time.Parse(time.DateOnly, s)
		if err != nil {
			continue // shape right, calendar wrong (2026-02-30)
		}
		if !found.IsZero() && !found.Equal(t) {
			return time.Time{}
		}
		found = t
	}
	return found
}

// isoShape reports whether s looks like DDDD-DD-DD.
func isoShape(s string) bool {
	for i := range len(s) {
		if i == 4 || i == 7 {
			if s[i] != '-' {
				return false
			}
		} else if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

// validKind reports whether k is one of the known document kinds.
func validKind(k connector.DocKind) bool {
	_, err := k.MarshalText()
	return err == nil
}
