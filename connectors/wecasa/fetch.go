package wecasa

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
)

// pdfMagic starts every PDF, at offset 0.
var pdfMagic = []byte("%PDF-")

// Fetch streams the invoice PDF of one order. ref.ProviderID is
// re-validated before any request. The answer must be application/pdf and
// start with "%PDF-" (else connector.ErrBroken). A declared Content-Length
// over MaxPDFBytes fails before reading (ErrBroken and
// httpx.ErrBodyTooLarge); an undeclared oversized body fails the read with
// httpx.ErrBodyTooLarge, never silently truncated. The caller closes the
// reader.
func (c *Connector) Fetch(ctx context.Context, s connector.Session, ref connector.DocumentRef) (io.ReadCloser, error) {
	sess, err := sessionOf(s)
	if err != nil {
		return nil, fmt.Errorf("wecasa: fetch: %w", err)
	}
	if !idRe.MatchString(ref.ProviderID) {
		return nil, errors.New("wecasa: fetch: invalid provider id")
	}
	path := pathOrders + ref.ProviderID + pathInvoice
	r, err := sess.api(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("wecasa: fetch: %w", err)
	}
	body, err := c.checkPDF(path, r)
	if err != nil {
		_ = r.body.Close()
		return nil, fmt.Errorf("wecasa: fetch: %w", err)
	}
	return body, nil
}

// checkPDF validates the headers and the magic bytes and returns the capped
// body, magic bytes included.
func (c *Connector) checkPDF(path string, r reply) (io.ReadCloser, error) {
	body, err := capped(path, r, mimePDF, c.opts.MaxPDFBytes)
	if err != nil {
		return nil, err
	}
	head := make([]byte, len(pdfMagic))
	if _, err := io.ReadFull(body, head); err != nil {
		if errors.Is(err, httpx.ErrBodyTooLarge) {
			return nil, fmt.Errorf("%w: %s: %w", connector.ErrBroken, path, err)
		}
		return nil, fmt.Errorf("%w: %s: body shorter than the PDF header", connector.ErrBroken, path)
	}
	if !bytes.Equal(head, pdfMagic) {
		return nil, fmt.Errorf("%w: %s: body is not a PDF", connector.ErrBroken, path)
	}
	return &pdfBody{Reader: io.MultiReader(bytes.NewReader(head), body), closer: body}, nil
}

// pdfBody replays the checked header, then streams the capped body.
type pdfBody struct {
	io.Reader
	closer io.Closer
}

func (b *pdfBody) Close() error {
	if err := b.closer.Close(); err != nil {
		return fmt.Errorf("wecasa: close pdf: %w", err)
	}
	return nil
}

// Probe checks the session is still valid: GET /api/v1/user with the
// bearer token answers 200 with a non-empty "public_id". A 401 or a
// landing on the login page wraps connector.ErrNeedsLogin; other statuses
// map like List.
func (c *Connector) Probe(ctx context.Context, s connector.Session) error {
	sess, err := sessionOf(s)
	if err != nil {
		return fmt.Errorf("wecasa: probe: %w", err)
	}
	r, err := sess.api(ctx, pathUser)
	if err != nil {
		return fmt.Errorf("wecasa: probe: %w", err)
	}
	defer func() { _ = r.body.Close() }()
	body, err := capped(pathUser, r, mimeJSON, maxProbeBytes)
	if err != nil {
		return fmt.Errorf("wecasa: probe: %w", err)
	}
	var u wireUser
	if err := decode(body, &u); err != nil {
		return fmt.Errorf("%w: wecasa: probe: %s: %w", connector.ErrBroken, pathUser, err)
	}
	if u.PublicID == "" {
		return fmt.Errorf("%w: wecasa: probe: %s: empty public_id", connector.ErrBroken, pathUser)
	}
	return nil
}
