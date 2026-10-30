package fakeprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
)

const mePath = "/api/me"

// pdfMagic starts every PDF, at offset 0.
var pdfMagic = []byte("%PDF-")

// Fetch streams one invoice PDF. ref.ProviderID is re-validated before any
// request. The answer must be application/pdf and start with "%PDF-" (else
// connector.ErrBroken). A declared Content-Length over MaxPDFBytes fails
// with httpx.ErrBodyTooLarge and connector.ErrBroken (same classification
// as List) before reading; an undeclared oversized body
// fails the read with httpx.ErrBodyTooLarge, never silently truncated. The
// caller closes the reader.
func (c *Connector) Fetch(ctx context.Context, s connector.Session, ref connector.DocumentRef) (io.ReadCloser, error) {
	sess, err := sessionOf(s)
	if err != nil {
		return nil, fmt.Errorf("fakeprovider: fetch: %w", err)
	}
	if !idRe.MatchString(ref.ProviderID) {
		return nil, errors.New("fakeprovider: fetch: invalid provider id")
	}
	path := listPath + "/" + ref.ProviderID + "/pdf"
	r, err := sess.get(ctx, path, nil)
	if err != nil {
		return nil, fmt.Errorf("fakeprovider: fetch: %w", err)
	}
	body, err := c.checkPDF(path, r)
	if err != nil {
		_ = r.body.Close()
		return nil, fmt.Errorf("fakeprovider: fetch: %w", err)
	}
	return body, nil
}

// checkPDF validates the headers and the magic bytes and returns the capped
// body, magic bytes included.
func (c *Connector) checkPDF(path string, r reply) (io.ReadCloser, error) {
	if r.ctype != pdfMime {
		return nil, fmt.Errorf("%w: %s: content type is not %s", connector.ErrBroken, path, pdfMime)
	}
	if r.length > c.opts.MaxPDFBytes {
		return nil, fmt.Errorf("%w: %s: declared length over %d bytes: %w", connector.ErrBroken, path, c.opts.MaxPDFBytes, httpx.ErrBodyTooLarge)
	}
	body := httpx.LimitBody(r.body, c.opts.MaxPDFBytes)
	head := make([]byte, len(pdfMagic))
	if _, err := io.ReadFull(body, head); err != nil {
		if errors.Is(err, httpx.ErrBodyTooLarge) {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return nil, fmt.Errorf("%w: %s: body shorter than the PDF header", connector.ErrBroken, path)
	}
	if string(head) != string(pdfMagic) {
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
		return fmt.Errorf("fakeprovider: close pdf: %w", err)
	}
	return nil
}

// Probe checks the session is still valid: GET https://www.fakeprovider.test/api/me
// answers 200 with {"account": "..."}. A 401 or a landing on the SSO login
// page wraps connector.ErrNeedsLogin; other statuses map like List.
func (c *Connector) Probe(ctx context.Context, s connector.Session) error {
	sess, err := sessionOf(s)
	if err != nil {
		return fmt.Errorf("fakeprovider: probe: %w", err)
	}
	r, err := sess.get(ctx, mePath, nil)
	if err != nil {
		return fmt.Errorf("fakeprovider: probe: %w", err)
	}
	defer func() { _ = r.body.Close() }()
	if r.ctype != "application/json" {
		return fmt.Errorf("%w: fakeprovider: probe: %s: content type is not application/json", connector.ErrBroken, mePath)
	}
	var me wireMe
	if err := decodeStrict(httpx.LimitBody(r.body, maxProbeBytes), &me); err != nil {
		return fmt.Errorf("%w: fakeprovider: probe: %s: %w", connector.ErrBroken, mePath, err)
	}
	if me.Account == "" {
		return fmt.Errorf("%w: fakeprovider: probe: %s: empty account", connector.ErrBroken, mePath)
	}
	return nil
}
