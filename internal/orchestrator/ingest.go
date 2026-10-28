package orchestrator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/dest"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/store"
)

// localDest is the Name() of the local destination: its RemoteRef.ID is the
// path under the output folder, indexed as LocalPath.
const localDest = "local"

// Input is one downloaded or dropped document.
type Input struct {
	Source      string        // "inbox" or the connector id; reported
	Origin      string        // inbox item path; "" for connectors; reported
	ProviderID  string        // dedup key; "" = none (never versioned)
	Doc         normalize.Doc // naming metadata; Version is ignored (dedup decides)
	PeriodStart time.Time     // optional, indexed
	PeriodEnd   time.Time     // optional, indexed
	Content     io.Reader
}

// Ingest reads Content (at most MaxSize bytes, else ErrTooLarge), hashes it,
// applies normalize.Decide with provider = normalize.Slug(Doc.Provider),
// renders the path with Doc.Version set to the decided version, Puts it, then
// Inserts the index row. The DocResult status is always set; the error is nil
// only for StatusFiled and StatusSkippedDuplicate. A document is validated
// (non-empty provider slug, renderable) before anything is written. No error
// text, file content or secret ever lands in a DocResult; failures are logged
// through the redacting logger.
func (o *Orchestrator) Ingest(ctx context.Context, in Input) (DocResult, error) {
	res := DocResult{
		Source:     in.Source,
		Origin:     in.Origin,
		Provider:   normalize.Slug(in.Doc.Provider),
		ProviderID: in.ProviderID,
	}
	err := o.ingest(ctx, in, &res)
	if err != nil {
		o.logFailure(ctx, res, err)
	}
	return res, err
}

// ingest runs the pipeline, setting res.Status (and Version, Path) as it
// goes. It returns nil only for StatusFiled and StatusSkippedDuplicate.
func (o *Orchestrator) ingest(ctx context.Context, in Input, res *DocResult) error {
	res.Status = StatusFailed
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("ingest: %w", err)
	}

	doc := in.Doc
	doc.Version = 1
	if res.Provider == "" {
		res.Status = StatusInvalid
		return fmt.Errorf("ingest: %w: provider has no slug", ErrInvalidDoc)
	}
	if _, err := o.namer.Render(doc); err != nil {
		res.Status = StatusInvalid
		return fmt.Errorf("ingest: %w: %w", ErrInvalidDoc, err)
	}

	data, err := o.read(in.Content)
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			res.Status = StatusTooLarge
		}
		return err
	}
	sum := sha256.Sum256(data)

	ref := connector.DocumentRef{
		ProviderID:  in.ProviderID,
		Kind:        doc.Kind,
		IssuedAt:    doc.Date,
		PeriodStart: in.PeriodStart,
		PeriodEnd:   in.PeriodEnd,
		AmountCents: doc.AmountCents,
		Currency:    doc.Currency,
	}
	dec, err := normalize.Decide(ctx, o.idx, res.Provider, ref, sum)
	if err != nil {
		return fmt.Errorf("ingest: dedup: %w", err)
	}
	switch dec.Action {
	case normalize.SkipSameHash:
		res.Status = StatusSkippedDuplicate
		return nil
	case normalize.SkipKnownID:
		// Decide does not return it today (rule 1 is the connector
		// loop's); report it as the skip it is.
		res.Status = StatusSkippedKnownID
		return nil
	case normalize.New, normalize.NewVersion:
	default:
		return fmt.Errorf("ingest: unexpected dedup action %v", dec.Action)
	}

	doc.Version = dec.Version
	p, err := o.namer.Render(doc)
	if err != nil {
		res.Status = StatusInvalid
		return fmt.Errorf("ingest: %w: %w", ErrInvalidDoc, err)
	}
	res.Version = dec.Version

	return o.file(ctx, in, doc, p, sum, data, res)
}

// file Puts data at p, then indexes it.
func (o *Orchestrator) file(ctx context.Context, in Input, doc normalize.Doc, p normalize.Path, sum [32]byte, data []byte, res *DocResult) error {
	rref, putErr := o.dst.Put(ctx, dest.NormalizedDoc{Doc: doc, Path: p}, bytes.NewReader(data))
	notDurable := false
	switch {
	case putErr == nil:
	case errors.Is(putErr, dest.ErrExists):
		res.Status = StatusExists
		res.Path = p.Rel()
		return fmt.Errorf("ingest: put: %w", putErr)
	case errors.Is(putErr, fsx.ErrNotDurable):
		// Published, but the directory entry may not survive a crash: index
		// it anyway, or every later run would hit ErrExists.
		notDurable = true
	default:
		return fmt.Errorf("ingest: put: %w", putErr)
	}

	row := store.Document{
		Provider:    res.Provider,
		ProviderID:  in.ProviderID,
		Kind:        doc.Kind,
		IssuedAt:    doc.Date,
		PeriodStart: in.PeriodStart,
		PeriodEnd:   in.PeriodEnd,
		AmountCents: doc.AmountCents,
		Currency:    doc.Currency,
		SHA256:      sum,
		Version:     doc.Version,
	}
	id := rref.ID
	if o.dst.Name() == localDest {
		if id == "" {
			id = p.Rel()
		}
		row.LocalPath = id
	} else {
		row.DriveID = id
	}
	if _, err := o.idx.Insert(ctx, row); err != nil {
		o.log.LogAttrs(ctx, slog.LevelError, "document stored but not indexed: the destination file exists unindexed and will clash on the next run",
			slog.String("source", res.Source),
			slog.String("provider", res.Provider),
			slog.String("destination", o.dst.Name()),
			slog.String("path", p.Rel()),
			slog.Any("error", err))
		return fmt.Errorf("ingest: index: %w", err)
	}

	res.Path = p.Rel()
	if notDurable {
		res.Status = StatusNotDurable
		return fmt.Errorf("ingest: put: %w", putErr)
	}
	res.Status = StatusFiled
	return nil
}

// read reads r fully, refusing more than maxSize bytes.
func (o *Orchestrator) read(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, errors.New("ingest: no content")
	}
	data, err := io.ReadAll(io.LimitReader(r, o.maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("ingest: read: %w", err)
	}
	if int64(len(data)) > o.maxSize {
		return nil, fmt.Errorf("ingest: %w (limit %d bytes)", ErrTooLarge, o.maxSize)
	}
	return data, nil
}

// logFailure logs a non-filed document. The error goes through the
// redacting handler; the DocResult never carries it.
func (o *Orchestrator) logFailure(ctx context.Context, res DocResult, err error) {
	o.log.LogAttrs(ctx, slog.LevelWarn, "document not filed",
		slog.String("source", res.Source),
		slog.String("origin", res.Origin),
		slog.String("provider", res.Provider),
		slog.String("status", string(res.Status)),
		slog.Any("error", err))
}
