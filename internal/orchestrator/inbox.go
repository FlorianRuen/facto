package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/FlorianRuen/facto/internal/inbox"
	"github.com/FlorianRuen/facto/internal/normalize"
)

// InboxSourceName is the DocResult and Warning source of inbox items.
const InboxSourceName = "inbox"

// ReasonNotRemoved is the Warning reason of an inbox file that was filed
// (or recognized as a duplicate) but could not be removed from the inbox.
const ReasonNotRemoved = "not-removed"

// InboxResult is the outcome of IngestInbox.
type InboxResult struct {
	Documents []DocResult
	Warnings  []Warning
}

// IngestInbox scans src and ingests every item in order (Source "inbox",
// Origin = item path, ProviderID = item.Doc.Ref). An item is Done (removed)
// only after StatusFiled (Put AND Insert succeeded) or
// StatusSkippedDuplicate; every other status leaves the file. A Done failure
// keeps the document's status and adds a ReasonNotRemoved warning. An item
// that changed since the scan (at Open or while read) is StatusChanged. A
// per-item failure does not stop the loop; a canceled ctx does (the error
// wraps ctx.Err()); an item filed as ctx is canceled is kept, not removed.
// Scan warnings are reported with Source "inbox".
func (o *Orchestrator) IngestInbox(ctx context.Context, src InboxSource) (InboxResult, error) {
	var out InboxResult
	if err := ctx.Err(); err != nil {
		return out, fmt.Errorf("ingest inbox: %w", err)
	}
	scan, err := src.Scan(ctx)
	if err != nil {
		return out, fmt.Errorf("ingest inbox: scan: %w", err)
	}
	for _, w := range scan.Warnings {
		out.Warnings = append(out.Warnings, Warning{Source: InboxSourceName, Path: w.Path, Reason: string(w.Reason)})
	}
	for _, it := range scan.Items {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("ingest inbox: %w", err)
		}
		res, warn := o.ingestItem(ctx, src, it)
		out.Documents = append(out.Documents, res)
		if warn != nil {
			out.Warnings = append(out.Warnings, *warn)
		}
	}
	if err := ctx.Err(); err != nil {
		return out, fmt.Errorf("ingest inbox: %w", err)
	}
	return out, nil
}

// ingestItem files one inbox item and removes it when it is safely filed.
func (o *Orchestrator) ingestItem(ctx context.Context, src InboxSource, it inbox.Item) (DocResult, *Warning) {
	in := Input{
		Source:     InboxSourceName,
		Origin:     it.Path,
		ProviderID: it.Doc.Ref,
		Doc:        it.Doc,
	}
	rc, err := src.Open(ctx, it)
	if err != nil {
		res := DocResult{
			Source:     in.Source,
			Origin:     in.Origin,
			ProviderID: in.ProviderID,
			Provider:   normalize.Slug(it.Doc.Provider),
			Status:     StatusFailed,
		}
		if errors.Is(err, inbox.ErrChanged) {
			res.Status = StatusChanged
		}
		o.logFailure(ctx, res, fmt.Errorf("ingest inbox: open: %w", err))
		return res, nil
	}
	in.Content = rc
	res, ierr := o.Ingest(ctx, in)
	// Ingest has read everything it needs; a close error changes nothing.
	_ = rc.Close()
	if ierr != nil && res.Status == StatusFailed && errors.Is(ierr, inbox.ErrChanged) {
		// The file changed while it was being read: same as at Open.
		res.Status = StatusChanged
	}
	if ierr != nil || (res.Status != StatusFiled && res.Status != StatusSkippedDuplicate) {
		return res, nil
	}
	if ctx.Err() != nil {
		// Canceled after filing: keep the inbox file; the next run sees it
		// as a duplicate and removes it then.
		return res, nil
	}
	if err := src.Done(ctx, it); err != nil {
		o.log.LogAttrs(ctx, slog.LevelWarn, "inbox file filed but not removed",
			slog.String("origin", it.Path),
			slog.String("status", string(res.Status)),
			slog.Any("error", err))
		return res, &Warning{Source: InboxSourceName, Path: it.Path, Reason: ReasonNotRemoved}
	}
	return res, nil
}
