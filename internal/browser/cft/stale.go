package cft

import (
	"context"
	"log/slog"

	"github.com/FlorianRuen/facto/internal/clock"
)

// WarnIfStale logs exactly one Warn record (naming m.Version) and returns
// true when clk.Now() is more than MaxPinAge after m.PinnedAt; otherwise it
// logs nothing and returns false. A nil log discards the record.
func WarnIfStale(ctx context.Context, log *slog.Logger, clk clock.Clock, m Manifest) bool {
	if clk.Now().Sub(m.PinnedAt) <= MaxPinAge {
		return false
	}
	if log != nil {
		log.WarnContext(ctx, "the pinned Chrome for Testing build is more than 4 weeks old: update facto",
			slog.String("version", m.Version),
			slog.String("pinned_at", m.PinnedAt.UTC().Format("2006-01-02")))
	}
	return true
}
