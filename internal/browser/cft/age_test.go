// Pin age tests (J1 task T11, ADR 0008 patching policy: "the pin is never
// more than 4 weeks behind. facto warns at run time when the pinned build is
// older"). See helpers_test.go for the expected API.
package cft_test

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/browser/cft"
	"github.com/FlorianRuen/facto/internal/clock"
)

// recorder is a slog.Handler keeping every record.
type recorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec.Clone())
	return nil
}

func (r *recorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *recorder) WithGroup(string) slog.Handler      { return r }

func (r *recorder) all() []slog.Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]slog.Record(nil), r.records...)
}

// render returns the message and every attribute value of rec.
func render(rec slog.Record) string {
	var b strings.Builder
	b.WriteString(rec.Message)
	rec.Attrs(func(a slog.Attr) bool {
		b.WriteString(" " + a.Key + "=" + a.Value.String())
		return true
	})
	return b.String()
}

func TestPinnedChrome_AgeWarning(t *testing.T) {
	t.Parallel()

	const day = 24 * time.Hour
	tests := []struct {
		name string
		age  time.Duration // clock.Now() - PinnedAt
		warn bool
	}{
		{name: "pinned today", age: 0},
		{name: "one week old", age: 7 * day},
		{name: "27 days old", age: 27 * day},
		{name: "exactly 4 weeks old", age: cft.MaxPinAge},
		{name: "4 weeks and one second", age: cft.MaxPinAge + time.Second, warn: true},
		{name: "29 days old", age: 29 * day, warn: true},
		{name: "one year old", age: 365 * day, warn: true},
		{name: "clock before the pin date", age: -day},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := validManifest()
			clk := clock.NewFake(m.PinnedAt.Add(tt.age))
			rec := &recorder{}

			got := cft.WarnIfStale(t.Context(), slog.New(rec), clk, m)
			if got != tt.warn {
				t.Fatalf("WarnIfStale() = %v, want %v", got, tt.warn)
			}
			records := rec.all()
			if !tt.warn {
				if len(records) != 0 {
					t.Fatalf("logged %d records, want none", len(records))
				}
				return
			}
			if len(records) != 1 {
				t.Fatalf("logged %d records, want exactly one warning", len(records))
			}
			if records[0].Level != slog.LevelWarn {
				t.Fatalf("level = %v, want WARN", records[0].Level)
			}
			if text := render(records[0]); !strings.Contains(text, m.Version) {
				t.Fatalf("warning %q does not name the pinned version %q", text, m.Version)
			}
		})
	}

	t.Run("max pin age is four weeks", func(t *testing.T) {
		t.Parallel()
		if cft.MaxPinAge != 28*day {
			t.Fatalf("MaxPinAge = %v, want 4 weeks (ADR 0008)", cft.MaxPinAge)
		}
	})
}
