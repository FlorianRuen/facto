package normalize_test

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/normalize"
)

// TestNewNamer_RejectsPlaceholderArguments: only {date} takes a layout, and
// a dir separator cannot hide inside an optional group.
func TestNewNamer_RejectsPlaceholderArguments(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cfg  normalize.Config
	}{
		{"argument on year", normalize.Config{File: "{year:2006}"}},
		{"empty date layout", normalize.Config{File: "{date:}"}},
		{"brace inside placeholder", normalize.Config{File: "{date:{ref}}"}},
		{"group inside placeholder", normalize.Config{File: "{date:[x]}"}},
		{"slash inside dir group", normalize.Config{Dir: "{year}[/{provider}]"}},
		{"empty dir segment from leading slash", normalize.Config{Dir: "/"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := normalize.NewNamer(tc.cfg); !errors.Is(err, normalize.ErrBadTemplate) {
				t.Fatalf("NewNamer(%+v) err = %v, want ErrBadTemplate", tc.cfg, err)
			}
		})
	}
}

// TestRender_ExtremeAmounts: the int64 bounds render without overflow and
// parse back.
func TestRender_ExtremeAmounts(t *testing.T) {
	t.Parallel()
	n := newNamer(t, normalize.Config{})
	for _, v := range []int64{math.MinInt64, math.MaxInt64, -1, 1} {
		d := normalize.Doc{Provider: "edf", Kind: connector.Invoice, Date: day(2026, time.March, 14), AmountCents: cents(v), Currency: "EUR", Ext: "pdf"}
		file := render(t, n, d).File
		got, err := normalize.ParseName(file)
		if err != nil {
			t.Fatalf("ParseName(%q): %v", file, err)
		}
		if got.AmountCents == nil || *got.AmountCents != v {
			t.Fatalf("amount %d rendered as %q parsed back as %v", v, file, deref(got.AmountCents))
		}
	}
}

// TestRender_LongDirSegmentIsCapped: a dir segment never exceeds
// fsx.MaxNameLen nor ends with a dangling hyphen.
func TestRender_LongDirSegmentIsCapped(t *testing.T) {
	t.Parallel()
	n := newNamer(t, normalize.Config{})
	p := render(t, n, normalize.Doc{
		Provider: strings.Repeat("ab ", 200), Category: "housing", Kind: connector.Invoice,
		Date: day(2026, time.March, 14), Ext: "pdf",
	})
	for _, seg := range strings.Split(p.Dir, "/") {
		if len(seg) > fsx.MaxNameLen || strings.HasSuffix(seg, "-") {
			t.Fatalf("segment %q (len %d) not capped cleanly", seg, len(seg))
		}
	}
}
