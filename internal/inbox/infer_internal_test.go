package inbox

import (
	"testing"
	"time"
)

func TestDateInName(t *testing.T) {
	t.Parallel()
	d := func(s string) time.Time {
		v, err := time.Parse(time.DateOnly, s)
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
		return v
	}
	tests := []struct {
		name string
		want time.Time
	}{
		{"avis-2026-10-02.pdf", d("2026-10-02")},
		{"2026-10-02", d("2026-10-02")},
		{"2024-02-29 leap.pdf", d("2024-02-29")},
		{"2026-03-14-copie-2026-03-14.pdf", d("2026-03-14")},
		{"x2026-03-14y", d("2026-03-14")},
		{"2025-02-29.pdf", time.Time{}},              // not a leap year
		{"2026-13-01.pdf", time.Time{}},              // month 13
		{"du-2026-01-01-au-2026-02-01", time.Time{}}, // ambiguous
		{"12026-03-14.pdf", time.Time{}},             // glued digit before
		{"2026-03-145.pdf", time.Time{}},             // glued digit after
		{"2026_03_14.pdf", time.Time{}},              // wrong separator
		{"2026-3-14.pdf", time.Time{}},               // not zero-padded
		{"", time.Time{}},
		{"short", time.Time{}},
	}
	for _, tt := range tests {
		if got := dateInName(tt.name); !got.Equal(tt.want) {
			t.Errorf("dateInName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
