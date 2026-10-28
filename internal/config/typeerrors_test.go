package config_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/config"
)

// TestLoad_TypeErrorsCapped: a document with many wrongly typed items
// reports the first 20 and counts the rest.
func TestLoad_TypeErrorsCapped(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		items int
		more  string // expected "and N more" suffix, "" for none
	}{
		{"under the cap", 3, ""},
		{"at the cap", 20, ""},
		{"over the cap", 25, "; and 5 more"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			doc := "manual: [" + strings.Repeat("1,", tt.items-1) + "1]\n"
			err := parseErr(t, doc, fakeHome(t))
			if !errors.Is(err, config.ErrInvalid) {
				t.Fatalf("Parse() error = %v, want ErrInvalid", err)
			}
			msg := err.Error()
			if got, want := strings.Count(msg, "wrong type"), min(tt.items, 20); got != want {
				t.Errorf("reported %d type errors, want %d: %s", got, want, msg)
			}
			if tt.more != "" && !strings.HasSuffix(msg, tt.more) {
				t.Errorf("error %q, want suffix %q", msg, tt.more)
			}
			if tt.more == "" && strings.Contains(msg, "more") {
				t.Errorf("error %q, want no overflow count", msg)
			}
		})
	}
}
