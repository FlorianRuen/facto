package logx_test

import (
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
)

// TestClean_ParseErrorKeptTailIdempotent (SEC-J0-24, found by FuzzClean):
// the host and path a parse error keeps after "***@" must not be changed by
// a later pattern (a token-like run, a key and its value), or a second Clean
// masks the whole argument. Such a tail is masked whole the first time.
func TestClean_ParseErrorKeptTailIdempotent(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, in, want string }{
		{"empty userinfo then token-like run", `parse "@://%00000000000000A0`, `parse "***`},
		{"short userinfo then token-like run", `parse "u@://%00000000000000A0`, `parse "***`},
		{"token-like path closed", `parse "u@://%00000000000000A0": bad`, `parse "***": bad`},
		{"key and value in the kept tail", `parse "@://token:abc`, `parse "***`},
		{"plain host and path kept", `parse "https://u:p@db.test/x?q": bad`, `parse "***@db.test/x?***": bad`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := logx.Clean(tt.in)
			if got != tt.want {
				t.Errorf("Clean(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if again := logx.Clean(got); again != got {
				t.Errorf("Clean not idempotent: %q then %q", got, again)
			}
		})
	}
}

// TestClean_MaskOverURLAuthorityEndIdempotent (SEC-J0-24, found by
// FuzzClean_KeyShapedValue): a masked value that swallows the "#", "/" or
// "?" ending a URL authority lets the userinfo pattern reach a later "@";
// Clean applies the URL patterns again then, so a second Clean changes
// nothing.
func TestClean_MaskOverURLAuthorityEndIdempotent(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, in, want string }{
		{"grown value swallows a fragment", "A:// password=EJRXTokenYXR4= # @", "A://"},
		{"value is a fragment", "A:// password=# @", "A://"},
		{"no later at sign", "A:// password=# x", "A:// password=*** x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := logx.Clean(tt.in)
			if got != tt.want {
				t.Errorf("Clean(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if again := logx.Clean(got); again != got {
				t.Errorf("Clean not idempotent: %q then %q", got, again)
			}
		})
	}
}
