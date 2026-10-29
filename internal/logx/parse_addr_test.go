package logx_test

// Contract (review of b452032): a net/url parse error repeats password bytes
// outside the quoted raw URL when the userinfo holds "[": the authority ends
// at the first "/", the bracketed text is taken for an IPv6 host and the
// error quotes it again in `ParseAddr("…")` and `(at "…")`. An opaque URL
// (no "//") that holds a control character is cut at "#" too, so the quoted
// text after its last "@" may be password. Clean masks both, at every
// quoting depth.

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
)

func TestClean_MasksParseAddrAndOpaqueParseErrors(t *testing.T) {
	t.Parallel()
	errText := func(raw string) string {
		t.Helper()
		_, err := url.Parse(raw)
		if err == nil {
			t.Fatalf("url.Parse(%q) succeeded, the test needs an error", raw)
		}
		return err.Error()
	}
	addr := errText("https://[tok.MRK]/x@h.example/")
	addrQuote := errText(`https://[a"MRK]/x@h/`)
	opaque := errText("mailto:\x01p@MRK#x@h")
	tests := []struct{ name, in, want string }{
		{
			"bracketed userinfo quoted by ParseAddr",
			addr,
			`parse "***@h.example/": invalid host: ParseAddr("***"): unexpected character (at "***")`,
		},
		{
			"bracketed userinfo quoted by ParseAddr, percent-q",
			fmt.Sprintf("%q", addr),
			`"parse \"***@h.example/\": invalid host: ParseAddr(\"***\"): unexpected character (at \"***\")"`,
		},
		{
			"bracketed userinfo quoted by ParseAddr, double percent-q",
			fmt.Sprintf("%q", fmt.Sprintf("%q", addr)),
			`"\"parse \\\"***@h.example/\\\": invalid host: ParseAddr(\\\"***\\\"): unexpected character (at \\\"***\\\")\""`,
		},
		{
			"ParseAddr reason holding an escaped quote",
			addrQuote,
			`parse "***@h/": invalid host: ParseAddr("***"): unable to parse IP`,
		},
		{
			"ParseAddr reason holding an escaped quote, percent-q",
			fmt.Sprintf("%q", addrQuote),
			`"parse \"***@h/\": invalid host: ParseAddr(\"***\"): unable to parse IP"`,
		},
		{
			"opaque URL cut at a hash after a control character",
			opaque,
			`parse "***": net/url: invalid control character in URL`,
		},
		{
			"opaque URL cut at a hash after a control character, percent-q",
			fmt.Sprintf("%q", opaque),
			`"parse \"***\": net/url: invalid control character in URL"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := logx.Clean(tt.in); got != tt.want {
				t.Errorf("Clean(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
}
