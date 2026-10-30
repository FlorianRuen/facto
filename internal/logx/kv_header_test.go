package logx_test

import (
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
)

// Header-shaped free text: an unquoted key holding "cookie" or
// "authorization" followed by ":" covers the rest of its line. Every value
// is synthetic.
func TestClean_MasksWholeCookieAndAuthorizationLines(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, in, want string }{
		{"cookie later pairs", "Cookie: lang=fr; ileo=deadbeefcafe; theme=dark", "Cookie: ***; ileo=***; theme=***"},
		{"cookie two pairs", "Cookie: a=1; b=2", "Cookie: ***; b=***"},
		{"cookie bare token", "Cookie: a=1; deadbeefcafe", "Cookie: ***; ***"},
		{"cookie pair after space", "Cookie: a=1 b=deadbeef", "Cookie: *** b=***"},
		{"cookie value with comma", "Cookie: a=1; b=dead,beef; c=3", "Cookie: ***; b=***; c=***"},
		{"cookie stops at newline", "Cookie: a=1; b=2\nnext line x=1", "Cookie: ***; b=***\nnext line x=1"},
		{"cookie stops at cr", "Cookie: a=1; b=2\r\nnext", "Cookie: ***; b=***\r\nnext"},
		{"cookie in sentence", "request failed, Cookie: sid=1; ileo=deadbeef", "request failed, Cookie: ***; ileo=***"},
		{"lowercase cookie", "cookie: a=1; ileo=deadbeef", "cookie: ***; ileo=***"},
		{
			"set-cookie attributes kept",
			"Set-Cookie: ileo=deadbeef; Path=/; Domain=ileo.example; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Max-Age=60; SameSite=Lax; Priority=High; HttpOnly; Secure; Partitioned",
			"Set-Cookie: ***; Path=/; Domain=ileo.example; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Max-Age=60; SameSite=Lax; Priority=High; HttpOnly; Secure; Partitioned",
		},
		{"set-cookie lowercase attributes", "set-cookie: a=deadbeef; path=/; secure", "set-cookie: ***; path=/; secure"},
		{"authorization token scheme", "Authorization: Token deadbeefcafe", "Authorization: ***"},
		{"authorization lowercase scheme", "Authorization: token deadbeefcafe", "Authorization: ***"},
		{"authorization digest", `Authorization: Digest username="bob", response="deadbeef"`, "Authorization: ***"},
		{"authorization bearer colon", "Authorization: Bearer: deadbeef", "Authorization: ***"},
		{"authorization bearer two words", "Authorization: Bearer dead beef", "Authorization: Bearer ***"},
		{"authorization basic tab", "Authorization: Basic\tdXNlcjpw extra", "Authorization: Basic\t***"},
		{"authorization no space", "Authorization:Bearer deadbeef", "Authorization:Bearer ***"},
		{"authorization stops at newline", "Authorization: Token dead\nstatus=ok", "Authorization: ***\nstatus=ok"},
		{"proxy-authorization", "Proxy-Authorization: Negotiate deadbeef", "Proxy-Authorization: ***"},
		{"authorization in sentence", "401 for Authorization: Token deadbeef, retry", "401 for Authorization: ***"},
		{"authorization equals unchanged", "authorization=Bearer%20deadbeef", "authorization=***"},
		{"authorization scheme alone", "Authorization: Bearer", "Authorization: Bearer"},
		{"quoted json key unchanged", `{"Cookie":"a=1; b=2","x":1}`, `{"Cookie":"***","x":1}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := logx.Clean(tt.in); got != tt.want {
				t.Errorf("Clean(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestClean_HeaderLinesLinear feeds 1 MB lines built from header-shaped
// units; a quadratic scan (one copy per cookie segment) took over a minute.
// Not parallel on purpose: outside Linux the budget is the process CPU time
// (see package cputime), only meaningful while the parallel tests wait.
func TestClean_HeaderLinesLinear(t *testing.T) {
	assertCleanLinear(t, map[string]string{
		"cookie pairs": "Cookie: a=1; ",
		"semicolons":   "Cookie: ;;;;;;;;;;;;;;",
		"auth lines":   "Authorization: x\n",
		"bracketed":    "Cookie:[a=1; ",
		"pre-masked":   "Authorization:*** ",
	})
}

// TestClean_HeaderLinesInFormattedMaps covers fmt's one-line rendering of an
// http.Header and the handler's pre-masked map entries: sibling headers
// survive, credentials do not.
func TestClean_HeaderLinesInFormattedMaps(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, in, want string }{
		{"bracketed values", "map[Accept:[text/html] Authorization:[Token dead beef] Cookie:[sid=abc; b=2] X:[1]]", "map[Accept:[text/html] Authorization:[***] Cookie:[sid=***; b=***] X:[1]]"},
		{"bracketed bearer", "map[Authorization:[Bearer deadbeef] X:[1]]", "map[Authorization:[Bearer ***] X:[1]]"},
		{"bracketed set-cookie", "map[Set-Cookie:[a=1; Path=/] X:[1]]", "map[Set-Cookie:[a=***; Path=/] X:[1]]"},
		{"pre-masked entries", "map[Accept:[text/html] Authorization:*** Cookie:*** X:[1]]", "map[Accept:[text/html] Authorization:*** Cookie:*** X:[1]]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := logx.Clean(tt.in); got != tt.want {
				t.Errorf("Clean(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
