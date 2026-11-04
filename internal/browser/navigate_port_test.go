package browser_test

import (
	"errors"
	"testing"

	"github.com/FlorianRuen/facto/internal/browser"
)

// TestPage_NavigatePortRules (J1 T27, red-team informational): an empty
// port ("https://host:/") is refused like httpx refuses it, before any CDP
// call; 443, explicit or not, is the only port accepted.
func TestPage_NavigatePortRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		url string
		ok  bool
	}{
		{"https://login.supplier.example/login", true},
		{"https://login.supplier.example:443/login", true},
		{"https://login.supplier.example:/", false},
		{"https://login.supplier.example:/login", false},
		{"https://login.supplier.example:", false},
		{"https://login.supplier.example:8443/login", false},
		{"https://login.supplier.example:0443/login", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			t.Parallel()
			e := newPage(t)
			m := e.f.mark()
			err := e.p.Navigate(testCtx(t), tt.url)
			sent := index(e.f.since(m), "Page.navigate") >= 0
			if tt.ok {
				if err != nil || !sent {
					t.Errorf("Navigate(%q) = %v (navigate sent %v), want accepted", tt.url, err, sent)
				}
				return
			}
			if !errors.Is(err, browser.ErrURLRefused) {
				t.Errorf("Navigate(%q) = %v, want ErrURLRefused", tt.url, err)
			}
			if sent {
				t.Errorf("Navigate(%q) sent Page.navigate although refused", tt.url)
			}
		})
	}
}
