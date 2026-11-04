package fakeprovider_test

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/connectors/fakeprovider"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
)

// Compile-time: the package provides a connector.
var _ connector.Connector = (*fakeprovider.Connector)(nil)

func TestInfo_AllowlistOnlyFakeproviderHosts(t *testing.T) {
	t.Parallel()
	c := fakeprovider.New(fakeprovider.Options{})
	info := c.Info()

	if info.ID != "fakeprovider" || fakeprovider.ID != "fakeprovider" {
		t.Errorf("ID = %q (const %q), want fakeprovider", info.ID, fakeprovider.ID)
	}
	if info.Name == "" {
		t.Error("Name is empty")
	}
	if !slices.Equal(info.Kinds, []connector.DocKind{connector.Invoice}) {
		t.Errorf("Kinds = %v, want [invoice]", info.Kinds)
	}
	// Exactly as in docs/connectors/fakeprovider.md, in that order.
	want := []string{"www.fakeprovider.test", "sso.fakeprovider.test"}
	if !slices.Equal(info.AllowedDomains, want) {
		t.Fatalf("AllowedDomains = %q, want %q", info.AllowedDomains, want)
	}
	if fakeprovider.HostWWW != want[0] || fakeprovider.HostSSO != want[1] {
		t.Errorf("HostWWW, HostSSO = %q, %q; want %q", fakeprovider.HostWWW, fakeprovider.HostSSO, want)
	}
	for _, d := range info.AllowedDomains {
		if strings.Contains(d, "*") {
			t.Errorf("wildcard entry %q: the fake site has exactly two hosts", d)
		}
	}
	if err := connector.ValidateInfo(info); err != nil {
		t.Fatalf("ValidateInfo: %v", err)
	}
	if err := connector.NewRegistry().Register(c); err != nil {
		t.Fatalf("Register in a fresh registry: %v", err)
	}

	// Info hands out fresh slices: a caller cannot widen the allowlist.
	info.AllowedDomains[0] = "evil.test"
	info.Kinds[0] = connector.Statement
	again := c.Info()
	if !slices.Equal(again.AllowedDomains, want) || again.Kinds[0] != connector.Invoice {
		t.Fatalf("mutating a returned Info changed the connector: %q %v", again.AllowedDomains, again.Kinds)
	}
}

func TestInfo_ClientRefusesEveryOtherHost(t *testing.T) {
	t.Parallel()
	s := newSite(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	hc := s.client(t)
	for _, host := range []string{evilHost, "fakeprovider.test", "x.fakeprovider.test", "www.fakeprovider.test.evil.test"} {
		resp, err := hc.Get(t.Context(), "https://"+host+"/api/me")
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("GET %s succeeded, want ErrDomainNotAllowed", host)
			continue
		}
		if !errors.Is(err, httpx.ErrDomainNotAllowed) {
			t.Errorf("GET %s: %v, want ErrDomainNotAllowed", host, err)
		}
	}
	for _, d := range s.dialList() {
		t.Errorf("dialled %s for a host outside the allowlist", d)
	}
	// Control: the allowed hosts do reach the site, so the refusals above
	// are the allowlist and not a broken harness.
	for _, host := range []string{wwwHost, ssoHost} {
		resp, err := hc.Get(t.Context(), "https://"+host+"/")
		if err != nil {
			t.Fatalf("GET %s: %v", host, err)
		}
		_ = resp.Body.Close()
	}
}
