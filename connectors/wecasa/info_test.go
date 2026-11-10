package wecasa_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/FlorianRuen/facto/connectors/wecasa"
	"github.com/FlorianRuen/facto/internal/browser"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
)

func TestInfo_MatchesSheet(t *testing.T) {
	t.Parallel()
	c := wecasa.New(wecasa.Options{})
	info := c.Info()
	if info.ID != "wecasa" || wecasa.ID != "wecasa" {
		t.Errorf("ID = %q, want wecasa", info.ID)
	}
	if info.Name != "Wecasa" {
		t.Errorf("Name = %q, want Wecasa", info.Name)
	}
	if info.Category != "services" {
		t.Errorf("Category = %q, want services", info.Category)
	}
	if !slices.Equal(info.Kinds, []connector.DocKind{connector.Invoice}) {
		t.Errorf("Kinds = %v, want [invoice]", info.Kinds)
	}
	if want := []string{"www.wecasa.fr"}; !slices.Equal(info.AllowedDomains, want) {
		t.Errorf("AllowedDomains = %q, want %q", info.AllowedDomains, want)
	}
	if want := []string{"https://storage.googleapis.com/wecasa-react-prod/"}; !slices.Equal(info.BrowserStatic, want) {
		t.Errorf("BrowserStatic = %q, want %q", info.BrowserStatic, want)
	}
	if err := connector.ValidateInfo(info); err != nil {
		t.Errorf("ValidateInfo: %v", err)
	}
	if _, err := browser.ParseStatic(info.BrowserStatic); err != nil {
		t.Errorf("browser.ParseStatic(BrowserStatic): %v", err)
	}
	if _, err := httpx.ParseAllowlist(info.AllowedDomains); err != nil {
		t.Errorf("httpx.ParseAllowlist(AllowedDomains): %v", err)
	}
}

func TestInfo_FreshSlicesOnEveryCall(t *testing.T) {
	t.Parallel()
	c := wecasa.New(wecasa.Options{})
	a := c.Info()
	a.AllowedDomains[0] = evilHost
	a.BrowserStatic[0] = "https://" + evilHost + "/x/"
	a.Kinds[0] = connector.Statement
	b := c.Info()
	if b.AllowedDomains[0] != wwwHost {
		t.Errorf("AllowedDomains shared between calls: %q", b.AllowedDomains)
	}
	if b.BrowserStatic[0] != "https://storage.googleapis.com/wecasa-react-prod/" {
		t.Errorf("BrowserStatic shared between calls: %q", b.BrowserStatic)
	}
	if b.Kinds[0] != connector.Invoice {
		t.Errorf("Kinds shared between calls: %v", b.Kinds)
	}
}

func TestRegister_AddsWecasaOnce(t *testing.T) {
	t.Parallel()
	r := connector.NewRegistry()
	if err := wecasa.Register(r); err != nil {
		t.Fatalf("Register: %v", err)
	}
	c, ok := r.Get("wecasa")
	if !ok {
		t.Fatal("wecasa not in the registry after Register")
	}
	if _, ok := c.(*wecasa.Connector); !ok {
		t.Errorf("registered %T, want *wecasa.Connector", c)
	}
	if err := wecasa.Register(r); !errors.Is(err, connector.ErrDuplicateID) {
		t.Errorf("second Register = %v, want ErrDuplicateID", err)
	}
}
