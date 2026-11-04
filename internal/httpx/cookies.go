package httpx

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Cookie is one cookie-jar entry, without net/http types: connector
// packages may not import net/http (CLAUDE.md rule 5, depguard rule
// "network"), so they inject and export session cookies through
// SetCookies and Cookies. Value is sensitive: callers hold it as a
// secret.Secret and expose it only at this call.
type Cookie struct {
	Name    string
	Value   string
	Path    string    // "" means "/"
	Expires time.Time // zero: session cookie
}

// jarURL is the https origin of host, the key cookies are stored under. host
// must be allowed; it may not carry a port other than the default one.
func (c *Client) jarURL(host string) (*url.URL, error) {
	if !c.allow.Allows(host) {
		return nil, fmt.Errorf("%w: %s", ErrDomainNotAllowed, host)
	}
	h := strings.TrimSuffix(strings.ToLower(host), ":"+defaultHTTPSPort)
	return &url.URL{Scheme: "https", Host: h, Path: "/"}, nil
}

// SetCookies stores cookies in the jar as host-only cookies of
// https://host/. A host outside the allowlist wraps ErrDomainNotAllowed and
// stores nothing. Names and values are stored as given; the jar itself drops
// expired cookies. Every cookie is stored Secure, HttpOnly and SameSite=Lax:
// the client speaks HTTPS only and has no script context, so the attributes
// a browser reported change nothing here. Errors never carry a cookie value.
func (c *Client) SetCookies(host string, cookies []Cookie) error {
	u, err := c.jarURL(host)
	if err != nil {
		return err
	}
	hc := make([]*http.Cookie, 0, len(cookies))
	for _, ck := range cookies {
		path := ck.Path
		if path == "" {
			path = "/"
		}
		hc = append(hc, &http.Cookie{
			Name:     ck.Name,
			Value:    ck.Value,
			Path:     path,
			Expires:  ck.Expires,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	c.hc.Jar.SetCookies(u, hc)
	return nil
}

// Cookies returns the cookies the jar would send on a request to
// https://host/: name and value only (Path "/", other fields zero), as the
// jar exposes them. A host outside the allowlist wraps ErrDomainNotAllowed.
func (c *Client) Cookies(host string) ([]Cookie, error) {
	u, err := c.jarURL(host)
	if err != nil {
		return nil, err
	}
	jc := c.hc.Jar.Cookies(u)
	out := make([]Cookie, 0, len(jc))
	for _, ck := range jc {
		out = append(out, Cookie{Name: ck.Name, Value: ck.Value, Path: "/"})
	}
	return out, nil
}
