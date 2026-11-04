package fakeprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/secret"
)

// blobVersion is the version of the Persist format.
const blobVersion = 1

// maxBlobCookies caps the cookies a Persist blob may carry.
const maxBlobCookies = 64

// Session is an open fakeprovider session: the allowlisted client whose jar
// holds the session cookies. It never renders a cookie value: String,
// GoString, Format and LogValue print a fixed placeholder.
type Session struct {
	hc *httpx.Client
}

var (
	_ connector.Persistable = (*Session)(nil)
	_ slog.LogValuer        = (*Session)(nil)
	_ fmt.Formatter         = (*Session)(nil)
)

// sessionText is how a Session renders everywhere.
const sessionText = "fakeprovider.Session{cookies:" + secret.Masked + "}"

// String implements fmt.Stringer.
func (s *Session) String() string { return sessionText }

// GoString implements fmt.GoStringer.
func (s *Session) GoString() string { return sessionText }

// Format renders sessionText for every verb and flag.
func (s *Session) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, sessionText) }

// LogValue implements slog.LogValuer.
func (s *Session) LogValue() slog.Value { return slog.StringValue(sessionText) }

// allowedHost returns the allowlisted host a cookie Domain designates (a
// leading dot and letter case ignored), or false.
func allowedHost(domain string) (string, bool) {
	d := strings.ToLower(strings.TrimPrefix(domain, "."))
	for _, h := range allowedHosts() {
		if d == h {
			return h, true
		}
	}
	return "", false
}

// errInvalidCookie names the cookie by index only: names and values are
// supplier data and may be secrets.
func errInvalidCookie(i int, what string) error {
	return fmt.Errorf("fakeprovider: cookie %d: invalid %s", i, what)
}

// NewSession injects cookies (from Browser.Cookies after login) into hc's
// jar and returns the session. A cookie whose Domain is not one of
// Info().AllowedDomains is dropped: it never reaches the jar nor a Persist
// blob. A cookie with a name or value that is not a valid RFC 6265 token or
// cookie-value is an error that names it by index only.
func NewSession(hc *httpx.Client, cookies []connector.Cookie) (*Session, error) {
	if hc == nil {
		return nil, errors.New("fakeprovider: nil http client")
	}
	byHost := map[string][]httpx.Cookie{}
	for i, c := range cookies {
		host, ok := allowedHost(c.Domain)
		if !ok {
			continue
		}
		if !validCookieName(c.Name) {
			return nil, errInvalidCookie(i, "name")
		}
		if !validCookieValue(c.Value.Expose()) {
			return nil, errInvalidCookie(i, "value")
		}
		if c.Path != "" && !strings.HasPrefix(c.Path, "/") {
			return nil, errInvalidCookie(i, "path")
		}
		byHost[host] = append(byHost[host], httpx.Cookie{
			Name:    c.Name,
			Value:   c.Value.Expose(),
			Path:    c.Path,
			Expires: c.Expires,
		})
	}
	for _, host := range allowedHosts() {
		if len(byHost[host]) == 0 {
			continue
		}
		if err := hc.SetCookies(host, byHost[host]); err != nil {
			return nil, fmt.Errorf("fakeprovider: inject cookies: %w", err)
		}
	}
	return &Session{hc: hc}, nil
}

// blob is the Persist format: version 1, cookies of the allowlisted hosts.
// Persist writes it by hand (appendBlob); Restore decodes it with
// encoding/json.
type blob struct {
	V       int          `json:"v"`
	Cookies []blobCookie `json:"cookies"`
}

type blobCookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

// Persist exports the cookies the jar would send to each allowlisted host,
// server-rotated values included, as an opaque secret blob. Cookies of any
// other host are never in the jar, hence never persisted. A jar cookie whose
// name or value Restore would refuse is skipped (it would make the whole
// blob unusable). A session without any usable cookie wraps
// connector.ErrNeedsLogin. The jar exposes cookies scoped to "/" only, so
// the blob records Path "/".
//
// The blob is written into one exactly sized buffer that the returned
// Secret owns (secret.New does not copy), so Wipe clears the only
// plaintext copy Persist makes: no encoder buffer, no growth reallocation.
// Residual copies outside Persist's control: the cookie value strings the
// jar hands out (immutable, left to the GC) and the jar itself.
func (s *Session) Persist(_ context.Context) (secret.Secret, error) {
	if s == nil || s.hc == nil {
		return secret.Secret{}, errors.New("fakeprovider: persist: nil session")
	}
	var cookies []blobCookie
	for _, host := range allowedHosts() {
		cs, err := s.hc.Cookies(host)
		if err != nil {
			return secret.Secret{}, fmt.Errorf("fakeprovider: persist: %w", err)
		}
		for _, c := range cs {
			if !validCookieName(c.Name) || !validCookieValue(c.Value) || len(cookies) == maxBlobCookies {
				continue
			}
			cookies = append(cookies, blobCookie{Name: c.Name, Value: c.Value, Domain: host, Path: "/"})
		}
	}
	if len(cookies) == 0 {
		return secret.Secret{}, fmt.Errorf("%w: fakeprovider: no session cookie to persist", connector.ErrNeedsLogin)
	}
	buf := make([]byte, 0, blobLen(cookies))
	buf = appendBlob(buf, cookies)
	return secret.New(buf), nil
}

// blobHead renders blobVersion as one digit: this fails to compile once
// blobVersion leaves 0..9.
const _ = uint(9 - blobVersion)

// Blob JSON pieces. Every string appendBlob writes is a validated cookie
// name (RFC 7230 token), cookie value (RFC 6265 cookie-octets), allowlisted
// host or "/": none holds a double quote, a backslash or a control byte, so
// none needs JSON escaping.
const (
	blobHead   = `{"v":` + string(rune('0'+blobVersion)) + `,"cookies":[`
	blobTail   = "]}\n"
	ckName     = `{"name":"`
	ckValue    = `","value":"`
	ckDomain   = `","domain":"`
	ckPath     = `","path":"`
	ckEnd      = `"}`
	ckSep      = ","
	ckOverhead = len(ckName) + len(ckValue) + len(ckDomain) + len(ckPath) + len(ckEnd)
)

// blobLen returns the exact length appendBlob writes for cookies.
func blobLen(cookies []blobCookie) int {
	n := len(blobHead) + len(blobTail)
	for i, c := range cookies {
		if i > 0 {
			n += len(ckSep)
		}
		n += ckOverhead + len(c.Name) + len(c.Value) + len(c.Domain) + len(c.Path)
	}
	return n
}

// appendBlob appends the version-1 blob for cookies to dst.
func appendBlob(dst []byte, cookies []blobCookie) []byte {
	dst = append(dst, blobHead...)
	for i, c := range cookies {
		if i > 0 {
			dst = append(dst, ckSep...)
		}
		dst = append(dst, ckName...)
		dst = append(dst, c.Name...)
		dst = append(dst, ckValue...)
		dst = append(dst, c.Value...)
		dst = append(dst, ckDomain...)
		dst = append(dst, c.Domain...)
		dst = append(dst, ckPath...)
		dst = append(dst, c.Path...)
		dst = append(dst, ckEnd...)
	}
	return append(dst, blobTail...)
}

// errBadBlob is what every unusable saved session wraps. It never carries
// the decoder's message: the blob holds cookie values.
func errBadBlob(what string) error {
	return fmt.Errorf("%w: fakeprovider: saved session %s", connector.ErrNeedsLogin, what)
}

// Restore rebuilds a session from a Persist blob (Env.Saved) into hc's jar.
// A zero, malformed, foreign-version blob, or one naming a host outside the
// allowlist or a cookie path other than "/", wraps connector.ErrNeedsLogin;
// the error never echoes the blob. Restore makes no request.
func Restore(hc *httpx.Client, saved secret.Secret) (*Session, error) {
	if hc == nil {
		return nil, errors.New("fakeprovider: nil http client")
	}
	if saved.IsZero() {
		return nil, errBadBlob("is empty")
	}
	dec := json.NewDecoder(strings.NewReader(saved.Expose()))
	dec.DisallowUnknownFields()
	var b blob
	if err := dec.Decode(&b); err != nil {
		return nil, errBadBlob("is malformed")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errBadBlob("has trailing data")
	}
	if b.V != blobVersion {
		return nil, errBadBlob("has an unknown version")
	}
	if len(b.Cookies) == 0 || len(b.Cookies) > maxBlobCookies {
		return nil, errBadBlob("has no usable cookie")
	}
	cookies := make([]connector.Cookie, 0, len(b.Cookies))
	for i, c := range b.Cookies {
		if _, ok := allowedHost(c.Domain); !ok || strings.HasPrefix(c.Domain, ".") {
			return nil, errBadBlob(fmt.Sprintf("cookie %d: host not allowed", i))
		}
		// Persist always writes Path "/"; any other path is refused so a
		// failed restore can be cleared from the jar completely.
		if !validCookieName(c.Name) || !validCookieValue(c.Value) || c.Path != "/" {
			return nil, errBadBlob(fmt.Sprintf("cookie %d: invalid", i))
		}
		cookies = append(cookies, connector.Cookie{
			Name: c.Name, Value: secret.FromString(c.Value), Domain: c.Domain, Path: c.Path,
			Secure: true, HTTPOnly: true,
		})
	}
	s, err := NewSession(hc, cookies)
	if err != nil {
		return nil, errBadBlob("cannot be injected")
	}
	return s, nil
}

// validCookieName reports whether n is a non-empty RFC 7230 token.
func validCookieName(n string) bool {
	if n == "" || len(n) > 256 {
		return false
	}
	for i := range len(n) {
		c := n[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`()<>@,;:\"/[]?={}`, c) >= 0 {
			return false
		}
	}
	return true
}

// validCookieValue reports whether v is a non-empty run of RFC 6265
// cookie-octets (no space, DQUOTE, comma, semicolon, backslash, control).
func validCookieValue(v string) bool {
	if v == "" || len(v) > 4096 {
		return false
	}
	for i := range len(v) {
		c := v[i]
		if c <= ' ' || c >= 0x7f || c == '"' || c == ',' || c == ';' || c == '\\' {
			return false
		}
	}
	return true
}
