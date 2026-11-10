package wecasa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/secret"
)

// pathPage is the customer-area page whose inline script holds the API
// token.
const pathPage = "/my-customer-area/bookings-list"

// blobVersion is the version of the Persist format.
const blobVersion = 1

// maxBlobCookies caps the cookies a Persist blob may carry.
const maxBlobCookies = 64

// Session is an open Wecasa session: the allowlisted client whose jar
// holds the session cookies, and the API bearer token. It never renders a
// cookie or the token: String, GoString, Format and LogValue print a fixed
// placeholder.
type Session struct {
	hc    *httpx.Client
	token secret.Secret
}

var (
	_ connector.Persistable = (*Session)(nil)
	_ slog.LogValuer        = (*Session)(nil)
	_ fmt.Formatter         = (*Session)(nil)
)

// sessionText is how a Session renders everywhere.
const sessionText = "wecasa.Session{cookies:" + secret.Masked + ",token:" + secret.Masked + "}"

// String implements fmt.Stringer.
func (s *Session) String() string { return sessionText }

// GoString implements fmt.GoStringer.
func (s *Session) GoString() string { return sessionText }

// Format renders sessionText for every verb and flag.
func (s *Session) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, sessionText) }

// LogValue implements slog.LogValuer.
func (s *Session) LogValue() slog.Value { return slog.StringValue(sessionText) }

// isHost reports whether a cookie Domain designates Host (a leading dot
// and letter case ignored).
func isHost(domain string) bool {
	return strings.ToLower(strings.TrimPrefix(domain, ".")) == Host
}

// errInvalidCookie names the cookie by index only: names and values are
// supplier data and may be secrets.
func errInvalidCookie(i int, what string) error {
	return fmt.Errorf("wecasa: cookie %d: invalid %s", i, what)
}

// injectCookies puts the www.wecasa.fr cookies into hc's jar. Cookies of
// any other domain are dropped: they never reach the jar nor a blob.
func injectCookies(hc *httpx.Client, cookies []connector.Cookie) error {
	var jar []httpx.Cookie
	for i, c := range cookies {
		if !isHost(c.Domain) {
			continue
		}
		if !validCookieName(c.Name) {
			return errInvalidCookie(i, "name")
		}
		if !validCookieValue(c.Value.Expose()) {
			return errInvalidCookie(i, "value")
		}
		if c.Path != "" && !strings.HasPrefix(c.Path, "/") {
			return errInvalidCookie(i, "path")
		}
		jar = append(jar, httpx.Cookie{Name: c.Name, Value: c.Value.Expose(), Path: c.Path, Expires: c.Expires})
	}
	if len(jar) == 0 {
		return nil
	}
	if err := hc.SetCookies(Host, jar); err != nil {
		return fmt.Errorf("wecasa: inject cookies: %w", err)
	}
	return nil
}

// NewSession injects cookies (from Browser.Cookies after login) into hc's
// jar, then reads the API token from the bookings page over hc. A cookie
// whose Domain is not www.wecasa.fr is dropped; a cookie with an invalid
// name, value or path is an error naming it by index only. A page without
// the token, or a redirect to the login page, wraps connector.ErrNeedsLogin.
// The page body is cleared once parsed; it is never logged nor returned.
func NewSession(ctx context.Context, hc *httpx.Client, cookies []connector.Cookie) (*Session, error) {
	if hc == nil {
		return nil, errors.New("wecasa: nil http client")
	}
	if err := injectCookies(hc, cookies); err != nil {
		return nil, err
	}
	tok, err := readToken(ctx, hc)
	if err != nil {
		return nil, fmt.Errorf("wecasa: read the api token: %w", err)
	}
	return &Session{hc: hc, token: tok}, nil
}

// readToken GETs the bookings page with the jar's cookies and parses the
// token out of it.
func readToken(ctx context.Context, hc *httpx.Client) (secret.Secret, error) {
	r, err := send(ctx, hc, pathPage, map[string][]string{"Accept": {mimeHTML}})
	if err != nil {
		return secret.Secret{}, err
	}
	defer func() { _ = r.body.Close() }()
	body, err := capped(pathPage, r, mimeHTML, maxPageBytes)
	if err != nil {
		return secret.Secret{}, err
	}
	page, err := readAll(pathPage, body)
	if err != nil {
		return secret.Secret{}, err
	}
	defer clear(page)
	tok, err := parseToken(page)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("%s: %w", pathPage, err)
	}
	return tok, nil
}

// blob is the Persist format, version 1: the token and the cookies of
// www.wecasa.fr. Persist writes it by hand (appendBlob); Restore decodes it
// with encoding/json.
type blob struct {
	V       int          `json:"v"`
	Token   string       `json:"token"`
	Cookies []blobCookie `json:"cookies"`
}

type blobCookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

// Persist exports the token and the cookies the jar would send to
// www.wecasa.fr (server-rotated values included) as an opaque secret blob.
// A jar cookie Restore would refuse is skipped. A session without token or
// without any usable cookie wraps connector.ErrNeedsLogin.
//
// The blob is written into one exactly sized buffer that the returned
// Secret owns (secret.New does not copy), so Wipe clears the only
// plaintext copy Persist makes. Residual copies outside Persist's control:
// the cookie strings the jar hands out, the jar itself, and the token the
// Session holds.
func (s *Session) Persist(_ context.Context) (secret.Secret, error) {
	if s == nil || s.hc == nil {
		return secret.Secret{}, errors.New("wecasa: persist: nil session")
	}
	tok := s.token.Expose()
	if !tokenRe.MatchString(tok) {
		return secret.Secret{}, fmt.Errorf("%w: wecasa: no api token to persist", connector.ErrNeedsLogin)
	}
	cs, err := s.hc.Cookies(Host)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("wecasa: persist: %w", err)
	}
	var cookies []blobCookie
	for _, c := range cs {
		if !validCookieName(c.Name) || !validCookieValue(c.Value) || len(cookies) == maxBlobCookies {
			continue
		}
		cookies = append(cookies, blobCookie{Name: c.Name, Value: c.Value, Domain: Host, Path: "/"})
	}
	if len(cookies) == 0 {
		return secret.Secret{}, fmt.Errorf("%w: wecasa: no session cookie to persist", connector.ErrNeedsLogin)
	}
	buf := make([]byte, 0, blobLen(tok, cookies))
	buf = appendBlob(buf, tok, cookies)
	return secret.New(buf), nil
}

// This fails to compile once blobVersion leaves 0..9: blobHead renders it
// as one digit.
const _ = uint(9 - blobVersion)

// Blob JSON pieces. Every string appendBlob writes is a validated token
// (tokenRe), cookie name (RFC 7230 token), cookie value (RFC 6265
// cookie-octets), Host or "/": none holds a double quote, a backslash or a
// control byte, so none needs JSON escaping.
const (
	blobHead   = `{"v":` + string(rune('0'+blobVersion)) + `,"token":"`
	blobMid    = `","cookies":[`
	blobTail   = "]}\n"
	ckName     = `{"name":"`
	ckValue    = `","value":"`
	ckDomain   = `","domain":"`
	ckPath     = `","path":"`
	ckEnd      = `"}`
	ckSep      = ","
	ckOverhead = len(ckName) + len(ckValue) + len(ckDomain) + len(ckPath) + len(ckEnd)
)

// blobLen returns the exact length appendBlob writes.
func blobLen(tok string, cookies []blobCookie) int {
	n := len(blobHead) + len(tok) + len(blobMid) + len(blobTail)
	for i, c := range cookies {
		if i > 0 {
			n += len(ckSep)
		}
		n += ckOverhead + len(c.Name) + len(c.Value) + len(c.Domain) + len(c.Path)
	}
	return n
}

// appendBlob appends the version-1 blob to dst.
func appendBlob(dst []byte, tok string, cookies []blobCookie) []byte {
	dst = append(dst, blobHead...)
	dst = append(dst, tok...)
	dst = append(dst, blobMid...)
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
// the decoder's message: the blob holds the token and cookie values.
func errBadBlob(what string) error {
	return fmt.Errorf("%w: wecasa: saved session %s", connector.ErrNeedsLogin, what)
}

// Restore rebuilds a session from a Persist blob (Env.Saved) into hc's
// jar. A zero, malformed or foreign-version blob, an unknown member, a
// token of the wrong shape, a cookie of another host or with a path other
// than "/" wraps connector.ErrNeedsLogin; the error never echoes the blob.
// Restore makes no request: Login probes the result.
func Restore(hc *httpx.Client, saved secret.Secret) (*Session, error) {
	if hc == nil {
		return nil, errors.New("wecasa: nil http client")
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
	if !tokenRe.MatchString(b.Token) {
		return nil, errBadBlob("has no usable token")
	}
	if len(b.Cookies) == 0 || len(b.Cookies) > maxBlobCookies {
		return nil, errBadBlob("has no usable cookie")
	}
	jar := make([]httpx.Cookie, 0, len(b.Cookies))
	for i, c := range b.Cookies {
		if c.Domain != Host {
			return nil, errBadBlob(fmt.Sprintf("cookie %d: host not allowed", i))
		}
		// Persist always writes Path "/"; any other path is refused so a
		// failed restore can be cleared from the jar completely.
		if !validCookieName(c.Name) || !validCookieValue(c.Value) || c.Path != "/" {
			return nil, errBadBlob(fmt.Sprintf("cookie %d: invalid", i))
		}
		jar = append(jar, httpx.Cookie{Name: c.Name, Value: c.Value, Path: "/"})
	}
	if err := hc.SetCookies(Host, jar); err != nil {
		return nil, errBadBlob("cannot be injected")
	}
	return &Session{hc: hc, token: secret.FromString(b.Token)}, nil
}

// clearJar deletes every cookie hc's jar holds for www.wecasa.fr. Restore
// only injects cookies scoped to "/", which Cookies lists; a cookie set
// again with an Expires in the past is deleted by the jar.
func clearJar(hc *httpx.Client) error {
	cs, err := hc.Cookies(Host)
	if err != nil {
		return fmt.Errorf("wecasa: login: clear saved cookies: %w", err)
	}
	if len(cs) == 0 {
		return nil
	}
	del := make([]httpx.Cookie, 0, len(cs))
	for _, c := range cs {
		del = append(del, httpx.Cookie{Name: c.Name, Value: "deleted", Path: "/", Expires: time.Unix(1, 0).UTC()})
	}
	if err := hc.SetCookies(Host, del); err != nil {
		return fmt.Errorf("wecasa: login: clear saved cookies: %w", err)
	}
	return nil
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
