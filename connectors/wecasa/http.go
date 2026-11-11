package wecasa

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"strings"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
)

// HTTP status codes and methods. Named here: the package may not import
// net/http (depguard rule "network").
const (
	methodGet = "GET"

	statusOK              = 200
	statusUnauthorized    = 401
	statusForbidden       = 403
	statusNotFound        = 404
	statusTooManyRequests = 429
)

// Media types the site answers with.
const (
	mimeJSON = "application/json"
	mimeHTML = "text/html"
	mimePDF  = "application/pdf"
)

// reply is a 200 answer whose body the caller must close.
type reply struct {
	body   io.ReadCloser
	ctype  string // media type, lowercased, parameters dropped; "" if unparsable
	length int64  // declared Content-Length, -1 when unknown
}

// sessionOf returns s as a usable *Session.
func sessionOf(s connector.Session) (*Session, error) {
	sess, ok := s.(*Session)
	if !ok || sess == nil || sess.hc == nil || sess.token.IsZero() {
		return nil, fmt.Errorf("wecasa: session of type %T is not a wecasa session", s)
	}
	return sess, nil
}

// api sends GET https://www.wecasa.fr<path> with the bearer token.
func (s *Session) api(ctx context.Context, path string) (reply, error) {
	// The only place the token is exposed: the header map is dropped
	// when the request ends. httpx never echoes header values.
	header := map[string][]string{
		"Authorization": {"Bearer " + s.token.Expose()},
		"Accept":        {mimeJSON},
	}
	return send(ctx, s.hc, path, header)
}

// send sends GET https://www.wecasa.fr<path> with header and maps the
// answer: a landing on the login page or a 401 wraps ErrNeedsLogin, 403
// ErrAuthFailed, 429 ErrRateLimited (no retry, Retry-After ignored), any
// other non-200 ErrBroken. Errors name the path, never a header or body.
func send(ctx context.Context, hc *httpx.Client, path string, header map[string][]string) (reply, error) {
	u := url.URL{Scheme: "https", Host: Host, Path: path}
	resp, err := hc.Send(ctx, methodGet, u.String(), header)
	if err != nil {
		// httpx errors name the host only, never the query nor a header.
		return reply{}, fmt.Errorf("GET %s: %w", path, err)
	}
	if final := resp.Request; final != nil && final.URL != nil && path != pathLogin &&
		strings.TrimSuffix(final.URL.Path, "/") == pathLogin {
		_ = resp.Body.Close()
		return reply{}, fmt.Errorf("%w: GET %s: redirected to the login page", connector.ErrNeedsLogin, path)
	}
	if resp.StatusCode != statusOK {
		_ = resp.Body.Close()
		return reply{}, statusError(path, resp.StatusCode)
	}
	ctype := ""
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err == nil {
		ctype = strings.ToLower(mt)
	}
	return reply{body: resp.Body, ctype: ctype, length: resp.ContentLength}, nil
}

// statusError maps a non-200 status to a connector sentinel.
func statusError(path string, code int) error {
	var sentinel error
	switch code {
	case statusUnauthorized:
		sentinel = connector.ErrNeedsLogin
	case statusForbidden:
		sentinel = connector.ErrAuthFailed
	case statusTooManyRequests:
		sentinel = connector.ErrRateLimited
	case statusNotFound:
		return fmt.Errorf("%w: endpoint %s not found (status 404)", connector.ErrBroken, path)
	default:
		sentinel = connector.ErrBroken
	}
	return fmt.Errorf("%w: GET %s: status %d", sentinel, path, code)
}

// capped checks the media type and the declared length of r and returns
// its body capped at limit. Failures wrap ErrBroken; a declared length
// over limit also wraps httpx.ErrBodyTooLarge.
func capped(path string, r reply, ctype string, limit int64) (io.ReadCloser, error) {
	if r.ctype != ctype {
		return nil, fmt.Errorf("%w: %s: content type is not %s", connector.ErrBroken, path, ctype)
	}
	if r.length > limit {
		return nil, fmt.Errorf("%w: %s: declared length over %d bytes: %w", connector.ErrBroken, path, limit, httpx.ErrBodyTooLarge)
	}
	return httpx.LimitBody(r.body, limit), nil
}

// readAll reads a capped body. A cap hit wraps ErrBroken and
// httpx.ErrBodyTooLarge.
func readAll(path string, body io.Reader) ([]byte, error) {
	b, err := io.ReadAll(body)
	if err != nil {
		clear(b)
		if errors.Is(err, httpx.ErrBodyTooLarge) {
			return nil, fmt.Errorf("%w: %s: body over the size cap: %w", connector.ErrBroken, path, httpx.ErrBodyTooLarge)
		}
		return nil, fmt.Errorf("%s: read body: %w", path, err)
	}
	return b, nil
}
