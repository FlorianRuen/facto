package fakeprovider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"strings"

	"github.com/FlorianRuen/facto/internal/connector"
)

// HTTP status codes the site answers with. Named here: the package may not
// import net/http (depguard rule "network").
const (
	statusOK              = 200
	statusUnauthorized    = 401
	statusForbidden       = 403
	statusNotFound        = 404
	statusTooManyRequests = 429
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
	if !ok || sess == nil || sess.hc == nil {
		return nil, fmt.Errorf("fakeprovider: session of type %T is not a fakeprovider session", s)
	}
	return sess, nil
}

// get sends GET https://www.fakeprovider.test<path>?<query> and maps the
// answer: a landing on the SSO host or a 401 wraps ErrNeedsLogin, 403
// ErrAuthFailed, 429 ErrRateLimited (no retry, Retry-After ignored), any
// other non-200 ErrBroken. Errors name the path, never the query.
func (s *Session) get(ctx context.Context, path string, query url.Values) (reply, error) {
	u := url.URL{Scheme: "https", Host: HostWWW, Path: path, RawQuery: query.Encode()}
	resp, err := s.hc.Get(ctx, u.String())
	if err != nil {
		// httpx errors name the host only, never the query.
		return reply{}, fmt.Errorf("fakeprovider: GET %s: %w", path, err)
	}
	if final := resp.Request; final != nil && final.URL != nil && strings.EqualFold(final.URL.Hostname(), HostSSO) {
		_ = resp.Body.Close()
		return reply{}, fmt.Errorf("%w: fakeprovider: GET %s: redirected to the login page", connector.ErrNeedsLogin, path)
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
		return fmt.Errorf("%w: fakeprovider: endpoint %s not found (status 404)", connector.ErrBroken, path)
	default:
		sentinel = connector.ErrBroken
	}
	return fmt.Errorf("%w: fakeprovider: GET %s: status %d", sentinel, path, code)
}

// decodeStrict decodes exactly one JSON value from r into v: unknown
// fields and trailing data are refused. Errors never carry the decoder's
// message (it may quote body values); a body cap hit keeps
// httpx.ErrBodyTooLarge in the chain.
func decodeStrict(r io.Reader, v any) error {
	dec := newStrictDecoder(r)
	if err := dec.Decode(v); err != nil {
		return jsonError(err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return jsonError(err)
		}
		return errors.New("trailing data after the JSON value")
	}
	return nil
}
