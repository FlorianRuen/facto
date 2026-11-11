package wecasa_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/connectors/wecasa"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/secret"
)

// seedTok is a synthetic token of the accepted shape, built from parts so
// no source line holds a token-like literal (gitleaks, SEC-J3-5).
const seedTok = "abcd" + "efghijklmnop" + "0123"

// FuzzParseToken (SEC-J3-3): the bookings-page token parser never panics,
// its errors never quote the page, and a token it accepts is a substring
// of the page in the strict token charset.
func FuzzParseToken(f *testing.F) {
	for _, s := range []string{
		"window.wecasa = {\n    token: '" + seedTok + "',\n    locale: 'fr-FR'\n  };",
		`window.wecasa = { token: "` + seedTok + `" };`,
		"window.wecasa = { token: '' };",
		"window.wecasa = { token: 'a', token: 'b' };",
		"window.wecasa = { token: 'unterminated",
		"window.wecasa = {",
		"<html>no block</html>",
		"window.wecasa = { token: x };",
		"window.wecasa = {} window.wecasa = { token: '" + seedTok + "' };",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, page []byte) {
		in := string(page)
		tok, err := wecasa.ParseToken(page)
		if err != nil {
			if !tok.IsZero() {
				t.Fatal("token returned with an error")
			}
			if !errors.Is(err, connector.ErrNeedsLogin) && !errors.Is(err, connector.ErrBroken) {
				t.Fatalf("error %v is neither ErrNeedsLogin nor ErrBroken", err)
			}
			msg := err.Error()
			// The parser's fixed vocabulary (window.wecasa, ErrBroken…) may
			// appear in both; any other 12+ byte page word may not.
			for _, w := range strings.Fields(in) {
				if len(w) >= 12 && strings.Contains(msg, w) && !strings.Contains(fixedErrorText, w) {
					t.Fatalf("error %q quotes the page (%q)", msg, w)
				}
			}
			return
		}
		v := tok.Expose()
		if len(v) < 16 || len(v) > 512 || !strings.Contains(in, v) {
			t.Fatalf("accepted token of length %d not found as is in the page", len(v))
		}
		for i := range len(v) {
			c := v[i]
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("._~+/=-", c) >= 0
			if !ok {
				t.Fatalf("accepted token holds byte %#x outside the token charset", c)
			}
		}
	})
}

// FuzzRestore_PersistRoundTrip (SEC-J3-3): Restore never panics, fails
// with ErrNeedsLogin without quoting the blob, and a session it accepts
// persists to a blob Restore accepts again.
func FuzzRestore_PersistRoundTrip(f *testing.F) {
	for _, s := range []string{
		`{"v":1,"token":"` + seedTok + `","cookies":[{"name":"_wecasa_session","value":"abc123","domain":"www.wecasa.fr","path":"/"}]}`,
		`{"v":1,"token":"` + seedTok + `","cookies":[]}`,
		`{"v":2,"token":"` + seedTok + `","cookies":[{"name":"a","value":"b","domain":"www.wecasa.fr","path":"/"}]}`,
		`{"v":1,"token":"short","cookies":[{"name":"a","value":"b","domain":"evil.test","path":"/"}]}`,
		`{"v":1,"token":"` + seedTok + `","cookies":[{"name":"a","value":"b","domain":"www.wecasa.fr","path":"/x"}],"x":1}`,
		`not json`,
		``,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		hc, err := httpx.New([]string{wecasa.Host}, httpx.Options{})
		if err != nil {
			t.Fatalf("httpx.New: %v", err)
		}
		sess, err := wecasa.Restore(hc, secret.FromString(raw))
		if err != nil {
			if sess != nil {
				t.Fatal("session returned with an error")
			}
			if !errors.Is(err, connector.ErrNeedsLogin) {
				t.Fatalf("Restore error %v does not wrap ErrNeedsLogin", err)
			}
			if len(raw) >= 8 && strings.Contains(err.Error(), raw) {
				t.Fatal("Restore error quotes the blob")
			}
			return
		}
		blob, err := sess.Persist(t.Context())
		if err != nil {
			t.Fatalf("Persist of a restored session: %v", err)
		}
		hc2, err := httpx.New([]string{wecasa.Host}, httpx.Options{})
		if err != nil {
			t.Fatalf("httpx.New: %v", err)
		}
		if _, err := wecasa.Restore(hc2, blob); err != nil {
			t.Fatalf("Restore of a Persist blob: %v", err)
		}
	})
}

// fixedErrorText is every fixed word parseToken's errors use: the sentinel
// texts and the parser's messages (connectors/wecasa/parse.go).
var fixedErrorText = connector.ErrNeedsLogin.Error() + " " + connector.ErrBroken.Error() +
	" no window.wecasa block in the page; several window.wecasa blocks in the page;" +
	" window.wecasa block not closed; no token in the window.wecasa block;" +
	" several tokens in the window.wecasa block; token in the window.wecasa block is not a quoted string;" +
	" is not terminated; empty token; has an unexpected shape"
