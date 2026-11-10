package wecasa_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/connectors/wecasa"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// TestParseToken_StrictInsideWindowWecasa: the token is read only from
// the window.wecasa = { ... } block, single or double quoted, with a
// strict charset. No token → ErrNeedsLogin (the session is gone); a token
// of the wrong shape or an ambiguous block → ErrBroken. Errors never echo
// the page.
func TestParseToken_StrictInsideWindowWecasa(t *testing.T) {
	t.Parallel()
	tok := testsecrets.Canary(t, testsecrets.Token)
	block := func(body string) string {
		return "<script>\n  window.wecasa = {\n" + body + "\n  };\n</script>"
	}
	tests := []struct {
		name    string
		page    string
		want    string
		wantErr error
	}{
		{name: "single quotes", page: block("    token: '" + tok + "',\n    locale: 'fr-FR'"), want: tok},
		{name: "double quotes", page: block(`    token: "` + tok + `",`), want: tok},
		{name: "token not first", page: block("    locale: 'fr-FR',\n    token: '" + tok + "'"), want: tok},
		{name: "compact", page: "<script>window.wecasa={token:'" + tok + "'}</script>", want: tok},
		{name: "charset edge", page: block("token: 'aZ09._~+/=-aZ09._~+/=-'"), want: "aZ09._~+/=-aZ09._~+/=-"},
		{name: "no block", page: "<html><body>login</body></html>", wantErr: connector.ErrNeedsLogin},
		{name: "token outside the block", page: "<script>var x = {token: '" + tok + "'};</script>" + block("locale: 'fr-FR'"), wantErr: connector.ErrNeedsLogin},
		{name: "token after the block", page: block("locale: 'fr-FR'") + "<script>x = {token: '" + tok + "'}</script>", wantErr: connector.ErrNeedsLogin},
		{name: "empty token", page: block("token: '',"), wantErr: connector.ErrNeedsLogin},
		{name: "other key ending in token", page: block("csrftoken: '" + tok + "',"), wantErr: connector.ErrNeedsLogin},
		{name: "too short", page: block("token: 'abcdefghijklmno',"), wantErr: connector.ErrBroken},
		{name: "too long", page: block("token: '" + strings.Repeat("a", 513) + "',"), wantErr: connector.ErrBroken},
		{name: "space inside", page: block("token: 'abcdefgh ijklmnopq',"), wantErr: connector.ErrBroken},
		{name: "quote break-out", page: block(`token: 'abcdefghijklmnop"<x>',`), wantErr: connector.ErrBroken},
		{name: "mismatched quotes", page: block(`token: 'abcdefghijklmnopq",`), wantErr: connector.ErrBroken},
		{name: "template literal", page: block("token: `abcdefghijklmnopq`,"), wantErr: connector.ErrBroken},
		{name: "unquoted", page: block("token: someVariable,"), wantErr: connector.ErrBroken},
		{name: "two tokens", page: block("token: '" + tok + "',\n token: 'abcdefghijklmnopq'"), wantErr: connector.ErrBroken},
		{name: "two blocks", page: block("token: '"+tok+"'") + block("token: '"+tok+"'"), wantErr: connector.ErrBroken},
		{name: "unterminated block", page: "<script>window.wecasa = {\n token: '" + tok + "',\n", wantErr: connector.ErrBroken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := wecasa.ParseToken([]byte(tt.page))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseToken = %v, want %v", err, tt.wantErr)
				}
				if !got.IsZero() {
					t.Error("ParseToken returned a token with its error")
				}
				if strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), "abcdefgh") {
					t.Errorf("error echoes the page: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseToken: %v", err)
			}
			if got.Expose() != tt.want {
				t.Errorf("token = %q, want %q", got.Expose(), tt.want)
			}
		})
	}
}

// TestParseToken_RecordedPage: the sanitized recording, with a token put
// back where the sanitizer wrote '[redacted]', parses; the page as
// recorded (token redacted) does not hold a usable token.
func TestParseToken_RecordedPage(t *testing.T) {
	t.Parallel()
	tok := testsecrets.Canary(t, testsecrets.Token)
	got, err := wecasa.ParseToken(pageWithToken(t, "token: '"+tok+"'"))
	if err != nil {
		t.Fatalf("ParseToken(recorded page): %v", err)
	}
	if got.Expose() != tok {
		t.Errorf("token = %q, want the canary", got.Expose())
	}
	if _, err := wecasa.ParseToken(fixture(t, fxPage)); !errors.Is(err, connector.ErrBroken) {
		t.Errorf("ParseToken(page with '[redacted]') = %v, want ErrBroken (bad charset)", err)
	}
	for _, f := range []string{fxLogin, "005-get-customer-area.html"} {
		if _, err := wecasa.ParseToken(fixture(t, f)); !errors.Is(err, connector.ErrNeedsLogin) {
			t.Errorf("ParseToken(%s) = %v, want ErrNeedsLogin", f, err)
		}
	}
}
