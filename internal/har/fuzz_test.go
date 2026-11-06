package har_test

import (
	"testing"

	"github.com/FlorianRuen/facto/internal/har"
)

// FuzzRedactBody_Idempotent: redacting a redacted body changes nothing.
// facto record checks every entry with har.Check before writing (a second
// redaction must be a no-op), so any instability makes a real recording
// fail with "redaction check failed".
func FuzzRedactBody_Idempotent(f *testing.F) {
	for _, s := range []string{
		`{"token":"abcdefgh","a":[{"password":"x1234567"}]}`,
		`<script>var c={token:"abcdefgh",list:"/api"};</script>`,
		`a = "token" : "secretvalue", password: 'abcdefg'`,
		`<input type="password" value="abcdefg"><meta name="csrf-token" content="zzzzzzzz">`,
		`Authorization: Bearer abcdefghijkl eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl`,
		`"token":"aaaaaa"token:"bbbbbbbb"`,
		// Minified single-page app bundles (J2, Wecasa).
		`e.token="abcdefgh",e.password=t.password||"",r={csrfToken:"zzzzzzzz"};`,
		`var a={"token":"abc","x":"defghijk"};b='session':'qwertyui'`,
		`n.headers.Authorization="Bearer "+e,o.token=e.token;i("token","abcdefghij")`,
		// Synthetic key-shaped values, split for secret scanners (SEC-J1-9).
		`{key:"AIza` + `SyA-abcdefghijklmnop",authDomain:"x.firebaseapp.com",apiKey:"AIza` + `SyB-1234567890abcd"}`,
		`sessionId: "abc\"defghij", token: "x\u0022yyyyyyy"`,
		`a.pin="1234567";b.pinned="yesyesyes";c.code='98765432'`,
		`token= "aaaaaaaa"token="bbbbbbbb"`,
	} {
		for _, mt := range []string{"text/html", "application/json", "text/javascript", "application/x-www-form-urlencoded"} {
			f.Add(mt, s)
		}
	}
	f.Fuzz(func(t *testing.T, mt, s string) {
		once := har.RedactBody(mt, s)
		if twice := har.RedactBody(mt, once); twice != once {
			t.Fatalf("not idempotent for %q:\nonce:  %q\ntwice: %q", mt, once, twice)
		}
	})
}

// FuzzRedactURL_Idempotent: the same for URLs (request URL, Location,
// Referer).
func FuzzRedactURL_Idempotent(f *testing.F) {
	for _, s := range []string{
		"https://a.test/x?token=abc&page=2#frag",
		"https://u:p@a.test/p%20q/[x]?a=b c&code=1",
		"/relative?access_token=x",
		"https://a.test/?q=Bearer%20abcdefghijkl",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		once := har.RedactURL(s)
		if twice := har.RedactURL(once); twice != once {
			t.Fatalf("not idempotent:\nin:    %q\nonce:  %q\ntwice: %q", s, once, twice)
		}
	})
}
