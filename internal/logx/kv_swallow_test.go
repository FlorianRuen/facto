package logx_test

import (
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
)

// TestClean_MasksValueAfterSwallowedKey (SEC-J0-24, found by FuzzClean and
// review): a sensitive key, an auth scheme or a kept Set-Cookie attribute
// must not swallow the next key and leave its value in clear. A value that
// holds a sensitive key and its separator stays masked whole, and the mask
// grows over that inner key's value: masks only grow. Every value is
// synthetic.
func TestClean_MasksValueAfterSwallowedKey(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, in, want string }{
		{"key value is a key", "token: password: deadbeef 0", "token: *** 0"},
		{"key value is a key with equals", "token=pwd=deadbeef", "token=***"},
		{"chain of keys", "token: secret: password: deadbeef", "token: ***"},
		{"key value is a plain word", "token: hello world", "token: *** world"},
		{"key value with a non-sensitive pair", "token=user=deadbeef", "token=***"},
		{"scheme credential is a quoted key", "BeArer pwd='deadbeef 0", "BeArer ***"},
		{"scheme credential is a key", "Bearer token=deadbeef", "Bearer ***"},
		{"cookie attribute then key", "Cookie: sid=abc; Path=/ password=deadbeef", "Cookie: ***; Path=/ password=***"},
		{"cookie attribute then quoted key", `Cookie: sid=abc; Path=/ "token":"deadbeef `, `Cookie: ***; Path=/ "token":"***`},
		{
			"cookie attribute then a second cookie",
			"Cookie: sid=abc; Path=/ password=deadbeef Cookie: sid=abc; Path=/",
			"Cookie: ***; Path=/ password=*** Cookie: ***; Path=/",
		},
		// A cookie pair whose name is not a cookie name (letters, digits, "_",
		// "-", ".") is a swallowed value: masked whole.
		{"cookie swallowed key, value as a name", "Cookie: password: deadbeef =", "Cookie: ***"},
		{"cookie swallowed quoted value as a name", "Cookie: pwd='deadbeef =", "Cookie: ***"},
		{"cookie name with a space", "Cookie: a=1; dead beef=2", "Cookie: ***; ***"},
		{"cookie usual names kept", "Cookie: __Host-sid=1; _ga.x=2", "Cookie: ***; _ga.x=***"},
		// A quoted value ending with a key and its separator: the closing
		// quote opens that key's value, which the mask covers too.
		{"quoted value swallows a quoted key", "Cookie:' pwd='deadbeef 0", "Cookie:'***"},
		{"quoted value ends with a key", `token:"a b password="deadbeef" c`, `token:"***" c`},
		{"quoted value is a key", `token:"password="deadbeef"`, `token:"***"`},
		{"quoted value holds a key with another quote", `password="a pwd='x" deadbeef' c`, `password="***`},
		{"quoted value ends with a plain word", `token:"a b="c`, `token:"***"c`},
		{"cookie header in an attribute value", "Cookie:0 PAth=Cookie:&000", "Cookie:*** PAth=Cookie:***"},
		// Adjacent masks merge: "******" would be masked again by a second Clean.
		{"cookie first value touching a bare segment", `Cookie:0"`, "Cookie:***"},
		{"cookie first value touching a quoted segment", `Cookie: a"b; c=1`, "Cookie: ***; c=***"},
		{"cookie segment touching a masked token", `Cookie:00000000000000A0"`, "Cookie:***"},
		{"cookie segment touching a mask in the input", `Cookie: ***"`, "Cookie: ***"},
		// Review (T26): key-shaped values stay masked whole (base masked them).
		{"value ends with a key fragment", "password=hunter2Token=", "password=***"},
		{"value ends with a secret fragment", "password=xyzsecret=", "password=***"},
		{"key value ends with a fragment", "api_key: sk_live_secret=", "api_key: ***"},
		{"session value with a key fragment", "session=Q2tKeyZ9=", "session=***"},
		{"scheme credential ends with a fragment", "msg Bearer abToken=", "msg Bearer ***"},
		{"value is a key with nothing after", "token: password=", "token: ***"},
		{"value is a key then a scheme", "password=Secret:Basic", "password=***"},
		{"second key value is a key", "otp=123456 code: pin=", "otp=*** code: ***"},
		{"value holds a key prefix", "password=MySecret=2024", "password=***"},
		{"value runs into the next key", "got Bearer token= deadbeef x", "got Bearer *** x"},
		// Review (T26): quoted values in cookie attribute values.
		{"quoted value overruns an attribute", `Cookie: a; Path=/x token="abc;def" password=LEAKME1`, `Cookie: ***; Path=/x token="***" ***`},
		{"unclosed quoted value in an attribute", `Set-Cookie: a; Path=/ token:"x Set-Cookie: a; Path=/ token:"x `, `Set-Cookie: ***; Path=/ token:"***`},
		{"attribute quoted value ends with a key", `Set-Cookie: a; Path=/ token:"x token:"LEAKME1 `, `Set-Cookie: ***; Path=/ token:"***`},
		{"attribute quoted value ends with the same key", `Cookie: a; Path=/ pwd="x pwd="LEAKME1 more`, `Cookie: ***; Path=/ pwd="***`},
		{"attribute quoted value over a semicolon", `Cookie: a; Path=/ pwd='x; pwd='LEAKME1 more`, `Cookie: ***; Path=/ pwd='***`},
		{"attribute unclosed quoted value", `Cookie: a; Path=/ pwd="x secret: LEAKME1 ; b=1`, `Cookie: ***; Path=/ pwd="***`},
		{"attribute quoted value over a semicolon, then nothing", `Cookie:,PAth=token=";" `, `Cookie:,PAth=token="***" `},
		{"attribute quoted value then key", `Cookie: a; Path=/ pwd="x" secret: LEAKME1 ; b=1`, `Cookie: ***; Path=/ pwd="***" secret: *** ; b=***`},
		{"bracketed cookie attribute then key", "map[Set-Cookie:[a=1; Path=/ pwd=deadbeef] X:[1]]", "map[Set-Cookie:[a=***; Path=/ pwd=***] X:[1]]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := logx.Clean(tt.in)
			if got != tt.want {
				t.Errorf("Clean(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if again := logx.Clean(got); again != got {
				t.Errorf("Clean not idempotent: %q then %q", got, again)
			}
		})
	}
}

// TestClean_SwallowedKeysLinear: resuming at a key inside a value, and
// rescanning kept cookie attribute values, must stay linear. Not parallel on
// purpose (see TestClean_HeaderLinesLinear).
func TestClean_SwallowedKeysLinear(t *testing.T) {
	assertCleanLinear(t, map[string]string{
		"key chain":               "pwd=",
		"key chain with colons":   "token:",
		"scheme then key chain":   "Bearer pwd=",
		"attribute key chain":     "Cookie: a; Path=/ pwd=",
		"attribute cookie chain":  "Path=/ Cookie: a; ",
		"nested bracketed cookie": "Cookie:[a; Path=",
		"nested cookie no space":  "Cookie:a;Path=",
		"cookie path chain":       "Cookie: Path=",
		"value then key chain":    "token: pwd: ",
		"quoted values in values": "pwd=\"a pwd='",
		"quotes in a grown span":  "pwd=\"pwd='",
		"schemes in a grown span": "pwd=Bearer ",
		"headers in a grown span": "a=\"Authorization:x ",
		"escaped quotes in spans": "pwd=\\\"",
		"quoted key chain":        "pwd:' ",
		"quoted tail key chain":   "token:\"a b pwd=",
	})
}
