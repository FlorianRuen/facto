package logx_test

import (
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/logx"
)

func TestClean_MasksValueAfterSensitiveKeyInFreeText(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, in, want string }{
		{"equals", "login failed password=hunter", "login failed password=***"},
		{"colon space", "Cookie: sid=abc; Path=/", "Cookie: ***; Path=/"},
		{"set-cookie", "Set-Cookie: PHPSESSID=5f2b9c0e; HttpOnly", "Set-Cookie: ***; HttpOnly"},
		{"case-insensitive key", "PASSWORD = hunter", "PASSWORD = ***"},
		{"form body", "user=bob&password=hunter&next=1", "user=bob&password=***&next=1"},
		{"json", `{"login":"bob","password":"hunter two"}`, `{"login":"bob","password":"***"}`},
		{"json escaped quote in value", `{"token":"a\"b","x":1}`, `{"token":"***","x":1}`},
		{"re-quoted json", `"{\"password\":\"hunter\"}"`, `"{\"password\":\"***\"}"`},
		{"single quotes", "pwd='hunter'", "pwd='***'"},
		{"bearer", "Authorization: Bearer abcdef", "Authorization: Bearer ***"},
		{"basic lower", "header basic dXNlcjpw", "header basic ***"},
		{"bearer alone", "got Bearer abc.def", "got Bearer ***"},
		{"whole word short key", "X-Auth: abc", "X-Auth: ***"},
		{"camel case key", "otpCode=123456", "otpCode=***"},
		{"session id", "session_id=deadbeef", "session_id=***"},
		{"already masked", "password=***", "password=***"},
		{"empty value", "password=&next=1", "password=&next=1"},
		{"value to end", "secret:abc", "secret:***"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := logx.Clean(tt.in); got != tt.want {
				t.Errorf("Clean(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestClean_KeepsNonSensitiveKeyValues(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"author: bob",
		"keyboard=fr",
		"barcode=12345",
		"provider_id=a1 status=filed",
		"run: fetch: connector stopped",
		"basically fine",
		"bearer",
		"at 10:00:00 phase=list",
		"net/url: invalid userinfo",
	} {
		if got := logx.Clean(in); got != in {
			t.Errorf("Clean(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestClean_KeyValueMaskingIsLinear(t *testing.T) {
	// Not parallel: a wall-clock budget is only meaningful when the test does
	// not share the CPU with the package's parallel property tests.
	const size = 1 << 20
	for name, unit := range map[string]string{
		"keys without separator": "password ",
		"keys with empty values": "password=&",
		"bearer chain":           "Bearer ",
		"escaped key quotes":     `password\\\\\\\\ `,
		"unclosed quoted value":  `token:"`,
		"escaped quoted value":   `token:\\"a\\`,
		"short word keys":        "a.b-c_d:",
	} {
		in := strings.Repeat(unit, size/len(unit))
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = logx.Clean(in)
		}()
		timer := time.NewTimer(linearBudget())
		select {
		case <-done:
			timer.Stop()
		case <-timer.C:
			t.Errorf("%s: Clean of a 1 MB line still running after %v, want linear time", name, linearBudget())
			<-done
		}
	}
}
