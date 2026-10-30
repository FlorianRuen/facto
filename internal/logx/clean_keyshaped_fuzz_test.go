package logx_test

import (
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// keyShapedWords hold a sensitive key fragment; FuzzClean_KeyShapedValue
// builds values that look like a key followed by its separator.
var keyShapedWords = []string{
	"Token", "secret", "Pin", "Key", "Pass", "pwd", "Sid", "Code", "Auth", "Session", "otp", "Cookie",
}

// FuzzClean_KeyShapedValue (SEC-J0-24, review of T26): a value right after a
// sensitive key that itself reads like a key and its separator
// (password=ab12Token=cd34, token: abcdsecret: …) must never survive in
// part, whatever text comes before and after it: masks only grow over such
// values, never stop at the inner key.
func FuzzClean_KeyShapedValue(f *testing.F) {
	for _, s := range []string{
		"", "login failed", "Cookie: sid=abc; Path=/", "token:", "BeArer", `pwd:'`, `x="`, "Set-Cookie: a; Path=/",
	} {
		f.Add(s, "", uint8(0), uint8(0), uint8(0))
		f.Add(s, s, uint8(3), uint8(5), uint8(1))
	}
	canary := testsecrets.Canary(f, testsecrets.Token)
	tail := canary[strings.LastIndex(canary, "-")+1:]
	head, rest := tail[:4], tail[4:8]

	f.Fuzz(func(t *testing.T, prefix, suffix string, key, word, sep uint8) {
		k := fuzzKeys[int(key)%len(fuzzKeys)]
		w := keyShapedWords[int(word)%len(keyShapedWords)]
		v := head + w + rest + string(":="[sep%2])
		in := prefix + " " + k + v + " " + suffix
		out := logx.Clean(in)
		for _, piece := range []string{head, rest} {
			if strings.Contains(out, piece) && !strings.Contains(prefix+suffix, piece) {
				t.Fatalf("Clean(%q) = %q leaks %q of the key-shaped value after %q", in, out, piece, k)
			}
		}
		if logx.Clean(out) != out {
			t.Fatalf("Clean not idempotent on %q: %q then %q", in, out, logx.Clean(out))
		}
	})
}
