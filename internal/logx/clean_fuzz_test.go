package logx_test

import (
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// fuzzKeys are sensitive keys and separators the fuzzer puts a short value
// after (see FuzzClean).
var fuzzKeys = []string{
	"password=", "password: ", "PASSWORD = ", "token:", `"token":"`, "pwd='",
	"Authorization: Bearer ", "Cookie: sid=", "session_id=", "otpCode=", "secret:",
}

// FuzzClean (SEC-J0-24) feeds hostile free text to Clean:
//   - it never panics;
//   - it never introduces a control byte (C0 or DEL) that was not in its
//     input: Clean does not strip controls (the handler does), but must not
//     forge them either;
//   - a canary token (FACTO-CANARY-<kind>-<26 base32 chars>) placed anywhere
//     between fuzzed text never survives, not even its random tail;
//   - it is idempotent: Clean(Clean(x)) == Clean(x);
//   - a short value (8 random canary characters, under the base64 run
//     threshold) right after a sensitive key, at a word boundary and followed
//     by a space, never survives, whatever text comes before it. The
//     corpus under testdata/fuzz/FuzzClean keeps the minimized inputs where
//     an earlier sensitive key or auth scheme swallows the next key and
//     leaves its value in clear (Cookie attributes, "token: password: v",
//     "Bearer pwd='v").
func FuzzClean(f *testing.F) {
	for _, s := range []string{
		"", "login failed", "Cookie: sid=abc; Path=/", `{"login":"bob","password":"hunter two"}`,
		`"{\"password\":\"hunter\"}"`, "Authorization: Bearer abcdef", "got Bearer abc.def",
		"user=bob&password=hunter&next=1", "password=***", "password=&next=1",
		`parse "https://u:p@h.test/x?q=1": invalid`, "https://user:secret@h.test/p?token=x#frag",
		"eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", "token:\"", `password\\\\ `, "a.b-c_d:",
		"x\x1b[2Jy\r\nlevel=INFO forged", "\x00\x7f",
	} {
		f.Add(s, s, uint8(0))
	}
	canary := testsecrets.Canary(f, testsecrets.Token)
	tail := canary[strings.LastIndex(canary, "-")+1:]
	short := tail[:8]

	f.Fuzz(func(t *testing.T, prefix, suffix string, key uint8) {
		// Raw input: no panic, no forged control byte.
		for _, in := range []string{prefix, prefix + suffix} {
			out := logx.Clean(in)
			for i := range len(out) {
				if c := out[i]; (c < 0x20 || c == 0x7f) && !strings.ContainsRune(in, rune(c)) {
					t.Fatalf("Clean(%q) = %q introduces control byte %#x", in, out, c)
				}
			}
		}

		// Idempotence.
		for _, x := range []string{prefix, prefix + suffix} {
			if once := logx.Clean(x); logx.Clean(once) != once {
				t.Fatalf("Clean not idempotent on %q: %q then %q", x, once, logx.Clean(once))
			}
		}

		// A canary token anywhere.
		in := prefix + canary + suffix
		if out := logx.Clean(in); strings.Contains(out, tail) {
			t.Fatalf("Clean(%q) = %q leaks the canary token", in, out)
		}

		// A short value after a sensitive key.
		k := fuzzKeys[int(key)%len(fuzzKeys)]
		in = prefix + " " + k + short + " " + suffix
		if out := logx.Clean(in); strings.Contains(out, short) && !strings.Contains(prefix+suffix, short) {
			t.Fatalf("Clean(%q) = %q leaks the value after %q", in, out, k)
		}
	})
}
