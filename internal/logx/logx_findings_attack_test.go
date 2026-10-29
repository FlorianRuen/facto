// Red-team findings (J0 T30) against internal/logx, now defended. Uses
// atkCanaries, atkLoggers and atkPersist from attack_test.go.
package logx_test

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
)

// TestAttack_LogxCanaryInAttrKeysNeverWritten puts the canary in attribute
// KEYS and group NAMES: a buggy connector writing log.Info("m", tok, true)
// or WithGroup(cookieValue). The handler cleans values, map keys and the
// message; keys reach the inner handler as they are.
func TestAttack_LogxCanaryInAttrKeysNeverWritten(t *testing.T) {
	t.Parallel()
	pw, cookie, token, sess := atkCanaries(t)
	canaries := []string{pw, cookie, token, sess}
	for name, lg := range atkLoggers() {
		l := lg.log
		l.Info("m", slog.String(token, "present"))
		l.Info("m", slog.Group(cookie, slog.String("a", "b")))
		l.WithGroup(sess).Info("m", "a", "b")
		l.With(slog.Bool(pw, true)).Info("m")
		out := lg.buf.Bytes()
		atkPersist(t, name, out)
		for _, c := range canaries {
			if bytes.Contains(out, []byte(c)) {
				t.Errorf("%s: canary leaked through an attribute key or group name", name)
			}
		}
	}
}

// TestAttack_LogxFreeTextKeyValueSecrets logs error texts that quote a raw
// header or form body. The secret values are realistic shapes the pattern
// masking skips on purpose (lowercase hex session id, lowercase word
// password), but they follow a sensitive key inside the text.
func TestAttack_LogxFreeTextKeyValueSecrets(t *testing.T) {
	t.Parallel()
	const (
		hexSID = "5f2b9c0e7a1d4c3b8e6f0a9d2c7b1e4f" // synthetic, 32 lowercase hex
		wordPW = "correcthorsebatterystaple"        // synthetic, all lowercase
	)
	tests := []struct{ name, text, secret string }{
		{"set-cookie header in error", "unexpected response: Set-Cookie: PHPSESSID=" + hexSID + "; Path=/", hexSID},
		{"cookie header in error", "request failed, Cookie: sid=" + hexSID, hexSID},
		{"bearer in error", "401 for Authorization: Bearer " + hexSID, hexSID},
		{"form body in error", "login form rejected: username=synthetic&password=" + wordPW, wordPW},
		{"json body in error", `bad body {"login":"synthetic","password":"` + wordPW + `"}`, wordPW},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			l := slog.New(logx.NewHandler(slog.NewJSONHandler(&buf, nil), logx.Options{}))
			l.Error("connector stopped", "error", errors.New(tt.text))
			l.Info(tt.text)
			if strings.Contains(buf.String(), tt.secret) {
				t.Errorf("secret after a sensitive key in free text was logged:\n%s", buf.String())
			}
		})
	}
}
