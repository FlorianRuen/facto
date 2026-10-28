// Red-team findings (J0 T30) against internal/logx, now defended. Uses
// atkCanaries, atkLoggers and atkPersist from attack_test.go.
package logx_test

import (
	"bytes"
	"log/slog"
	"testing"
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
