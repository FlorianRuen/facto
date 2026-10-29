package logx_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
)

// Attribute keys and group names go through Clean and lose their control
// characters; plain keys are untouched and sensitivity still applies.
func TestHandler_CleansKeysAndGroupNames(t *testing.T) {
	t.Parallel()
	const tok = "AbCdEfGhIjKlMnOpQr1234" // synthetic, no sensitive word
	tests := []struct {
		name    string
		log     func(*slog.Logger)
		want    []string
		notWant []string
	}{
		{"plain key kept", func(l *slog.Logger) { l.Info("m", "provider_id", "a1") }, []string{`provider_id=a1`}, nil},
		{"token key masked", func(l *slog.Logger) { l.Info("m", tok, "v") }, []string{`***=v`}, []string{tok}},
		{"control chars removed", func(l *slog.Logger) { l.Info("m", "a\nlevel=ERROR b\x00c", "v") }, []string{`"alevel=ERROR bc"=v`}, []string{"\nlevel"}},
		{"token group", func(l *slog.Logger) { l.Info("m", slog.Group(tok, "a", "b")) }, []string{`***.a=b`}, []string{tok}},
		{"with group", func(l *slog.Logger) { l.WithGroup("g."+tok).Info("m", "a", "b") }, []string{`g.***.a=b`}, []string{tok}},
		{"with attrs", func(l *slog.Logger) { l.With(tok, 1).Info("m") }, []string{`***=1`}, []string{tok}},
		{"nested group", func(l *slog.Logger) {
			l.Info("m", slog.Group("outer", slog.Group(tok, "a", "b")))
		}, []string{`outer.***.a=b`}, []string{tok}},
		{"sensitive key still masked", func(l *slog.Logger) { l.Info("m", "Set-Cookie", "plainvalue") }, []string{`Set-Cookie=***`}, []string{"plainvalue"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			l := slog.New(logx.NewHandler(slog.NewTextHandler(&buf, nil), logx.Options{}))
			tt.log(l)
			out := buf.String()
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("output %q lacks %q", out, w)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(out, w) {
					t.Errorf("output %q contains %q", out, w)
				}
			}
		})
	}
}
