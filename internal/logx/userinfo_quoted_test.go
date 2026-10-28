package logx_test

// Contract (rule 16): userinfo is removed from a URL of any scheme even when
// the password holds characters that end a URL match, such as a space or a
// double quote. url.Parse quotes the raw URL in its error exactly in that case
// ("net/url: invalid userinfo"), so the password must not survive Clean or the
// handler. Over-masking up to the last "@" of the authority is acceptable.

import (
	"bytes"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
)

func TestClean_StripsUserinfoWithSpaceOrQuote(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, secret string
	}{
		{"space in password", `parse "https://bob:hun ter2@h.example/": net/url: invalid userinfo`, "ter2"},
		{"quote in password", `parse "https://bob:hu"nter2@h.example/": net/url: invalid userinfo`, "nter2"},
		{"space in user", `dial ftp://bo b:pwmarker7@h.example/p`, "pwmarker7"},
		{"tab in password", "proxy socks5://u:pw\tmarker8@h.example:1080", "marker8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := logx.Clean(tt.in)
			if strings.Contains(got, tt.secret) {
				t.Errorf("Clean(%q) = %q, still contains the password", tt.in, got)
			}
			if !strings.Contains(got, "h.example") {
				t.Errorf("Clean(%q) = %q, want the host kept", tt.in, got)
			}
		})
	}
}

func TestClean_KeepsTextWithoutUserinfo(t *testing.T) {
	t.Parallel()
	tests := []string{
		"see https://h.example/a b@c for details",
		"mail bob@h.example about it",
		"ok https://h.example/p and later x@y",
	}
	for _, in := range tests {
		if got := logx.Clean(in); got != in {
			t.Errorf("Clean(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestHandler_URLParseErrorNeverLogsPassword(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://bob:hun ter2@h.example/",
		`https://bob:hu"nter2@h.example/`,
	} {
		_, err := url.Parse(raw)
		if err == nil {
			t.Fatalf("url.Parse(%q) succeeded, the test needs an invalid-userinfo error", raw)
		}
		var buf bytes.Buffer
		log := slog.New(logx.NewHandler(slog.NewTextHandler(&buf, nil), logx.Options{}))
		log.Info("m", "perr", err)
		log.Info(err.Error())
		if out := buf.String(); strings.Contains(out, "ter2") || strings.Contains(out, "nter2") {
			t.Errorf("logged %q, still contains the password", out)
		}
	}
}
