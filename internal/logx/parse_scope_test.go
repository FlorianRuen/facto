package logx_test

// Contract (J0 follow-up): the parse-error masking of maskParseErrors is
// scoped to URLs and survives re-quoting.
//
//   - Scope: the quoted argument of `parse "<arg>"` is masked only when it
//     looks like a URL (it contains "://" or starts with a scheme followed by
//     ":"). Config, file and other parse errors are left alone. When the
//     argument holds no "@", it stops at the first `": `; a URL-looking
//     argument with an "@" still runs to the last closing quote of the line
//     (passwords may hold quotes).
//   - Re-quoting: the same masking applies when the error text was embedded
//     with %q or JSON-encoded, where the delimiting quotes are escaped
//     (`parse \"…\": …`, `invalid port \"…\" after host`), at any depth.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
)

func TestClean_ParseMaskingScopedToURLs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{
			"config parse error",
			`config: parse "x.toml": unknown key "foo"`,
			`config: parse "x.toml": unknown key "foo"`,
		},
		{
			"file parse error",
			`could not parse "config.toml": line 3`,
			`could not parse "config.toml": line 3`,
		},
		{
			"two non-URL parse errors",
			`parse "a": x; then parse "b": y`,
			`parse "a": x; then parse "b": y`,
		},
		{
			"non-URL argument with an at sign later",
			`load: parse "settings.json": bad value "x@y"`,
			`load: parse "settings.json": bad value "x@y"`,
		},
		{
			"URL after a non-URL parse error",
			`parse "a": x; then parse "https://u:p/w@h.example/": y`,
			`parse "a": x; then parse "***@h.example/": y`,
		},
		{
			"URL without at sign stops at the first closing quote",
			`parse "https://h.example:x/": invalid port ":x" after host; see "doc"`,
			`parse "***": invalid port "***" after host; see "doc"`,
		},
		{
			"scheme without slashes",
			`parse "mailto:u:p/w@h.example": bad`,
			`parse "***@h.example": bad`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := logx.Clean(tt.in); got != tt.want {
				t.Errorf("Clean(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestClean_MasksReQuotedParseErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{
			"backslash-escaped quotes",
			`parse \"https://user:pa/S3cr3tPW@host.example/x\": invalid port \":pa\" after host`,
			`parse \"***@host.example/x\": invalid port \"***\" after host`,
		},
		{
			"percent-q at the end of the string",
			`"bad url: parse \"https://u:p/w@h.example/\""`,
			`"bad url: parse \"***@h.example/\""`,
		},
		{
			"JSON object",
			`{"err":"parse \"https://u:p?w@h.example/p?t=1\": bad"}`,
			`{"err":"parse \"***@h.example/p?***\": bad"}`,
		},
		{
			"JSON object, no at sign",
			`{"err":"parse \"https://h.example:pw/\": invalid port \":pw\" after host"}`,
			`{"err":"parse \"***\": invalid port \"***\" after host"}`,
		},
		{
			"double-escaped quotes",
			`"\"parse \\\"https://u:p/w@h.example/x\\\": invalid port \\\":p\\\" after host\""`,
			`"\"parse \\\"***@h.example/x\\\": invalid port \\\"***\\\" after host\""`,
		},
		{
			"escaped non-URL argument is kept",
			`{"err":"config: parse \"x.toml\": unknown key \"foo\""}`,
			`{"err":"config: parse \"x.toml\": unknown key \"foo\""}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := logx.Clean(tt.in); got != tt.want {
				t.Errorf("Clean(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
}

// reQuotedURLs are raw URLs that url.Parse rejects while quoting a password
// that holds "/", "?", "#", a double quote or a space; the quoted part always
// contains "pw7marker".
var reQuotedURLs = []string{
	"https://user:pa/pw7marker@host.example/x",
	"https://user:pw7marker/ss@host.example/x",
	"https://user:pa?pw7marker@host.example/",
	"https://user:pw7marker#ss@host.example/",
	`https://bob:hu"pw7marker@h.example/`,
	"https://bob:hun pw7marker@h.example/",
	`https://u:a/b"c d?pw7marker@h.example/`,
}

// reQuote returns the ways an error text gets embedded in another string.
func reQuote(t *testing.T, msg string) map[string]string {
	t.Helper()
	js, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := json.Marshal(map[string]string{"error": "load: " + msg})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"percent-q":         fmt.Sprintf("%q", msg),
		"wrapped percent-q": fmt.Sprintf("fetch %q failed", msg),
		"double percent-q":  fmt.Sprintf("%q", fmt.Sprintf("%q", msg)),
		"json string":       string(js),
		"json object":       string(obj),
	}
}

func TestClean_ReQuotedRealParseErrorsNeverKeepPassword(t *testing.T) {
	t.Parallel()
	for _, raw := range reQuotedURLs {
		_, err := url.Parse(raw)
		if err == nil {
			t.Fatalf("url.Parse(%q) succeeded, the test needs a parse error", raw)
		}
		msg := err.Error()
		if !strings.Contains(msg, "pw7marker") {
			t.Fatalf("url.Parse(%q) error %q does not quote the password, the test needs it to", raw, msg)
		}
		for form, in := range reQuote(t, msg) {
			if got := logx.Clean(in); strings.Contains(got, "pw7marker") {
				t.Errorf("%s: Clean(%q) = %q, still contains the password", form, in, got)
			}
		}
	}
}

func TestHandler_ReQuotedParseErrorNeverLogged(t *testing.T) {
	t.Parallel()
	for _, raw := range reQuotedURLs {
		_, err := url.Parse(raw)
		if err == nil {
			t.Fatalf("url.Parse(%q) succeeded, the test needs a parse error", raw)
		}
		var buf bytes.Buffer
		log := slog.New(logx.NewHandler(slog.NewJSONHandler(&buf, nil), logx.Options{}))
		for form, in := range reQuote(t, err.Error()) {
			log.Info("m", "body", in, "form", form)
		}
		if out := buf.String(); strings.Contains(out, "pw7marker") {
			t.Errorf("logged %q, still contains the password", out)
		}
	}
}
