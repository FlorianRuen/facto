package logx_test

// Contract: url.Parse quotes the raw URL in its error ("parse \"…\": …").
// When the userinfo holds an unencoded "/", "?" or "#", the authority seen
// by the URL patterns ends inside the password, so the userinfo is not
// recognized and the password would survive. Clean masks the quoted
// argument of such errors from the scheme up to its last "@", leaving a
// "***" hint, the host and the error reason.

import (
	"bytes"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
)

// parseErrorURLs are raw URLs whose password holds an unencoded authority
// terminator; the password always contains "pw7marker".
var parseErrorURLs = []string{
	"https://user:pw7marker/ss@host.example/x",
	"https://user:pw7marker#ss@host.example/",
	"https://user:pw7marker?ss@host.example/",
	"https://user:pa/pw7marker@host.example/x",
	"https://user:pa?pw7marker@host.example/",
}

func TestClean_MasksQuotedURLInParseErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{
			"slash in password",
			`parse "https://user:pa/ss@host.example/x": invalid port ":pa" after host`,
			`parse "***@host.example/x": invalid port "***" after host`,
		},
		{
			"hash in password",
			`parse "https://user:pa#ss@h/": invalid port ":pa" after host`,
			`parse "***@h/": invalid port "***" after host`,
		},
		{
			"hash in password as url.Parse quotes it",
			`parse "https://user:pa": invalid port ":pa" after host`,
			`parse "***": invalid port "***" after host`,
		},
		{
			"wrapped in context",
			`fetch: parse "ftp://u:p?w@files.example/a": bad`,
			`fetch: parse "***@files.example/a": bad`,
		},
		{
			"no scheme",
			`parse "user:pa/ss@host.example/x": first path segment in URL cannot contain colon`,
			`parse "***@host.example/x": first path segment in URL cannot contain colon`,
		},
		{
			"no at sign",
			`parse "https://host.example:x/": invalid port ":x" after host`,
			`parse "***": invalid port "***" after host`,
		},
		{
			"query and fragment after the host",
			`parse "https://u:p/w@h.example/p?token=abc#f": bad`,
			`parse "***@h.example/p?***": bad`,
		},
		{
			"at the end of the text",
			`bad url: parse "https://u:p/w@h.example/"`,
			`bad url: parse "***@h.example/"`,
		},
		{
			"escaped quote in the argument",
			`parse "https://u:p\"w/x@h.example/": net/url: invalid userinfo`,
			`parse "***@h.example/": net/url: invalid userinfo`,
		},
		{
			"other quoted text is kept",
			`open "report.pdf": permission denied`,
			`open "report.pdf": permission denied`,
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

func TestClean_RealParseErrorsNeverKeepPassword(t *testing.T) {
	t.Parallel()
	for _, raw := range parseErrorURLs {
		_, err := url.Parse(raw)
		if err == nil {
			t.Fatalf("url.Parse(%q) succeeded, the test needs a parse error", raw)
		}
		msg := err.Error()
		if !strings.Contains(msg, "pw7marker") {
			t.Fatalf("url.Parse(%q) error %q does not quote the URL, the test needs it to", raw, msg)
		}
		got := logx.Clean(msg)
		if strings.Contains(got, "pw7marker") {
			t.Errorf("Clean(%q) = %q, still contains the password", msg, got)
		}
		if !strings.Contains(got, `parse "`+logx.Mask) {
			t.Errorf("Clean(%q) = %q, want a masked parse hint", msg, got)
		}
	}
}

func TestHandler_ParseErrorWithSlashInPasswordNeverLogged(t *testing.T) {
	t.Parallel()
	for _, raw := range parseErrorURLs {
		_, err := url.Parse(raw)
		if err == nil {
			t.Fatalf("url.Parse(%q) succeeded, the test needs a parse error", raw)
		}
		var buf bytes.Buffer
		log := slog.New(logx.NewHandler(slog.NewJSONHandler(&buf, nil), logx.Options{}))
		log.Info("m", "perr", err)
		log.Info(err.Error())
		log.Info("m", "wrapped", "load config: "+err.Error())
		if out := buf.String(); strings.Contains(out, "pw7marker") {
			t.Errorf("logged %q, still contains the password", out)
		}
	}
}
