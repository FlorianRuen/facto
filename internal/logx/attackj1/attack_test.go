// Red-team attacks on the redacting handler with the log lines facto
// itself writes in J1 (task T27): connector Login errors logged by the
// orchestrator (slog.Any("error", err)), CDP and browser errors, cookies
// as values (connector.Cookie, http.Cookie, maps, groups), and forged
// lines through newlines. The secrets used are canaries and a lowercase
// hex value: the token pattern does not mask hex on its own, so the hex
// value is only hidden when the key, header or cookie rule applies. A
// test passes when no secret reaches the output. Everything is synthetic.
package attackj1_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

const syntheticHex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func loggers() map[string]func(*bytes.Buffer) *slog.Logger {
	return map[string]func(*bytes.Buffer) *slog.Logger{
		"text": func(b *bytes.Buffer) *slog.Logger {
			return slog.New(logx.NewHandler(slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug}), logx.Options{}))
		},
		"json": func(b *bytes.Buffer) *slog.Logger {
			return slog.New(logx.NewHandler(slog.NewJSONHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug}), logx.Options{}))
		},
	}
}

func assertClean(t *testing.T, out string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("log output holds a secret (%.12s...): %q", s, out)
		}
	}
}

// TestAttack_LogxConnectorLoginErrorsAsTheOrchestratorLogsThem: the
// orchestrator logs a failed Login as slog.Any("error", err). Errors that
// quote the session cookie as a header line, a cookie string, a JSON body,
// a form, an Authorization header or an http.Header are masked.
func TestAttack_LogxConnectorLoginErrorsAsTheOrchestratorLogsThem(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	ck := testsecrets.Canary(t, testsecrets.Cookie)
	form := url.Values{"login": {"synthetic"}, "password": {syntheticHex}}
	hdr := http.Header{"Cookie": {"sid=" + syntheticHex}, "X-Trace": {"t"}}
	errs := []error{
		fmt.Errorf("fakeprovider: login: %w", errors.New("unexpected Set-Cookie: sid="+syntheticHex+"; Path=/; HttpOnly")),
		fmt.Errorf("login: response %q", "Set-Cookie: session="+syntheticHex+"; Secure"),
		fmt.Errorf("login: cookie %s", (&http.Cookie{Name: "session", Value: syntheticHex, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}).String()),
		fmt.Errorf("login: cookie %s", (&http.Cookie{Name: "JSESSIONID", Value: syntheticHex, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}).String()),
		fmt.Errorf("login: cookie %s", (&http.Cookie{Name: "auth_token", Value: syntheticHex, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}).String()),
		fmt.Errorf("login: body {\"user\":\"synthetic\",\"password\":%q}", syntheticHex),
		fmt.Errorf("login: posted %s", form.Encode()),
		fmt.Errorf("login: sent headers %v", hdr),
		fmt.Errorf("login: Authorization: Bearer %s", syntheticHex),
		fmt.Errorf("login: Authorization: Basic %s", syntheticHex),
		fmt.Errorf("login: GET https://u:%s@login.supplier.example/x?sid=%s#%s", syntheticHex, syntheticHex, syntheticHex),
		fmt.Errorf("login: password=%s otp=%s token=%s", pw, syntheticHex[:6], ck),
		fmt.Errorf("wrapped: %w", fmt.Errorf("%q", fmt.Errorf("Cookie: sid=%s", syntheticHex).Error())),
		fmt.Errorf("login: %w", connector.ErrAuthFailed),
	}
	for name, mk := range loggers() {
		for i, err := range errs {
			var b bytes.Buffer
			mk(&b).Warn("connector failed; marked broken", slog.String("connector", "fakeprovider"),
				slog.String("phase", "login"), slog.Any("error", err))
			if i < len(errs)-1 {
				assertClean(t, b.String(), syntheticHex, pw, ck)
			}
			if strings.Count(b.String(), "\n") != 1 {
				t.Errorf("%s: case %d produced %d lines", name, i, strings.Count(b.String(), "\n"))
			}
		}
	}
}

// TestAttack_LogxCookiesAsValues: cookies logged as values (the
// connector's own type, http.Cookie, slices, maps keyed by cookie name,
// a "cookies" group, a struct holding the jar) never print a value.
func TestAttack_LogxCookiesAsValues(t *testing.T) {
	t.Parallel()
	ck := testsecrets.Canary(t, testsecrets.Cookie)
	cc := connector.Cookie{Name: "sid", Value: secret.FromString(syntheticHex), Domain: "login.supplier.example", Path: "/", Expires: time.Unix(0, 0)}
	hc := &http.Cookie{Name: "lc", Value: syntheticHex, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	type jar struct {
		Host    string
		Cookies []*http.Cookie
		Raw     map[string]string
	}
	attrs := []slog.Attr{
		slog.Any("cookie", cc),
		slog.Any("c", cc),
		slog.Any("cs", []connector.Cookie{cc, cc}),
		slog.Any("hc", hc),
		slog.Any("hcs", []*http.Cookie{hc, {Name: "x", Value: ck, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}}),
		slog.Group("cookies", slog.String("lc", syntheticHex)),
		slog.Any("jar", jar{Host: "login.supplier.example", Cookies: []*http.Cookie{hc}, Raw: map[string]string{"sid": syntheticHex}}),
		slog.Any("req", &http.Request{Header: http.Header{"Cookie": {"lc=" + syntheticHex}}}),
	}
	for name, mk := range loggers() {
		for _, a := range attrs {
			var b bytes.Buffer
			mk(&b).Debug("browser: cookies read", a)
			if strings.Contains(b.String(), syntheticHex) || strings.Contains(b.String(), ck) {
				t.Errorf("%s: attr %q printed a cookie value: %q", name, a.Key, b.String())
			}
		}
	}
}

// TestAttack_LogxForgedLinesAndEscapes: an error or attribute carrying a
// newline, a carriage return or an ANSI escape cannot forge a second log
// line nor drive the terminal.
func TestAttack_LogxForgedLinesAndEscapes(t *testing.T) {
	t.Parallel()
	forged := "x\nlevel=INFO msg=\"login ok\" connector=edf\r\x1b[2K\x1b]52;c;ZmFjdG8\a\u2028tail"
	for name, mk := range loggers() {
		var b bytes.Buffer
		mk(&b).Warn("connector failed", slog.Any("error", errors.New(forged)), slog.String("note", forged), slog.String(forged, "v"))
		out := b.String()
		if strings.Count(out, "\n") != 1 {
			t.Errorf("%s: forged line: %q", name, out)
		}
		if strings.ContainsAny(out, "\r\x1b\a\u2028\u2029\u0085") {
			t.Errorf("%s: control character reached the log: %q", name, out)
		}
	}
}
