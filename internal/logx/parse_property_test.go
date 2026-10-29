package logx_test

// Contract (J0 review of maskParseErrors): whatever a net/url parse error
// quotes from a password never survives Clean nor the logging handler, in
// every way the error text gets embedded (raw, %q at any depth, JSON string or
// object, %w wrapping, errors.Join, after an escaped control character), and
// Clean stays linear in the length of its input.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/logx"
)

// prng is a splitmix64 generator: deterministic test input without
// math/rand (denied by depguard) or crypto/rand (not reproducible).
type prng struct{ state uint64 }

// IntN returns a pseudo-random int in [0, n), for 0 < n <= 65536.
func (p *prng) IntN(n int) int {
	p.state += 0x9e3779b97f4a7c15
	z := p.state
	z = (z ^ z>>30) * 0xbf58476d1ce4e5b9
	z = (z ^ z>>27) * 0x94d049bb133111eb
	z ^= z >> 31
	return int(uint16(z>>48)) % n // n is always small: the bias does not matter
}

// propMarker is embedded in every generated password; it must never survive.
const propMarker = "Qz7MRKv"

// propAlphabet holds the characters a generated password is drawn from,
// including every authority terminator, quote and escape character, the IPv6
// host brackets and control characters (which url.Parse rejects and %q
// escapes).
const propAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
	`/?#"' \@:%[]` + "\x01\x7f\t\n"

var propSchemes = []string{"https://", "postgres://", "ftp://", "//"}

// propPassword returns a random password holding propMarker, sometimes with
// leading or trailing spaces.
func propPassword(r *prng) string {
	var b strings.Builder
	if r.IntN(8) == 0 {
		b.WriteString(strings.Repeat(" ", 1+r.IntN(2)))
	}
	n := r.IntN(10)
	at := r.IntN(n + 1)
	for i := 0; i < n; i++ {
		if i == at {
			b.WriteString(propMarker)
		}
		b.WriteByte(propAlphabet[r.IntN(len(propAlphabet))])
	}
	if at == n {
		b.WriteString(propMarker)
	}
	if r.IntN(8) == 0 {
		b.WriteString(strings.Repeat(" ", 1+r.IntN(2)))
	}
	return b.String()
}

// propTokenTemplates hold pw as the whole userinfo of a hierarchical URL, in
// an opaque URL (no "//"), or in brackets that url.Parse takes for an IPv6
// host and quotes again in its reason; "%s" stands for pw.
var propTokenTemplates = []string{
	"https://%s@h/", "mailto:%s@h", "x:u:%s@h",
	"https://[%s]/x@h.example/", "mailto:\x01%s#x@h",
}

// propRawURL returns a random raw URL whose password is pw.
func propRawURL(r *prng, pw string) string {
	if r.IntN(4) == 0 {
		return strings.Replace(propTokenTemplates[r.IntN(len(propTokenTemplates))], "%s", pw, 1)
	}
	host := []string{"db.example", "host.example:5432", "h.example:x", "files.example"}[r.IntN(4)]
	path := []string{"", "/x", "/p?t=1", "/a#f"}[r.IntN(4)]
	user := []string{"u", "user", "bo b", ""}[r.IntN(4)]
	return propSchemes[r.IntN(len(propSchemes))] + user + ":" + pw + "@" + host + path
}

// propForms returns the ways the parse error err gets embedded in a log line.
func propForms(t *testing.T, err error) map[string]string {
	t.Helper()
	msg := err.Error()
	js, jerr := json.Marshal(msg)
	if jerr != nil {
		t.Fatal(jerr)
	}
	obj, jerr := json.Marshal(map[string]string{"error": "load: " + msg})
	if jerr != nil {
		t.Fatal(jerr)
	}
	joined := errors.Join(errors.New("first"), err).Error()
	jjs, jerr := json.Marshal(joined)
	if jerr != nil {
		t.Fatal(jerr)
	}
	return map[string]string{
		"raw":              msg,
		"percent-q":        fmt.Sprintf("%q", msg),
		"double percent-q": fmt.Sprintf("%q", fmt.Sprintf("%q", msg)),
		"json string":      string(js),
		"json object":      string(obj),
		"errorf wrap":      fmt.Errorf("fetch invoices: %w", err).Error(),
		"join percent-q":   fmt.Sprintf("%q", joined),
		"join json":        string(jjs),
		"tab percent-q":    fmt.Sprintf("%q", "x\t"+msg),
	}
}

func propCases(t *testing.T) int {
	t.Helper()
	if testing.Short() {
		return 4000
	}
	return 20000
}

func TestClean_RandomParseErrorsNeverKeepPassword(t *testing.T) {
	t.Parallel()
	r := &prng{state: 0xfac7010c5}
	leaks := map[string]int{}
	examples := map[string]string{}
	tested := 0
	for range propCases(t) {
		raw := propRawURL(r, propPassword(r))
		_, err := url.Parse(raw)
		if err == nil || !strings.Contains(err.Error(), propMarker) {
			continue
		}
		tested++
		for form, in := range propForms(t, err) {
			if got := logx.Clean(in); strings.Contains(got, propMarker) {
				leaks[form]++
				if _, ok := examples[form]; !ok {
					examples[form] = fmt.Sprintf("Clean(%q) = %q", in, got)
				}
			}
		}
	}
	if tested < 1000 {
		t.Fatalf("only %d generated URLs produced a parse error quoting the password", tested)
	}
	t.Logf("%d generated URLs gave a parse error quoting the password", tested)
	reportLeaks(t, tested, leaks, examples)
}

func TestHandler_RandomParseErrorsNeverLogged(t *testing.T) {
	t.Parallel()
	r := &prng{state: 0x5106fac7}
	leaks := map[string]int{}
	examples := map[string]string{}
	tested := 0
	n := propCases(t) / 10
	for range n {
		raw := propRawURL(r, propPassword(r))
		_, err := url.Parse(raw)
		if err == nil || !strings.Contains(err.Error(), propMarker) {
			continue
		}
		tested++
		for name, mk := range map[string]func(*bytes.Buffer) slog.Handler{
			"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
			"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		} {
			var buf bytes.Buffer
			log := slog.New(logx.NewHandler(mk(&buf), logx.Options{}))
			log.Info("m", "err", err)
			log.Info(err.Error())
			for form, in := range propForms(t, err) {
				log.Info("m", "body", in, "form", form)
			}
			if out := buf.String(); strings.Contains(out, propMarker) {
				leaks[name]++
				if _, ok := examples[name]; !ok {
					examples[name] = out
				}
			}
		}
	}
	if tested < 200 {
		t.Fatalf("only %d generated URLs produced a parse error quoting the password", tested)
	}
	t.Logf("%d generated URLs gave a parse error quoting the password", tested)
	reportLeaks(t, tested, leaks, examples)
}

func reportLeaks(t *testing.T, tested int, leaks map[string]int, examples map[string]string) {
	t.Helper()
	forms := make([]string, 0, len(leaks))
	for f := range leaks {
		forms = append(forms, f)
	}
	sort.Strings(forms)
	for _, f := range forms {
		t.Errorf("%s: %d/%d leaks, e.g. %s", f, leaks[f], tested, examples[f])
	}
}

func TestClean_ParseErrorRegressions(t *testing.T) {
	t.Parallel()
	errFor := func(raw string) error {
		_, err := url.Parse(raw)
		if err == nil || !strings.Contains(err.Error(), "MRK") {
			t.Fatalf("url.Parse(%q) = %v, the test needs an error quoting the password", raw, err)
		}
		return err
	}
	portErr := errFor("postgres://u: MRK/x@db:5432/x")
	spaceErr := errFor("//user:pa ssMRK@host/x")
	slashErr := errFor("https://user:pa/MRK@host.example/x")
	joined := errors.Join(errors.New("first"), slashErr).Error()
	tests := []struct{ name, in string }{
		{"port reason swallowed", portErr.Error()},
		{"port reason swallowed, percent-q", fmt.Sprintf("%q", portErr.Error())},
		{"scheme-relative with space", spaceErr.Error()},
		{"scheme-relative with space, percent-q", fmt.Sprintf("%q", spaceErr.Error())},
		{"errors.Join percent-q", fmt.Sprintf("%q", joined)},
		{"tab before parse, percent-q", fmt.Sprintf("%q", "x\t"+slashErr.Error())},
		{"unclosed non-URL argument before", `parse "abc ` + fmt.Sprintf("%q", spaceErr.Error())},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := logx.Clean(tt.in); strings.Contains(got, "MRK") {
				t.Errorf("Clean(%q) = %q, still contains the password", tt.in, got)
			}
		})
	}
}

// linearBudget is the time a 1 MB line may take: 2 s, or 10 s under the race
// detector, where the linear per-byte loops of Clean (maskBase64 among them)
// already take about 1 s per MB with coverage on. The quadratic scan this
// guards against took 87 s per MB without the race detector.
func linearBudget() time.Duration {
	if raceBuild {
		return 10 * time.Second
	}
	return 2 * time.Second
}

// depthUnits returns parse tokens delimited at every escaping depth from 0
// to 40 backslashes, none of them closed.
func depthUnits() string {
	var b strings.Builder
	for k := 0; k <= 40; k++ {
		b.WriteString("parse " + strings.Repeat(`\\`, k) + `"ab `)
	}
	return b.String()
}

func TestClean_LongLinesAreLinear(t *testing.T) {
	// Not parallel: a wall-clock budget is only meaningful when the test does
	// not share the CPU with the package's parallel property tests.
	const size = 1 << 20
	for name, unit := range map[string]string{
		"parse with colon":     `parse "a": `,
		"escaped parse quotes": `parse \"`,
		"URL-looking parse":    `parse "//a@b": `,
		"https parse":          `parse "https://a@b": `,
		"unclosed parse":       `parse "ab `,
		"escaped port reason":  `invalid port \"`,
		"reason after URL":     `parse "//a@b": invalid port "`,
		"every quoting depth":  depthUnits(),
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

func TestClean_ParseErrorRegressionsExact(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, in, want string }{
		{
			"port reason opening quote is not the argument end",
			`parse "postgres://u: MRK/x?y@db:5432/x?q": invalid port ": MRK" after host`,
			`parse "***@db:5432/x?***": invalid port "***" after host`,
		},
		{
			"port reason with an escaped quote",
			`parse "https://u:a\": MRK/x@h/": invalid port ":a\": MRK" after host`,
			`parse "***@h/": invalid port "***" after host`,
		},
		{
			"scheme-relative argument",
			`parse "//user:pa ss@host/x": net/url: invalid userinfo`,
			`parse "***@host/x": net/url: invalid userinfo`,
		},
		{
			"authority cut at a hash in the password",
			`parse "https://bo b:a@MRKhost": net/url: invalid userinfo`,
			`parse "***": net/url: invalid userinfo`,
		},
		{
			"tail that no host allows",
			`parse "//:a@Qr\\MRK": invalid character "\\" in host name`,
			`parse "***": invalid character "\\" in host name`,
		},
		{
			"bad escape in the userinfo",
			`parse "https://u:%MR@h/": invalid URL escape "%MR"`,
			`parse "***@h/": invalid URL escape "***"`,
		},
		{
			"escape letter before parse in a re-quoted text",
			`"first\nparse \"https://u:p/MRK@h/x\": bad"`,
			`"first\nparse \"***@h/x\": bad"`,
		},
		{
			"word before parse",
			`reparse "https://u:p/MRK@h/x": bad`,
			`reparse "***@h/x": bad`,
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
