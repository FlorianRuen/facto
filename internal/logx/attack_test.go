// Red-team attack tests for the redacting handler (J0 task T30). Each test
// tries to get a testsecrets canary (or another secret shape) through the
// handler into a log file written under testsecrets.ArtifactDir, which
// `make leakcheck` greps. A test passes when the attack is defeated.
package logx_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/logx"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// atkCanaries returns one canary of every kind.
func atkCanaries(t *testing.T) (pw, cookie, token, sess string) {
	t.Helper()
	return testsecrets.Canary(t, testsecrets.Password), testsecrets.Canary(t, testsecrets.Cookie),
		testsecrets.Canary(t, testsecrets.Token), testsecrets.Canary(t, testsecrets.Session)
}

// atkPersist writes data under the test's ArtifactDir so leakcheck scans it.
func atkPersist(t *testing.T, name string, data []byte) {
	t.Helper()
	r, err := fsx.Open(testsecrets.ArtifactDir(t))
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if err := r.WriteAtomic(t.Context(), name, data); err != nil {
		t.Fatalf("WriteAtomic %s: %v", name, err)
	}
}

// atkLoggers returns a JSON and a text redacting logger over buffers.
func atkLoggers() map[string]struct {
	buf *bytes.Buffer
	log *slog.Logger
} {
	out := map[string]struct {
		buf *bytes.Buffer
		log *slog.Logger
	}{}
	for name, mk := range map[string]func(io.Writer) slog.Handler{
		"log.json": func(w io.Writer) slog.Handler {
			return slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug})
		},
		"log.txt": func(w io.Writer) slog.Handler {
			return slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug})
		},
	} {
		buf := &bytes.Buffer{}
		out[name] = struct {
			buf *bytes.Buffer
			log *slog.Logger
		}{buf, slog.New(logx.NewHandler(mk(buf), logx.Options{}))}
	}
	return out
}

// atkLeakyError is a connector error that prints its secret in Error().
type atkLeakyError struct{ Cookie, Detail string }

func (e atkLeakyError) Error() string { return "upstream refused session " + e.Cookie + " " + e.Detail }

// atkPanicky panics with the secret when rendered.
type atkPanicky struct{ v string }

func (p atkPanicky) String() string { panic("render " + p.v) }

// atkValuer hides a secret under a non-sensitive key of a LogValue group.
type atkValuer struct{ v string }

func (a atkValuer) LogValue() slog.Value {
	return slog.GroupValue(slog.String("detail", "state="+a.v), slog.Any("nested", []string{a.v}))
}

type atkDeep struct {
	Level1 struct {
		Level2 []map[string]any
	}
	hidden string
	Ptr    *string
	Arr    [2]string
	Raw    json.RawMessage
}

// TestAttack_LogxCanaryInValuesNeverWritten pushes canaries through every
// value path a connector or the core could use: message, string values,
// errors, error chains, nested composites, unexported fields, pointers,
// LogValuers, panicking Stringers, HTTP requests, headers, cookies, URLs,
// and a canary straddling the error length cap.
func TestAttack_LogxCanaryInValuesNeverWritten(t *testing.T) {
	t.Parallel()
	pw, cookie, token, sess := atkCanaries(t)
	canaries := []string{pw, cookie, token, sess}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"https://user:"+pw+"@api.fournisseur.test/dl/"+token+"?sid="+sess, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Cookie", "PHPSESSID="+cookie)
	req.Header.Set("X-Custom", token)

	deep := atkDeep{hidden: pw, Ptr: &token, Arr: [2]string{"ok", sess}, Raw: json.RawMessage(`"` + cookie + `"`)}
	deep.Level1.Level2 = []map[string]any{{"note": map[any]any{1: []any{struct{ V string }{cookie}}}}}

	// The canary straddles DefaultMaxErrorLen (512).
	straddle := strings.Repeat("a ", 250) + token + " tail"

	logAll := func(l *slog.Logger) {
		l.Info("message carries " + token)
		l.Info("m", "note", "cookie="+cookie, "list", []string{pw, sess})
		l.Error("m", "err", fmt.Errorf("login as synthetic-user with %s: %w", pw, io.EOF))
		l.Error("m", "err", errors.Join(errors.New("a "+sess), atkLeakyError{Cookie: cookie, Detail: token}))
		l.Error("m", "err", atkLeakyError{Cookie: cookie})
		l.Info("m", "deep", deep)
		l.Info("m", "valuer", atkValuer{v: sess})
		l.Info("m", "panicky", atkPanicky{v: pw})
		l.Info("m", "req", req, "hdr", req.Header, "url", req.URL)
		l.Info("m", "cookie", &http.Cookie{Name: "sid", Value: cookie, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		l.Info("m", "jar_cookie_named", &http.Cookie{Name: "note", Value: cookie, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		l.Info("m", "values", url.Values{"q": {token}})
		l.Info("m", "long", straddle)
		l.Error("m", "err", errors.New(straddle))
		l.Info("m", slog.Group("g", slog.String("x", token), slog.Any("y", map[string]string{"k": sess})))
		l.With("ctx", token).WithGroup("http").With("v", cookie).Info("m", "w", pw)
		l.Info("m", "bytes", []byte(pw), "runes_as_string", string([]rune(sess)))
	}

	for name, lg := range atkLoggers() {
		logAll(lg.log)
		out := lg.buf.Bytes()
		atkPersist(t, name, out)
		for _, c := range canaries {
			if bytes.Contains(out, []byte(c)) {
				t.Errorf("%s: canary %q leaked through a value path", name, c[:20])
			}
		}
	}
}
