// Tests for J1 task T5: concrete Env interfaces and the session persistence
// contract (plan docs/agentic/plans/J1.md, decisions A5 and A9).
//
// Expected API (implementer: follow exactly):
//
//	// SecretResolver resolves bw://, keyring://… references. *secret.Resolver
//	// satisfies it.
//	type SecretResolver interface {
//	    Resolve(ctx context.Context, ref string) (secret.Secret, error)
//	}
//
//	// PromptRequest is what a connector asks the user. Label may come from
//	// the supplier site and is untrusted.
//	type PromptRequest struct {
//	    Label string
//	}
//	// MaxPromptLabelLen caps CleanLabel's output, in bytes.
//	const MaxPromptLabelLen = 128
//	// CleanLabel returns Label safe for one terminal line:
//	//   - ANSI escape sequences are removed whole: CSI (ESC '[' or the 8-bit
//	//     U+009B, up to the final byte 0x40–0x7E) and OSC (ESC ']', up to BEL
//	//     or ESC '\');
//	//   - \t, \r, \n become a space; every other rune that is not
//	//     unicode.IsPrint (C0, C1, DEL, bidi and other format characters,
//	//     line/paragraph separators) is removed; invalid UTF-8 bytes are
//	//     removed;
//	//   - logx.Clean masks token-like content (URL queries, JWTs, base64 runs);
//	//   - leading and trailing spaces are trimmed;
//	//   - the result is cut to MaxPromptLabelLen bytes on a rune boundary.
//	// Every Prompter implementation must display CleanLabel(), never Label.
//	func (r PromptRequest) CleanLabel() string
//
//	// Prompter asks the interactive user for a value such as an OTP code.
//	type Prompter interface {
//	    Prompt(ctx context.Context, req PromptRequest) (secret.Secret, error)
//	    Interactive() bool
//	}
//
//	// LaunchOptions configures one browser for one login.
//	type LaunchOptions struct {
//	    AllowedDomains []string // connector Info().AllowedDomains (A11)
//	    Visible        bool     // headful window; only when interactive
//	}
//
//	// BrowserPool hands out library-neutral browsers.
//	type BrowserPool interface {
//	    Launch(ctx context.Context, opts LaunchOptions) (Browser, error)
//	}
//
//	// Browser is the library-neutral page API. No method takes or returns a
//	// secret as a plain string.
//	type Browser interface {
//	    Navigate(ctx context.Context, url string) error
//	    WaitVisible(ctx context.Context, selector string) error
//	    TypeSecret(ctx context.Context, selector string, value secret.Secret) error
//	    Click(ctx context.Context, selector string) error
//	    CurrentURL(ctx context.Context) (string, error)
//	    Cookies(ctx context.Context, domains []string) ([]Cookie, error)
//	    Close() error
//	}
//
//	// Cookie is one browser cookie; its value is a secret.
//	type Cookie struct {
//	    Name     string
//	    Value    secret.Secret
//	    Domain   string
//	    Path     string
//	    Expires  time.Time // zero = session cookie
//	    Secure   bool
//	    HTTPOnly bool
//	}
//
//	// Credentials holds secret REFERENCES (bw://…, keyring://…), never values.
//	// OTP resolves to a code, never a seed (A5). Empty = not configured.
//	type Credentials struct {
//	    Login, Password, OTP string
//	}
//
//	type Env struct {
//	    Secrets     SecretResolver
//	    Browser     BrowserPool
//	    HTTP        *httpx.Client
//	    Prompt      Prompter
//	    Log         *slog.Logger
//	    Saved       secret.Secret // restored session blob; zero (IsZero) when none
//	    Credentials Credentials
//	    Interactive bool
//	}
//
//	// Persistable is optionally implemented by the Session a connector's
//	// Login returns. The orchestrator type-asserts it after a successful
//	// login, stores the blob encrypted, and hands it back as Env.Saved on the
//	// next run (A9). Sessions that do not implement it are never saved.
//	type Persistable interface {
//	    Persist(ctx context.Context) (secret.Secret, error)
//	}
package connector_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/secret"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// Compile-time contract checks.
var (
	_ connector.SecretResolver = (*secret.Resolver)(nil)
	_ connector.Prompter       = (*fakePrompter)(nil)
	_ connector.BrowserPool    = (*fakePool)(nil)
	_ connector.Browser        = (*fakeBrowser)(nil)
	_ connector.Persistable    = persistSession{}
)

// Method signatures pinned through method expressions: a secret parameter or
// result silently turning into a string fails to compile here.
var (
	_ func(connector.SecretResolver, context.Context, string) (secret.Secret, error)                   = connector.SecretResolver.Resolve
	_ func(connector.Prompter, context.Context, connector.PromptRequest) (secret.Secret, error)        = connector.Prompter.Prompt
	_ func(connector.Prompter) bool                                                                    = connector.Prompter.Interactive
	_ func(connector.BrowserPool, context.Context, connector.LaunchOptions) (connector.Browser, error) = connector.BrowserPool.Launch
	_ func(connector.Browser, context.Context, string) error                                           = connector.Browser.Navigate
	_ func(connector.Browser, context.Context, string) error                                           = connector.Browser.WaitVisible
	_ func(connector.Browser, context.Context, string, secret.Secret) error                            = connector.Browser.TypeSecret
	_ func(connector.Browser, context.Context, string) error                                           = connector.Browser.Click
	_ func(connector.Browser, context.Context) (string, error)                                         = connector.Browser.CurrentURL
	_ func(connector.Browser, context.Context, []string) ([]connector.Cookie, error)                   = connector.Browser.Cookies
	_ func(connector.Browser) error                                                                    = connector.Browser.Close
	_ func(connector.Persistable, context.Context) (secret.Secret, error)                              = connector.Persistable.Persist
)

// --- fakes -----------------------------------------------------------------

type fakePrompter struct {
	interactive bool
	answer      secret.Secret
	got         []connector.PromptRequest
}

func (p *fakePrompter) Prompt(_ context.Context, req connector.PromptRequest) (secret.Secret, error) {
	if !p.interactive {
		return secret.Secret{}, connector.ErrNeedsLogin
	}
	p.got = append(p.got, req)
	return p.answer, nil
}

func (p *fakePrompter) Interactive() bool { return p.interactive }

type fakePool struct {
	launched []connector.LaunchOptions
	browser  *fakeBrowser
}

func (p *fakePool) Launch(_ context.Context, opts connector.LaunchOptions) (connector.Browser, error) {
	p.launched = append(p.launched, opts)
	return p.browser, nil
}

// fakeBrowser simulates a login page: typing the expected password into
// #password then clicking #submit sets a session cookie.
type fakeBrowser struct {
	url       string
	wantPass  string
	typed     map[string]secret.Secret
	cookieVal string
	loggedIn  bool
	closed    bool
}

func (b *fakeBrowser) Navigate(_ context.Context, url string) error {
	b.url = url
	return nil
}

func (b *fakeBrowser) WaitVisible(_ context.Context, selector string) error {
	if selector == "" {
		return connector.ErrBroken
	}
	return nil
}

func (b *fakeBrowser) TypeSecret(_ context.Context, selector string, v secret.Secret) error {
	if b.typed == nil {
		b.typed = map[string]secret.Secret{}
	}
	b.typed[selector] = v
	return nil
}

func (b *fakeBrowser) Click(_ context.Context, selector string) error {
	if selector != "#submit" {
		return connector.ErrBroken
	}
	if b.typed["#password"].Expose() != b.wantPass {
		return connector.ErrAuthFailed
	}
	b.loggedIn = true
	b.url = "https://espace-client.fournisseur.example/factures"
	return nil
}

func (b *fakeBrowser) CurrentURL(context.Context) (string, error) { return b.url, nil }

func (b *fakeBrowser) Cookies(_ context.Context, domains []string) ([]connector.Cookie, error) {
	if !b.loggedIn {
		return nil, nil
	}
	c := connector.Cookie{
		Name:     "sid",
		Value:    secret.FromString(b.cookieVal),
		Domain:   "espace-client.fournisseur.example",
		Path:     "/",
		Expires:  time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
		Secure:   true,
		HTTPOnly: true,
	}
	if !slices.Contains(domains, c.Domain) {
		return nil, nil
	}
	return []connector.Cookie{c}, nil
}

func (b *fakeBrowser) Close() error {
	b.closed = true
	return nil
}

// mapResolver is a SecretResolver backed by a map of synthetic references.
type mapResolver map[string]string

func (m mapResolver) Resolve(_ context.Context, ref string) (secret.Secret, error) {
	v, ok := m[ref]
	if !ok {
		return secret.Secret{}, errors.New("unknown ref")
	}
	return secret.FromString(v), nil
}

// persistSession opts into persistence.
type persistSession struct{ blob secret.Secret }

func (s persistSession) Persist(context.Context) (secret.Secret, error) { return s.blob, nil }

// plainSession does not.
type plainSession struct{}

// browserLogin is what a connector's Login does with the T5 contract:
// restore Env.Saved when present, else drive the browser with resolved
// credentials and return a persistable session built from the cookies.
func browserLogin(ctx context.Context, env connector.Env) (connector.Session, error) {
	if !env.Saved.IsZero() {
		return persistSession{blob: env.Saved}, nil
	}
	pw, err := env.Secrets.Resolve(ctx, env.Credentials.Password)
	if err != nil {
		return nil, fmt.Errorf("resolve password: %w", err)
	}
	b, err := env.Browser.Launch(ctx, connector.LaunchOptions{
		AllowedDomains: []string{"espace-client.fournisseur.example"},
		Visible:        env.Interactive,
	})
	if err != nil {
		return nil, fmt.Errorf("launch: %w", err)
	}
	defer func() { _ = b.Close() }()
	if err := b.Navigate(ctx, "https://espace-client.fournisseur.example/login"); err != nil {
		return nil, err
	}
	if err := b.WaitVisible(ctx, "#password"); err != nil {
		return nil, err
	}
	if err := b.TypeSecret(ctx, "#password", pw); err != nil {
		return nil, err
	}
	if err := b.Click(ctx, "#submit"); err != nil {
		return nil, err
	}
	cookies, err := b.Cookies(ctx, []string{"espace-client.fournisseur.example"})
	if err != nil {
		return nil, err
	}
	if len(cookies) != 1 {
		return nil, connector.ErrBroken
	}
	return persistSession{blob: cookies[0].Value}, nil
}

// --- tests -----------------------------------------------------------------

// refItem1 is a synthetic Bitwarden item reference prefix.
const refItem1 = "bw://00000000-0000-4000-8000-000000000001/"

func TestEnv_ConcreteFieldTypes(t *testing.T) {
	t.Parallel()
	saved := secret.FromString("synthetic-session-blob")
	env := connector.Env{
		Secrets: mapResolver{},
		Browser: &fakePool{},
		Prompt:  &fakePrompter{},
		Log:     slog.New(slog.DiscardHandler),
		Saved:   saved,
		Credentials: connector.Credentials{
			Login:    refItem1 + "username",
			Password: refItem1 + "password",
			OTP:      refItem1 + "totp",
		},
		Interactive: true,
	}
	pin := func(connector.SecretResolver, connector.BrowserPool, connector.Prompter, secret.Secret, connector.Credentials, bool) {
	}
	pin(env.Secrets, env.Browser, env.Prompt, env.Saved, env.Credentials, env.Interactive)
	pinRefs := func(_, _, _ string) {}
	pinRefs(env.Credentials.Login, env.Credentials.Password, env.Credentials.OTP)

	if !(connector.Env{}).Saved.IsZero() {
		t.Error("zero Env.Saved: IsZero() = false, want true (no saved session)")
	}
	if env.Saved.Expose() != "synthetic-session-blob" {
		t.Error("Env.Saved does not carry the restored blob")
	}
}

func TestEnv_SecretsNeverRenderedWhenEnvPrinted(t *testing.T) {
	t.Parallel()
	blob := testsecrets.Canary(t, testsecrets.Session)
	env := connector.Env{Saved: secret.FromString(blob), Interactive: true}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, env); strings.Contains(out, blob) {
			t.Errorf("fmt %s of Env leaks the saved session blob", verb)
		}
	}
}

func TestBrowser_FakeLoginThroughContract(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pw := testsecrets.Canary(t, testsecrets.Password)
	sid := testsecrets.Canary(t, testsecrets.Cookie)
	br := &fakeBrowser{wantPass: pw, cookieVal: sid}
	pool := &fakePool{browser: br}
	ref := "bw://00000000-0000-4000-8000-000000000002/password"
	env := connector.Env{
		Secrets:     mapResolver{ref: pw},
		Browser:     pool,
		Credentials: connector.Credentials{Password: ref},
		Interactive: false,
	}

	s, err := browserLogin(ctx, env)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if len(pool.launched) != 1 || pool.launched[0].Visible {
		t.Errorf("launched = %+v, want one headless launch when not interactive", pool.launched)
	}
	if !br.closed {
		t.Error("browser not closed after login")
	}
	u, err := br.CurrentURL(ctx)
	if err != nil || !strings.HasPrefix(u, "https://espace-client.fournisseur.example/") {
		t.Errorf("CurrentURL = %q, %v", u, err)
	}
	p, ok := s.(connector.Persistable)
	if !ok {
		t.Fatal("session from browser login is not Persistable")
	}
	blob, err := p.Persist(ctx)
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if blob.Expose() != sid {
		t.Error("persisted blob is not the session cookie")
	}
}

func TestCookie_ValueNeverRendered(t *testing.T) {
	t.Parallel()
	sid := testsecrets.Canary(t, testsecrets.Cookie)
	c := connector.Cookie{Name: "sid", Value: secret.FromString(sid), Domain: "espace-client.fournisseur.example", Path: "/"}

	renders := map[string]string{
		"%v slice": fmt.Sprintf("%v", []connector.Cookie{c}),
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		renders[verb] = fmt.Sprintf(verb, c)
	}
	j, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	renders["json"] = string(j)
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("cookie", "c", c)
	renders["slog"] = buf.String()

	for name, out := range renders {
		if strings.Contains(out, sid) {
			t.Errorf("%s render of Cookie leaks its value", name)
		}
	}
}

func TestBrowser_WrongPasswordIsAuthFailed(t *testing.T) {
	t.Parallel()
	ref := "bw://00000000-0000-4000-8000-000000000003/password"
	br := &fakeBrowser{wantPass: testsecrets.Canary(t, testsecrets.Password)}
	env := connector.Env{
		Secrets:     mapResolver{ref: "synthetic-wrong-password"},
		Browser:     &fakePool{browser: br},
		Credentials: connector.Credentials{Password: ref},
	}
	_, err := browserLogin(context.Background(), env)
	if !errors.Is(err, connector.ErrAuthFailed) {
		t.Fatalf("err = %v, want ErrAuthFailed", err)
	}
	if !br.closed {
		t.Error("browser left open after a failed login")
	}
}

func TestPrompter_NonInteractiveNeedsLogin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := []struct {
		name        string
		interactive bool
		wantErr     error
	}{
		{name: "interactive answers", interactive: true},
		{name: "non-interactive needs login", interactive: false, wantErr: connector.ErrNeedsLogin},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var p connector.Prompter = &fakePrompter{interactive: tc.interactive, answer: secret.FromString("000000")}
			if p.Interactive() != tc.interactive {
				t.Fatalf("Interactive() = %v", p.Interactive())
			}
			code, err := p.Prompt(ctx, connector.PromptRequest{Label: "Code reçu par SMS"})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && code.Expose() != "000000" {
				t.Error("prompt answer lost")
			}
		})
	}
}

func TestPromptRequest_LabelCleaned(t *testing.T) {
	t.Parallel()
	token := testsecrets.Canary(t, testsecrets.Token)
	tests := []struct {
		name  string
		label string
		want  string // "" = only the generic properties are checked
	}{
		{name: "plain ascii kept", label: "Code SMS", want: "Code SMS"},
		{name: "accents kept", label: "Code reçu par e-mail", want: "Code reçu par e-mail"},
		{name: "empty", label: "", want: ""},
		{name: "SGR colour removed whole", label: "\x1b[31mCode\x1b[0m", want: "Code"},
		{name: "CSI cursor and clear removed", label: "\x1b[2J\x1b[1;1HCode", want: "Code"},
		{name: "OSC title with BEL removed", label: "\x1b]0;pwned\x07Code", want: "Code"},
		{name: "OSC 8 hyperlink with ST removed", label: "\x1b]8;;https://evil.example/\x1b\\lien\x1b]8;;\x1b\\", want: "lien"},
		{name: "8-bit CSI removed whole", label: "\u009b31mCode", want: "Code"},
		{name: "line breaks and tab become spaces", label: "Code\r\nFaux:\tok", want: "Code  Faux: ok"},
		{name: "other C0 and DEL removed", label: "Co\x00d\x07e\x7f", want: "Code"},
		{name: "bidi override removed", label: "\u202eedoC\u202c", want: "edoC"},
		{name: "line separator removed", label: "Code\u2028X", want: "CodeX"},
		{name: "invalid utf8 removed", label: "Code\xff\xfe", want: "Code"},
		{name: "surrounding spaces trimmed", label: "  Code  ", want: "Code"},
		{name: "token in url masked", label: "Ouvrez https://espace-client.fournisseur.example/otp?token=" + token},
		{name: "long label capped", label: strings.Repeat("a", 4*connector.MaxPromptLabelLen)},
		{name: "long multibyte label capped on rune boundary", label: strings.Repeat("é", connector.MaxPromptLabelLen)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := connector.PromptRequest{Label: tc.label}.CleanLabel()
			if tc.want != "" || tc.label == "" {
				if got != tc.want {
					t.Errorf("CleanLabel(%q) = %q, want %q", tc.label, got, tc.want)
				}
			}
			if !utf8.ValidString(got) {
				t.Errorf("CleanLabel(%q) = %q: invalid UTF-8", tc.label, got)
			}
			if len(got) > connector.MaxPromptLabelLen {
				t.Errorf("CleanLabel: %d bytes, cap %d", len(got), connector.MaxPromptLabelLen)
			}
			for _, r := range got {
				if !unicode.IsPrint(r) {
					t.Errorf("CleanLabel(%q) = %q: holds non-printable %U", tc.label, got, r)
				}
			}
			if strings.Contains(got, token) {
				t.Errorf("CleanLabel leaks a token-like value")
			}
		})
	}
}

func TestPersistable_OptIn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tests := []struct {
		name    string
		session connector.Session
		want    bool
	}{
		{name: "session without Persist is not persistable", session: plainSession{}, want: false},
		{name: "nil session is not persistable", session: nil, want: false},
		{name: "session with Persist is persistable", session: persistSession{blob: secret.FromString("synthetic-blob")}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, ok := tc.session.(connector.Persistable)
			if ok != tc.want {
				t.Fatalf("Persistable = %v, want %v", ok, tc.want)
			}
			if !ok {
				return
			}
			blob, err := p.Persist(ctx)
			if err != nil || blob.IsZero() {
				t.Fatalf("Persist = (zero=%v, %v)", blob.IsZero(), err)
			}
		})
	}
}

func TestPersistable_SavedRestoresWithoutBrowser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	blob := testsecrets.Canary(t, testsecrets.Session)
	pool := &fakePool{} // nil browser: any launch would fail the login
	env := connector.Env{Browser: pool, Saved: secret.FromString(blob)}

	s, err := browserLogin(ctx, env)
	if err != nil {
		t.Fatalf("login with saved session: %v", err)
	}
	if len(pool.launched) != 0 {
		t.Errorf("browser launched %d times despite a saved session", len(pool.launched))
	}
	p, ok := s.(connector.Persistable)
	if !ok {
		t.Fatal("restored session not Persistable")
	}
	got, err := p.Persist(ctx)
	if err != nil || got.Expose() != blob {
		t.Fatalf("round trip lost the blob (err %v)", err)
	}
}
