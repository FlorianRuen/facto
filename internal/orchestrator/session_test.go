// Tests for session restore/save and the login-only browser (J1 task T18).
// Spec: docs/spec.md "Run lifecycle" (1. restore the saved session, 3.
// needs_login asks for `facto login <id>`, 6. save the session), "Connector
// states"; J1 plan decisions A9 (Env.Saved + optional Persistable), A13
// (ephemeral sessions), ADR 0009 (Store API and error split), ADR 0008 and
// CLAUDE.md (browser launched for login only). Every value is synthetic.
//
// Expected API (implementer: follow exactly):
//
//	// SessionStore is the saved-session store (*vault.Store implements it).
//	type SessionStore interface {
//		Persistent() bool
//		Load(ctx context.Context, id string) (secret.Secret, error)
//		Save(ctx context.Context, id string, blob secret.Secret) error
//		Delete(ctx context.Context, id string) error
//	}
//
//	// Deps gains two optional fields (existing callers unchanged):
//	//	Sessions SessionStore          // nil = no persistence (as ephemeral)
//	//	Browser  connector.BrowserPool // nil = Env.Browser stays nil
//
//	// ConnectorResult and ConnectorStatus gain:
//	//	Notes []string // fixed orchestrator text for the user, never error text
//	// Report.AddRun copies Notes; JSON renders them as connectors[].notes
//	// (omitempty), Text as indented lines under the connector line, escaped.
//
// Run, per connector, after the HTTP client is built:
//
//   - Restore: when Sessions is non-nil and Persistent(), Load(ctx, id) once,
//     before Login. A blob becomes Env.Saved and is wiped once Login returns.
//     ErrNoSession (errors.Is) is silent. Any other error (vault.ErrKeyring,
//     a read error) logs exactly one warning for the connector; Env.Saved is
//     zero and the session is NOT deleted (the file may be fine next run).
//     Not persistent (or nil): no Load, no Persist, no Save, no Delete.
//   - Browser: Env.Browser wraps Deps.Browser (never the pool itself). The
//     wrapper launches with the connector's Info().AllowedDomains, whatever
//     the connector passed. When Login returns (success, error or panic),
//     every browser launched through it and not closed yet is closed, with
//     one warning per run of the connector, before List starts. After Login
//     the wrapper refuses Launch with an error and never reaches the pool.
//     The orchestrator never launches a browser itself.
//   - Save: after a successful Login, when the session implements
//     connector.Persistable and the store is persistent: Persist(ctx), then
//     Save(ctx, id, blob), then wipe the blob. A Save error wrapping
//     fsx.ErrNotDurable counts as saved. Any other Persist or Save error is
//     logged as a warning, the connector continues (List, Fetch) and its
//     result carries a note containing "session not saved".
//   - Drop: when Env.Saved was non-zero and Login or List fails with
//     connector.ErrNeedsLogin or connector.ErrAuthFailed, Delete(ctx, id) is
//     called once and the state is needs_login (the restored session, not
//     the credentials, was rejected). A Delete error is logged as a warning.
//     Without a restored session ErrAuthFailed stays auth_failed. Other
//     sentinels never delete.
//   - Every needs_login result carries a note containing "facto login <id>".
//
// The orchestrator imports neither internal/browser nor a concrete store: it
// may import internal/vault only for its sentinels ErrNoSession and
// ErrKeyring (imports_test.go).
package orchestrator_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/testsecrets"
	"github.com/FlorianRuen/facto/internal/vault"
)

// noteSessionNotSaved is the substring of the note a failed save leaves.
const noteSessionNotSaved = "session not saved"

func TestRun_RestoresSavedSession(t *testing.T) {
	t.Parallel()
	ev := &events{}
	sessions := newFakeSessions(ev, true)
	sessions.put("alpha", "synthetic-saved-blob-alpha")
	pool := &fakePool{ev: ev}
	r := newRunRig(t, nil, withSessions(sessions), withBrowser(pool))
	sessions.ev, pool.ev = r.ev, r.ev

	alpha := newSessConn(r.ev, "alpha", nil, runRef("a1", 1))
	bravo := newSessConn(r.ev, "bravo", nil, runRef("b1", 1))

	res, err := r.o.Run(t.Context(), registry(t, alpha, bravo), period2026)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	loads, saves, deletes := sessions.calls()
	if !slices.Equal(loads, []string{"alpha", "bravo"}) {
		t.Fatalf("Load calls = %q, want one per connector, by id", loads)
	}
	if len(saves) != 0 || len(deletes) != 0 {
		t.Fatalf("Save = %q, Delete = %q, want none (plain sessions are not persistable)", saves, deletes)
	}
	tests := []struct {
		conn     *sessConn
		want     string
		wantZero bool
	}{
		{alpha, "synthetic-saved-blob-alpha", false},
		{bravo, "", true},
	}
	for _, tt := range tests {
		id := tt.conn.info.ID
		got, zero := tt.conn.savedSeen()
		if len(got) != 1 || got[0] != tt.want || zero[0] != tt.wantZero {
			t.Fatalf("%s: Env.Saved during Login = %q (zero %v), want %q (zero %v)", id, got, zero, tt.want, tt.wantZero)
		}
		if c := byID(t, res, id); c.State != orchestrator.StateOK || docStatuses(c.Documents)[string(id[0])+"1"] != orchestrator.StatusFiled {
			t.Fatalf("%s = %+v, want ok with its document filed", id, c)
		}
		envs := tt.conn.envList()
		if envs[0].Browser == nil {
			t.Fatalf("%s: Env.Browser is nil while Deps.Browser is set", id)
		}
		if p, ok := envs[0].Browser.(*fakePool); ok && p == pool {
			t.Fatalf("%s: Env.Browser is the raw pool, want the orchestrator's login-only wrapper", id)
		}
	}
	if evs := r.ev.list(); slices.Index(evs, "load:alpha") > slices.Index(evs, "login:alpha") {
		t.Fatalf("events = %q, want load:alpha before login:alpha", evs)
	}
	if opts, _ := pool.launched(); len(opts) != 0 {
		t.Fatalf("browser launched %d times, want 0 (Login restored without it; the orchestrator never launches one)", len(opts))
	}
	for i, s := range sessions.handedOut() {
		if !s.IsZero() {
			t.Fatalf("restored blob %d not wiped after Login", i)
		}
	}
	if n := warnCount(t, r.log.String(), "bravo"); n != 0 {
		t.Fatalf("bravo: %d warnings for a missing session, want 0 (ErrNoSession is silent); log:\n%s", n, r.log.String())
	}
}

func TestRun_SavesPersistableAfterLogin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		saveErr  error
		loginErr error
		wantSave bool
		wantOK   bool
	}{
		{name: "saved", wantSave: true, wantOK: true},
		{name: "not durable counts as saved", saveErr: errSynthetic("fsync", fsx.ErrNotDurable), wantSave: true, wantOK: true},
		{name: "failed login never persists", loginErr: connector.ErrBroken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sessions := newFakeSessions(&events{}, true)
			sessions.saveErr = tt.saveErr
			r := newRunRig(t, nil, withSessions(sessions))
			sessions.ev = r.ev
			sess := &persistSession{blob: "synthetic-persist-blob-alpha"}
			alpha := newSessConn(r.ev, "alpha", sess, runRef("a1", 1))
			alpha.loginErr = tt.loginErr

			res, err := r.o.Run(t.Context(), registry(t, alpha), period2026)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			_, saves, deletes := sessions.calls()
			if len(deletes) != 0 {
				t.Fatalf("Delete = %q, want none", deletes)
			}
			got := byID(t, res, "alpha")
			if !tt.wantSave {
				if sess.persistCount() != 0 || len(saves) != 0 {
					t.Fatalf("Persist %d, Save %q after a failed login, want none", sess.persistCount(), saves)
				}
				return
			}
			if sess.persistCount() != 1 || !slices.Equal(saves, []string{"alpha"}) {
				t.Fatalf("Persist %d, Save %q, want one Persist then Save(alpha)", sess.persistCount(), saves)
			}
			if tt.saveErr == nil {
				if b, _ := sessions.blob("alpha"); b != "synthetic-persist-blob-alpha" {
					t.Fatalf("Save stored a different blob (%d bytes)", len(b))
				}
			}
			if evs := r.ev.list(); slices.Index(evs, "save:alpha") < slices.Index(evs, "login:alpha") {
				t.Fatalf("events = %q, want save:alpha after login:alpha", evs)
			}
			for i, s := range sess.handedOut() {
				if !s.IsZero() {
					t.Fatalf("Persist blob %d not wiped after Save", i)
				}
			}
			if tt.wantOK && (got.State != orchestrator.StateOK || docStatuses(got.Documents)["a1"] != orchestrator.StatusFiled) {
				t.Fatalf("alpha = %+v, want ok with a1 filed", got)
			}
			if hasNote(got, noteSessionNotSaved) {
				t.Fatalf("notes = %q, want no %q (ErrNotDurable means saved)", got.Notes, noteSessionNotSaved)
			}
		})
	}
}

func TestRun_NonPersistableNotSaved(t *testing.T) {
	t.Parallel()
	sessions := newFakeSessions(&events{}, true)
	r := newRunRig(t, nil, withSessions(sessions))
	sessions.ev = r.ev
	alpha := newSessConn(r.ev, "alpha", nil, runRef("a1", 1)) // *fakeSession: no Persist

	res, err := r.o.Run(t.Context(), registry(t, alpha), period2026)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	_, saves, deletes := sessions.calls()
	if len(saves) != 0 || len(deletes) != 0 {
		t.Fatalf("Save = %q, Delete = %q, want none for a session without Persist", saves, deletes)
	}
	got := byID(t, res, "alpha")
	if got.State != orchestrator.StateOK || len(got.Notes) != 0 {
		t.Fatalf("alpha = %+v, want ok without notes", got)
	}
	if n := warnCount(t, r.log.String(), "alpha"); n != 0 {
		t.Fatalf("%d warnings, want 0; log:\n%s", n, r.log.String())
	}
}

func TestRun_EphemeralNeverSaves(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		store    bool // false = Deps.Sessions nil
		loginErr error
	}{
		{name: "store not persistent", store: true},
		{name: "store not persistent, needs login", store: true, loginErr: connector.ErrNeedsLogin},
		{name: "no store"},
		{name: "no store, auth failed", loginErr: connector.ErrAuthFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ev := &events{}
			sessions := newFakeSessions(ev, false)
			sessions.put("alpha", "synthetic-stale-blob-alpha")
			var opts []rigOpt
			if tt.store {
				opts = append(opts, withSessions(sessions))
			}
			r := newRunRig(t, nil, opts...)
			sessions.ev = r.ev
			sess := &persistSession{blob: "synthetic-persist-blob-alpha"}
			alpha := newSessConn(r.ev, "alpha", sess, runRef("a1", 1))
			alpha.loginErr = tt.loginErr

			res, err := r.o.Run(t.Context(), registry(t, alpha), period2026)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			loads, saves, deletes := sessions.calls()
			if len(loads)+len(saves)+len(deletes) != 0 {
				t.Fatalf("store touched: Load %q, Save %q, Delete %q; want nothing", loads, saves, deletes)
			}
			if sess.persistCount() != 0 {
				t.Fatalf("Persist called %d times, want 0 (nothing will be saved)", sess.persistCount())
			}
			if _, zero := alpha.savedSeen(); len(zero) != 1 || !zero[0] {
				t.Fatalf("Env.Saved zero = %v, want one Login with a zero Saved", zero)
			}
			want := orchestrator.StateOK
			switch {
			case errors.Is(tt.loginErr, connector.ErrNeedsLogin):
				want = orchestrator.StateNeedsLogin
			case errors.Is(tt.loginErr, connector.ErrAuthFailed):
				want = orchestrator.StateAuthFailed // no restored session: the credentials were rejected
			}
			if got := byID(t, res, "alpha"); got.State != want {
				t.Fatalf("state = %q, want %q", got.State, want)
			}
		})
	}
}

func TestRun_AuthFailedDropsSavedSession(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		restored   bool
		loginErr   error
		listErr    error
		deleteErr  error
		wantDelete bool
		wantState  orchestrator.State
	}{
		{name: "login needs login", restored: true, loginErr: fmt.Errorf("probe: %w", connector.ErrNeedsLogin), wantDelete: true, wantState: orchestrator.StateNeedsLogin},
		{name: "login auth failed", restored: true, loginErr: fmt.Errorf("probe: %w", connector.ErrAuthFailed), wantDelete: true, wantState: orchestrator.StateNeedsLogin},
		{name: "list needs login", restored: true, listErr: fmt.Errorf("list: %w", connector.ErrNeedsLogin), wantDelete: true, wantState: orchestrator.StateNeedsLogin},
		{name: "delete fails", restored: true, loginErr: connector.ErrNeedsLogin, deleteErr: errSynthetic("remove", fs.ErrPermission), wantDelete: true, wantState: orchestrator.StateNeedsLogin},
		{name: "needs login without saved session", loginErr: connector.ErrNeedsLogin, wantState: orchestrator.StateNeedsLogin},
		{name: "auth failed without saved session", loginErr: connector.ErrAuthFailed, wantState: orchestrator.StateAuthFailed},
		{name: "broken keeps session", restored: true, loginErr: connector.ErrBroken, wantState: orchestrator.StateBroken},
		{name: "rate limited keeps session", restored: true, loginErr: connector.ErrRateLimited, wantState: orchestrator.StateRateLimited},
		{name: "list rate limited keeps session", restored: true, listErr: connector.ErrRateLimited, wantState: orchestrator.StateRateLimited},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ev := &events{}
			sessions := newFakeSessions(ev, true)
			sessions.deleteErr = tt.deleteErr
			if tt.restored {
				sessions.put("alpha", "synthetic-saved-blob-alpha")
			}
			sessions.put("bravo", "synthetic-saved-blob-bravo")
			r := newRunRig(t, nil, withSessions(sessions))
			sessions.ev = r.ev
			alpha := newSessConn(r.ev, "alpha", nil, runRef("a1", 1))
			alpha.loginErr, alpha.listErr = tt.loginErr, tt.listErr
			bravo := newSessConn(r.ev, "bravo", nil, runRef("b1", 1))

			res, err := r.o.Run(t.Context(), registry(t, alpha, bravo), period2026)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			_, _, deletes := sessions.calls()
			if tt.wantDelete {
				if !slices.Equal(deletes, []string{"alpha"}) {
					t.Fatalf("Delete calls = %q, want exactly [alpha]", deletes)
				}
			} else if len(deletes) != 0 {
				t.Fatalf("Delete calls = %q, want none", deletes)
			}
			if _, ok := sessions.blob("bravo"); !ok {
				t.Fatal("bravo's saved session was dropped: only the rejected connector's session may be")
			}
			got := byID(t, res, "alpha")
			if got.State != tt.wantState {
				t.Fatalf("alpha state = %q, want %q", got.State, tt.wantState)
			}
			if b := byID(t, res, "bravo"); b.State != orchestrator.StateOK {
				t.Fatalf("bravo = %+v, want ok (one connector's failure never stops the next)", b)
			}
			wantHint := tt.wantState == orchestrator.StateNeedsLogin
			if hasNote(got, "facto login alpha") != wantHint {
				t.Fatalf("alpha notes = %q, want a note naming `facto login alpha`: %v", got.Notes, wantHint)
			}
			if tt.deleteErr != nil && warnCount(t, r.log.String(), "alpha") == 0 {
				t.Fatalf("Delete failure not logged as a warning; log:\n%s", r.log.String())
			}
			if !wantHint {
				return
			}
			rep := orchestrator.Report{StartedAt: day(time.March, 20), FinishedAt: day(time.March, 20)}
			rep.AddRun(res)
			js, jerr := rep.JSON()
			if jerr != nil {
				t.Fatalf("JSON: %v", jerr)
			}
			for name, out := range map[string]string{"report json": string(js), "report text": rep.Text()} {
				if !strings.Contains(out, "facto login alpha") {
					t.Fatalf("%s does not name `facto login alpha`:\n%s", name, out)
				}
			}
		})
	}
}

func TestRun_KeyringErrorDoesNotDeleteSession(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		loadErr  error
		loginErr error
		want     orchestrator.State
	}{
		{name: "keyring error", loadErr: errSynthetic("keyring", vault.ErrKeyring), want: orchestrator.StateOK},
		{name: "read error", loadErr: errSynthetic("read", fs.ErrPermission), want: orchestrator.StateOK},
		{name: "keyring error then needs login", loadErr: errSynthetic("keyring", vault.ErrKeyring), loginErr: connector.ErrNeedsLogin, want: orchestrator.StateNeedsLogin},
		{name: "keyring error then auth failed", loadErr: errSynthetic("keyring", vault.ErrKeyring), loginErr: connector.ErrAuthFailed, want: orchestrator.StateAuthFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ev := &events{}
			sessions := newFakeSessions(ev, true)
			sessions.put("alpha", "synthetic-saved-blob-alpha")
			sessions.loadErr["alpha"] = tt.loadErr
			r := newRunRig(t, nil, withSessions(sessions))
			sessions.ev = r.ev
			alpha := newSessConn(r.ev, "alpha", nil, runRef("a1", 1))
			alpha.loginErr = tt.loginErr

			res, err := r.o.Run(t.Context(), registry(t, alpha), period2026)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			loads, _, deletes := sessions.calls()
			if !slices.Equal(loads, []string{"alpha"}) {
				t.Fatalf("Load calls = %q, want [alpha]", loads)
			}
			if len(deletes) != 0 {
				t.Fatalf("Delete calls = %q, want none (the session file is kept on a keyring or read error)", deletes)
			}
			if _, ok := sessions.blob("alpha"); !ok {
				t.Fatal("saved session gone after a keyring error")
			}
			if seen, zero := alpha.savedSeen(); len(seen) != 1 || !zero[0] {
				t.Fatalf("Login calls %d, Saved zero %v; want one Login without a saved session", len(seen), zero)
			}
			if got := byID(t, res, "alpha"); got.State != tt.want {
				t.Fatalf("state = %q, want %q", got.State, tt.want)
			}
			// The login failure itself is a warning too: count only the
			// warnings logged before Login.
			if n := warnCountBeforeLogin(t, r.log.String(), "alpha"); n != 1 {
				t.Fatalf("%d warnings for the Load failure, want exactly 1; log:\n%s", n, r.log.String())
			}
		})
	}
}

func TestRun_BrowserClosedBeforeList(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		launches    int
		closeOwn    bool // the connector closes its browsers itself
		loginErr    error
		panicLogin  bool
		wantWarn    bool
		wantListRun bool
	}{
		{name: "left open", launches: 1, wantWarn: true, wantListRun: true},
		{name: "two left open", launches: 2, wantWarn: true, wantListRun: true},
		{name: "closed by the connector", launches: 1, closeOwn: true, wantListRun: true},
		{name: "no browser", launches: 0, wantListRun: true},
		{name: "login failed left open", launches: 1, loginErr: connector.ErrNeedsLogin, wantWarn: true},
		{name: "login panicked left open", launches: 1, panicLogin: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ev := &events{}
			pool := &fakePool{ev: ev}
			r := newRunRig(t, nil, withBrowser(pool))
			pool.ev = r.ev
			alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1))
			alpha.loginErr = tt.loginErr
			if tt.panicLogin {
				alpha.panicAt, alpha.panicVal = stageLogin, "synthetic crash"
			}
			alpha.onLogin = func(ctx context.Context, env connector.Env) {
				if env.Browser == nil {
					if tt.launches > 0 {
						t.Errorf("Env.Browser is nil while Deps.Browser is set")
					}
					return
				}
				for range tt.launches {
					b, err := env.Browser.Launch(ctx, connector.LaunchOptions{AllowedDomains: alpha.info.AllowedDomains})
					if err != nil {
						t.Errorf("Launch during Login: %v", err)
						return
					}
					if tt.closeOwn {
						_ = b.Close()
					}
				}
			}
			var openAtList []int
			alpha.onList = func() {
				_, bs := pool.launched()
				for _, b := range bs {
					if b.closeCount() == 0 {
						openAtList = append(openAtList, b.n)
					}
				}
			}

			res, err := r.o.Run(t.Context(), registry(t, alpha), period2026)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if listed := r.ev.withPrefix("list:") != nil; listed != tt.wantListRun {
				t.Fatalf("List called = %v, want %v", listed, tt.wantListRun)
			}
			if len(openAtList) != 0 {
				t.Fatalf("browsers %v still open when List started", openAtList)
			}
			_, bs := pool.launched()
			if len(bs) != tt.launches {
				t.Fatalf("pool launched %d browsers, want %d", len(bs), tt.launches)
			}
			for _, b := range bs {
				if n := b.closeCount(); n != 1 {
					t.Fatalf("browser %d closed %d times, want exactly once", b.n, n)
				}
			}
			if tt.wantWarn && !hasBrowserWarning(t, r.log.String(), "alpha") {
				t.Fatalf("no warning about a browser left open; log:\n%s", r.log.String())
			}
			if tt.closeOwn && hasBrowserWarning(t, r.log.String(), "alpha") {
				t.Fatalf("browser warning although the connector closed it; log:\n%s", r.log.String())
			}
			if tt.panicLogin && byID(t, res, "alpha").State != orchestrator.StateBroken {
				t.Fatalf("alpha = %+v, want broken after a Login panic", byID(t, res, "alpha"))
			}
		})
	}
}

func TestRun_BrowserLaunchRefusedAfterLogin(t *testing.T) {
	t.Parallel()
	ev := &events{}
	pool := &fakePool{ev: ev}
	r := newRunRig(t, nil, withBrowser(pool))
	pool.ev = r.ev
	alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1))
	var kept connector.BrowserPool
	alpha.onLogin = func(_ context.Context, env connector.Env) { kept = env.Browser }
	var listErr error
	var listBrowser connector.Browser
	alpha.onList = func() {
		if kept == nil {
			t.Errorf("Env.Browser is nil while Deps.Browser is set")
			return
		}
		listBrowser, listErr = kept.Launch(t.Context(), connector.LaunchOptions{AllowedDomains: alpha.info.AllowedDomains})
	}

	if _, err := r.o.Run(t.Context(), registry(t, alpha), period2026); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if kept != nil && (listErr == nil || listBrowser != nil) {
		t.Fatalf("Launch during List = (%v, %v), want an error and no browser (login only)", listBrowser, listErr)
	}
	if opts, _ := pool.launched(); len(opts) != 0 {
		t.Fatalf("pool launched %d browsers after Login, want 0", len(opts))
	}
}

func TestRun_BrowserAllowlistIsConnectorInfo(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		allowed []string
	}{
		{"widened", []string{"billing.alpha.example", "evil.example"}},
		{"wildcard", []string{"*"}},
		{"empty", nil},
		{"other connector", []string{"billing.bravo.example"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ev := &events{}
			pool := &fakePool{ev: ev}
			r := newRunRig(t, nil, withBrowser(pool))
			pool.ev = r.ev
			alpha := newFakeConn(r.ev, "alpha", runRef("a1", 1))
			alpha.onLogin = func(ctx context.Context, env connector.Env) {
				if env.Browser == nil {
					t.Errorf("Env.Browser is nil while Deps.Browser is set")
					return
				}
				b, err := env.Browser.Launch(ctx, connector.LaunchOptions{AllowedDomains: tt.allowed})
				if err == nil {
					_ = b.Close()
				}
			}
			if _, err := r.o.Run(t.Context(), registry(t, alpha), period2026); err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			opts, _ := pool.launched()
			for i, o := range opts {
				if !slices.Equal(o.AllowedDomains, alpha.info.AllowedDomains) {
					t.Fatalf("launch %d allowlist = %q, want the connector's Info %q", i, o.AllowedDomains, alpha.info.AllowedDomains)
				}
			}
		})
	}
}

func TestRun_SessionBlobNeverLogged(t *testing.T) {
	t.Parallel()
	savedCanary := testsecrets.Canary(t, testsecrets.Session)
	persistCanary := testsecrets.Canary(t, testsecrets.Session)
	cookieCanary := testsecrets.Canary(t, testsecrets.Cookie)
	artDir := testsecrets.ArtifactDir(t)

	ev := &events{}
	sessions := newFakeSessions(ev, true)
	sessions.put("alpha", savedCanary)
	sessions.put("bravo", savedCanary)
	r := newRunRig(t, nil, withSessions(sessions))
	sessions.ev = r.ev

	// alpha: restored, persisted and saved.
	alpha := newSessConn(r.ev, "alpha", &persistSession{secretField: cookieCanary, blob: persistCanary}, runRef("a1", 1))
	// bravo: restored, then rejected: the saved session is dropped.
	bravo := newSessConn(r.ev, "bravo", &persistSession{secretField: cookieCanary, blob: persistCanary}, runRef("b1", 1))
	bravo.loginErr = connector.ErrNeedsLogin
	// charlie: persisted, but Persist fails.
	charlie := newSessConn(r.ev, "charlie", &persistSession{secretField: cookieCanary, err: errSynthetic("persist", nil)}, runRef("c1", 1))

	res, err := r.o.Run(t.Context(), registry(t, alpha, bravo, charlie), period2026)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if seen, _ := alpha.savedSeen(); len(seen) != 1 || seen[0] != savedCanary {
		t.Fatal("alpha did not receive its saved session (the canary must still reach the connector)")
	}
	if b, _ := sessions.blob("alpha"); b != persistCanary {
		t.Fatal("alpha's Persist blob did not reach Save unchanged")
	}

	rep := orchestrator.Report{StartedAt: day(time.March, 20), FinishedAt: day(time.March, 20)}
	rep.AddRun(res)
	js, jerr := rep.JSON()
	if jerr != nil {
		t.Fatalf("JSON: %v", jerr)
	}
	// Written to the artifact dir: make leakcheck scans them too.
	if _, werr := orchestrator.WriteReport(t.Context(), artDir, rep); werr != nil {
		t.Fatalf("WriteReport: %v", werr)
	}
	root, oerr := fsx.Open(artDir)
	if oerr != nil {
		t.Fatalf("open artifact dir: %v", oerr)
	}
	defer func() { _ = root.Close() }()
	if werr := root.WriteAtomic(t.Context(), "run.log", r.log.Bytes()); werr != nil {
		t.Fatalf("write log artifact: %v", werr)
	}
	for name, out := range map[string]string{
		"log":         r.log.String(),
		"report json": string(js),
		"report text": rep.Text(),
		"result":      fmt.Sprintf("%+v", res),
		"result #v":   fmt.Sprintf("%#v", res),
	} {
		for _, c := range []string{savedCanary, persistCanary, cookieCanary} {
			if strings.Contains(out, c) {
				t.Fatalf("session canary leaked into the %s:\n%s", name, out)
			}
		}
	}
}

func TestRun_SaveFailureDoesNotFailRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		saveErr    error
		persistErr error
	}{
		{name: "save error", saveErr: errSynthetic("write", fs.ErrPermission)},
		{name: "keyring error on save", saveErr: errSynthetic("keyring", vault.ErrKeyring)},
		{name: "persist error", persistErr: errSynthetic("persist", nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ev := &events{}
			sessions := newFakeSessions(ev, true)
			sessions.saveErr = tt.saveErr
			r := newRunRig(t, nil, withSessions(sessions))
			sessions.ev = r.ev
			alpha := newSessConn(r.ev, "alpha", &persistSession{blob: "synthetic-persist-blob-alpha", err: tt.persistErr}, runRef("a1", 1), runRef("a2", 2))
			bravo := newSessConn(r.ev, "bravo", nil, runRef("b1", 1))

			res, err := r.o.Run(t.Context(), registry(t, alpha, bravo), period2026)
			if err != nil {
				t.Fatalf("Run() error = %v, want nil (a failed save is not a run failure)", err)
			}
			got := byID(t, res, "alpha")
			want := map[string]orchestrator.Status{"a1": orchestrator.StatusFiled, "a2": orchestrator.StatusFiled}
			if got.State != orchestrator.StateOK || !mapsEqual(docStatuses(got.Documents), want) {
				t.Fatalf("alpha = %+v, want ok with a1, a2 filed (the run continues after a failed save)", got)
			}
			if !hasNote(got, noteSessionNotSaved) {
				t.Fatalf("alpha notes = %q, want one containing %q", got.Notes, noteSessionNotSaved)
			}
			if b := byID(t, res, "bravo"); b.State != orchestrator.StateOK || hasNote(b, noteSessionNotSaved) {
				t.Fatalf("bravo = %+v, want ok without a save note", b)
			}
			if _, _, deletes := sessions.calls(); len(deletes) != 0 {
				t.Fatalf("Delete calls = %q, want none", deletes)
			}
			if warnCount(t, r.log.String(), "alpha") == 0 {
				t.Fatalf("failed save not logged as a warning; log:\n%s", r.log.String())
			}
			rep := orchestrator.Report{StartedAt: day(time.March, 20), FinishedAt: day(time.March, 20)}
			rep.AddRun(res)
			js, jerr := rep.JSON()
			if jerr != nil {
				t.Fatalf("JSON: %v", jerr)
			}
			for name, out := range map[string]string{"report json": string(js), "report text": rep.Text()} {
				if !strings.Contains(out, noteSessionNotSaved) {
					t.Fatalf("%s does not note %q:\n%s", name, noteSessionNotSaved, out)
				}
			}
		})
	}
}

// --- helpers ------------------------------------------------------------------

// hasNote reports whether one of c's notes contains sub.
func hasNote(c orchestrator.ConnectorResult, sub string) bool {
	for _, n := range c.Notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// warnCount counts the WARN records tagged connector=id.
func warnCount(t *testing.T, out, id string) int {
	t.Helper()
	n := 0
	for _, l := range logLines(t, out) {
		if l["connector"] == id && l["level"] == "WARN" {
			n++
		}
	}
	return n
}

// warnCountBeforeLogin counts the WARN records tagged connector=id logged
// before the first record of the login phase failing (phase=login).
func warnCountBeforeLogin(t *testing.T, out, id string) int {
	t.Helper()
	n := 0
	for _, l := range logLines(t, out) {
		if l["connector"] != id || l["level"] != "WARN" {
			continue
		}
		if l["phase"] == "login" && l["state"] != nil {
			break // the "connector stopped" line of a failed Login
		}
		n++
	}
	return n
}

// hasBrowserWarning reports whether a WARN record tagged connector=id
// mentions a browser.
func hasBrowserWarning(t *testing.T, out, id string) bool {
	t.Helper()
	for _, l := range logLines(t, out) {
		if l["connector"] == id && l["level"] == "WARN" && strings.Contains(strings.ToLower(fmt.Sprint(l["msg"])), "browser") {
			return true
		}
	}
	return false
}
