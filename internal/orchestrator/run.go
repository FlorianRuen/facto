package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
	"github.com/FlorianRuen/facto/internal/normalize"
)

// State is a connector's outcome in a run (docs/spec.md "Connector states").
type State string

// Connector states.
const (
	StateOK          State = "ok"
	StateNeedsLogin  State = "needs_login"
	StateBroken      State = "broken"
	StateAuthFailed  State = "auth_failed"
	StateRateLimited State = "rate_limited"
	StateInterrupted State = "interrupted" // stopped by the run's cancellation
)

// Connectors is the connector source (*connector.Registry implements it).
type Connectors interface {
	All() []connector.Connector
}

// HTTPFactory builds the allowlisted client handed to one connector.
type HTTPFactory func(allowed []string) (*httpx.Client, error)

// defaultHTTP is the production HTTPFactory.
func defaultHTTP(allowed []string) (*httpx.Client, error) {
	c, err := httpx.New(allowed, httpx.Options{})
	if err != nil {
		return nil, fmt.Errorf("http client: %w", err)
	}
	return c, nil
}

// ConnectorResult is the outcome of one connector.
type ConnectorResult struct {
	ID        string
	State     State
	Documents []DocResult // Source == ID, in listing order
	// Notes are fixed orchestrator texts for the user (never error text or
	// supplier data), e.g. the `facto login <id>` hint of needs_login.
	Notes []string
}

// RunResult is the outcome of Run.
type RunResult struct {
	Connectors []ConnectorResult // src.All() order, one per connector started
}

// Connector phases, logged when a connector fails or panics.
const (
	phaseInfo  = "info"
	phaseHTTP  = "http"
	phaseLogin = "login"
	phaseList  = "list"
	phaseFetch = "fetch"
	phaseRead  = "read" // Ingest reading the fetched body, or closing it
)

// errNilSource reports a nil Connectors source.
var errNilSource = errors.New("orchestrator: nil connector source")

// Run collects p from every connector of src.All(), sequentially, in that
// order. Per connector: connector.ValidateInfo (failure: broken, never
// logged in); Env{HTTP: Deps.NewHTTP(Info.AllowedDomains) (error: broken,
// never logged in), Log: the redacting logger tagged connector=<id>,
// Secrets: Deps.Secrets}; Login;
// List(session, p); then for each listed ref: a ProviderID validProviderID
// refuses (a URL, a query, a token, whitespace or control characters, over
// 128 bytes) is StatusInvalid, with no ProviderID, never fetched, indexed,
// named or logged; otherwise normalize.BeforeFetch (a known
// ProviderID is StatusSkippedKnownID and never fetched, a lookup error
// StatusFailed), Fetch, Ingest, close the body.
//
// Sessions and browser (Deps.Sessions, Deps.Browser): when Sessions is
// Persistent, the saved session is Loaded once before Login and handed over
// as Env.Saved, wiped once Login returns (vault.ErrNoSession is silent, any
// other Load error is one warning and the session is kept). Env.Browser is a
// login-only wrapper of Deps.Browser: it launches with Info.AllowedDomains,
// whatever the connector asks; when Login returns (or panics) it closes
// every browser still open (one warning) and refuses later launches. After
// a successful Login a connector.Persistable session is Persisted and
// Saved (fsx.ErrNotDurable counts as saved; any other failure is a warning
// and the note "session not saved", never a connector failure). When a
// restored session makes Login or List fail with ErrNeedsLogin or
// ErrAuthFailed, it is Deleted and the state is needs_login. Every
// needs_login result notes `facto login <id>`; every auth_failed result (the
// credentials, not a restored session, were rejected) notes
// `facto config <id>`.
//
// Login and List errors end the connector with the state of the sentinel
// they wrap (errors.Is), anything else broken. A Fetch error wrapping a
// sentinel ends the connector with that state; any other Fetch or Ingest
// error only fails that document. A panic in a connector (its methods or
// the body it returned) is recovered: the connector is broken, the panic
// value is never logged or reported, and the next connector runs. A body
// whose Read panics inside Ingest is still closed (a panicking Close is
// recovered too). A connector without a valid id (nil, Info panics, or
// ValidateInfo refuses its Info) is labelled by its position in src.All():
// "connector[<i>]"; the refused id never reaches the result.
//
// Only panics on the goroutine running Run can be recovered: a panic in a
// goroutine a connector starts itself crashes the whole process. Connectors
// must not start goroutines that can panic.
//
// A canceled ctx stops the loop: no further Login, Fetch or Put; the error
// wraps ctx.Err() and the results so far are returned. The connector that
// was running when ctx was canceled is StateInterrupted unless it already
// reached another state (it is never reported ok, even if its last document
// was filed). Connector failures are states, never Run errors.
func (o *Orchestrator) Run(ctx context.Context, src Connectors, p connector.Period) (RunResult, error) {
	var out RunResult
	if src == nil {
		return out, fmt.Errorf("run: %w", errNilSource)
	}
	for i, c := range src.All() {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("run: %w", err)
		}
		out.Connectors = append(out.Connectors, o.runConnector(ctx, i, c, p))
	}
	if err := ctx.Err(); err != nil {
		return out, fmt.Errorf("run: %w", err)
	}
	return out, nil
}

// Login runs one fresh login of c for `facto login <id>`: as Run does for
// one connector (ValidateInfo, Env with Deps.NewHTTP, the redacting logger,
// Deps.Secrets, Deps.Prompt, Deps.Credentials and the login-only browser;
// panics recovered; cancellation is StateInterrupted), except that no saved
// session is loaded (Env.Saved is zero), and that it stops once a
// connector.Persistable session has been Persisted and Saved: List and
// Fetch are never called. Index, Dest and Namer are not needed and not
// checked. A Login error ends in the state of the sentinel it wraps,
// anything else broken; a failed save is a warning and a note, the state
// stays ok.
func Login(ctx context.Context, d Deps, c connector.Connector) ConnectorResult {
	o := build(d)
	o.loginOnly = true
	return o.runConnector(ctx, 0, c, connector.Period{})
}

// connRun is the state of one connector while it runs. It is what the panic
// recovery reads, so it always holds the latest phase and results.
type connRun struct {
	res   ConnectorResult
	phase string
	ref   *connector.DocumentRef // the ref being fetched or read, if any
	body  io.Closer              // the fetched body not closed yet, if any
	log   *slog.Logger
}

// runConnector runs c, the i-th connector of the source, and returns its
// result. It never panics.
func (o *Orchestrator) runConnector(ctx context.Context, i int, c connector.Connector, p connector.Period) (res ConnectorResult) {
	// Until Info returns, the connector is known only by its position.
	label := fmt.Sprintf("connector[%d]", i)
	cr := &connRun{
		res:   ConnectorResult{ID: label, State: StateOK},
		phase: phaseInfo,
		log:   o.log.With(slog.String("connector", label)),
	}
	defer func() {
		// panic(nil) recovers as *runtime.PanicNilError (Go >= 1.21), so
		// every panic is caught here.
		if v := recover(); v != nil {
			o.recovered(ctx, cr, v)
			res = cr.res
		}
	}()
	if c == nil {
		cr.res.State = StateBroken
		cr.log.LogAttrs(ctx, slog.LevelError, "connector source returned a nil connector; marked broken")
		return cr.res
	}
	o.runSteps(ctx, c, p, cr)
	if cr.res.State == StateOK && ctx.Err() != nil {
		cr.res.State = StateInterrupted
		cr.log.LogAttrs(ctx, slog.LevelWarn, "connector interrupted by the run's cancellation",
			slog.String("phase", cr.phase),
			slog.String("state", string(StateInterrupted)))
	}
	return cr.res
}

// recovered marks a panicking connector broken. The panic value is
// deliberately never formatted: it may hold a cookie, a token or a page
// fragment. Only its dynamic type, the connector id and the phase are
// logged; the redacting handler stays a second line of defence. A body
// left open by the panic is closed.
func (o *Orchestrator) recovered(ctx context.Context, cr *connRun, v any) {
	cr.res.State = StateBroken
	closePanicked := false
	if cr.body != nil {
		b := cr.body
		cr.body = nil
		closePanicked = closeGuarded(b)
	}
	if cr.ref != nil {
		cr.res.Documents = append(cr.res.Documents, DocResult{
			Source:     cr.res.ID,
			Provider:   normalize.Slug(cr.res.ID),
			ProviderID: cr.ref.ProviderID,
			Status:     StatusFailed,
		})
	}
	cr.log.LogAttrs(ctx, slog.LevelError, "connector panicked; marked broken (panic value withheld)",
		slog.String("phase", cr.phase),
		slog.String("panic_type", fmt.Sprintf("%T", v)),
		slog.Bool("close_panicked", closePanicked))
}

// closeGuarded closes b and reports whether Close panicked. The panic value
// is discarded unformatted, for the same reason as in recovered; a close
// error changes nothing at this point.
func closeGuarded(b io.Closer) (panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	_ = b.Close()
	return false
}

// runSteps validates, logs in, lists and fetches. It updates cr as it goes
// so that a panic leaves an accurate partial result.
func (o *Orchestrator) runSteps(ctx context.Context, c connector.Connector, p connector.Period, cr *connRun) {
	info := c.Info()
	// An id ValidateInfo refuses may be anything (a token a buggy
	// connector returned): the connector keeps its positional label in
	// the result and the log until its Info is valid.
	if err := connector.ValidateInfo(info); err != nil {
		o.fail(ctx, cr, StateBroken, err)
		return
	}
	cr.res.ID = info.ID
	cr.log = o.log.With(slog.String("connector", info.ID))

	cr.phase = phaseHTTP
	client, err := o.newHTTP(info.AllowedDomains)
	if err != nil {
		o.fail(ctx, cr, StateBroken, err)
		return
	}
	env := connector.Env{
		HTTP:        client,
		Log:         cr.log,
		Secrets:     o.secrets,
		Prompt:      o.prompt,
		Interactive: o.prompt != nil && o.prompt.Interactive(),
		Credentials: o.creds[info.ID],
	}
	var lb *loginBrowser
	if o.browser != nil {
		lb = newLoginBrowser(o.browser, info.AllowedDomains)
		env.Browser = lb
	}
	if !o.loginOnly {
		env.Saved = o.restore(ctx, cr, info.ID)
	}
	restored := !env.Saved.IsZero()

	sess, err := o.login(ctx, cr, c, env, lb)
	if err != nil {
		o.stepFailed(ctx, cr, o.rejected(ctx, cr, info.ID, restored, err), err)
		return
	}
	if ctx.Err() != nil {
		return
	}
	o.save(ctx, cr, info.ID, sess)
	if o.loginOnly {
		return
	}

	cr.phase = phaseList
	refs, err := c.List(ctx, sess, p)
	if err != nil {
		o.stepFailed(ctx, cr, o.rejected(ctx, cr, info.ID, restored, err), err)
		return
	}

	provider := normalize.Slug(info.ID)
	for i := range refs {
		if ctx.Err() != nil {
			return
		}
		if !o.fetchOne(ctx, c, sess, info, provider, refs[i], cr) {
			return
		}
	}
}

// fetchOne handles one listed ref and appends its DocResult. It returns
// false when the connector must stop (sentinel error or cancellation).
func (o *Orchestrator) fetchOne(ctx context.Context, c connector.Connector, sess connector.Session, info connector.Info, provider string, ref connector.DocumentRef, cr *connRun) bool {
	if !validProviderID(ref.ProviderID) {
		// The id may be a signed link or a token: it never reaches the
		// report, the index, the file name or the log.
		cr.res.Documents = append(cr.res.Documents, DocResult{Source: info.ID, Provider: provider, Status: StatusInvalid})
		cr.log.LogAttrs(ctx, slog.LevelWarn, "document not filed: provider id refused (value withheld)",
			slog.String("phase", cr.phase),
			slog.String("status", string(StatusInvalid)))
		return true
	}
	base := DocResult{Source: info.ID, Provider: provider, ProviderID: ref.ProviderID}

	dec, err := normalize.BeforeFetch(ctx, o.idx, provider, ref)
	if err != nil {
		if ctx.Err() != nil {
			return false
		}
		base.Status = StatusFailed
		cr.res.Documents = append(cr.res.Documents, base)
		o.docFailed(ctx, cr, base, fmt.Errorf("run: known-id lookup: %w", err))
		return true
	}
	if dec.Action == normalize.SkipKnownID {
		base.Status = StatusSkippedKnownID
		cr.res.Documents = append(cr.res.Documents, base)
		return true
	}
	if ctx.Err() != nil {
		return false
	}

	// cr.ref stays set while connector code may panic for this ref, so the
	// recovery reports it; it is cleared once its DocResult is appended.
	// (No defer: deferred resets would run before the recovery.)
	cr.phase, cr.ref = phaseFetch, &ref
	rc, err := c.Fetch(ctx, sess, ref)
	if err != nil || rc == nil {
		if rc != nil {
			_ = rc.Close()
		}
		if err == nil {
			err = errors.New("fetch returned no body")
		}
		stop := false
		if ctx.Err() == nil {
			base.Status = StatusFailed
			cr.res.Documents = append(cr.res.Documents, base)
			if st, ok := sentinelState(err); ok {
				o.fail(ctx, cr, st, err)
				stop = true
			} else {
				o.docFailed(ctx, cr, base, fmt.Errorf("run: fetch: %w", err))
			}
		}
		cr.phase, cr.ref = phaseList, nil
		return !stop && ctx.Err() == nil
	}

	cr.phase, cr.body = phaseRead, rc
	res, _ := o.Ingest(ctx, Input{
		Source:     info.ID,
		ProviderID: ref.ProviderID,
		Doc: normalize.Doc{
			Provider:    info.ID,
			Category:    info.Category,
			Kind:        ref.Kind,
			Date:        ref.IssuedAt,
			AmountCents: ref.AmountCents,
			Currency:    ref.Currency,
			Ref:         ref.ProviderID,
			Ext:         extFor(ref.MimeType),
		},
		PeriodStart: ref.PeriodStart,
		PeriodEnd:   ref.PeriodEnd,
		Content:     rc,
	})
	// Ingest logged any failure of its own.
	cr.res.Documents = append(cr.res.Documents, res)
	cr.ref = nil
	// Cleared before Close, so a panicking Close is not closed again by the
	// recovery. Ingest has read everything it needs: a close error changes
	// nothing.
	cr.body = nil
	_ = rc.Close()
	cr.phase = phaseList
	return ctx.Err() == nil
}

// maxProviderIDLen bounds a DocumentRef.ProviderID: supplier invoice
// numbers and ids are short, a longer value is a link or a blob.
const maxProviderIDLen = 128

// validProviderID reports whether id may be reported, indexed and used in a
// file name. The empty id (no dedup key) is valid. An id is refused when it
// is longer than maxProviderIDLen bytes, is not valid UTF-8, holds "://",
// "?" or "=" (a URL or a query: a buggy connector using the download link as
// the id), a whitespace, control or other non-printable character, or has
// the shape of a JWT (a bearer token used as the id). Long alphanumeric runs
// are accepted: supplier invoice numbers look like them, and reports clean
// the id through logx anyway.
func validProviderID(id string) bool {
	if len(id) > maxProviderIDLen || !utf8.ValidString(id) {
		return false
	}
	if strings.Contains(id, "://") || strings.ContainsAny(id, "?=") {
		return false
	}
	for _, r := range id {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) || r == utf8.RuneError {
			return false
		}
	}
	return !isJWTShaped(id)
}

// isJWTShaped reports whether id is three dot-separated base64url segments,
// the first starting with "eyJ" (a base64url JSON object) and the first two
// non-empty: a signed or unsigned ("alg":"none") JSON Web Token.
func isJWTShaped(id string) bool {
	if !strings.HasPrefix(id, "eyJ") {
		return false
	}
	parts := strings.Split(id, ".")
	if len(parts) != 3 || parts[1] == "" {
		return false
	}
	for _, p := range parts {
		for i := range len(p) {
			if c := p[i]; !isBase64URL(c) {
				return false
			}
		}
	}
	return true
}

// isBase64URL reports whether c belongs to the unpadded base64url alphabet.
func isBase64URL(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}

// stepFailed ends the connector after a Login or List error. An error
// caused by the run's cancellation is not a connector state: Run reports
// the cancellation itself. rejected (a restored session the supplier
// refused, already dropped) makes the state needs_login, whatever sentinel
// the connector used: the session, not the credentials, was rejected.
func (o *Orchestrator) stepFailed(ctx context.Context, cr *connRun, rejected bool, err error) {
	if ctx.Err() != nil {
		return
	}
	st, ok := sentinelState(err)
	switch {
	case rejected:
		st = StateNeedsLogin
	case !ok:
		st = StateBroken
	}
	o.fail(ctx, cr, st, err)
}

// fail sets the connector state, adds the fixed note of needs_login
// (`facto login <id>`) or auth_failed (`facto config <id>`), and logs it
// through the redacting logger. The error text never reaches the result.
func (o *Orchestrator) fail(ctx context.Context, cr *connRun, st State, err error) {
	cr.res.State = st
	switch st {
	case StateNeedsLogin:
		cr.res.Notes = append(cr.res.Notes, loginNote(cr.res.ID))
	case StateAuthFailed:
		cr.res.Notes = append(cr.res.Notes, configNote(cr.res.ID))
	case StateOK, StateBroken, StateRateLimited, StateInterrupted:
		// No fixed hint: the report state says it all.
	}
	level := slog.LevelWarn
	if st == StateBroken {
		level = slog.LevelError
	}
	cr.log.LogAttrs(ctx, level, "connector stopped",
		slog.String("phase", cr.phase),
		slog.String("state", string(st)),
		slog.Any("error", err))
}

// docFailed logs a document the connector loop could not hand to Ingest,
// through the connector's redacting logger.
func (o *Orchestrator) docFailed(ctx context.Context, cr *connRun, d DocResult, err error) {
	cr.log.LogAttrs(ctx, slog.LevelWarn, "document not filed",
		slog.String("phase", cr.phase),
		slog.String("provider_id", d.ProviderID),
		slog.String("status", string(d.Status)),
		slog.Any("error", err))
}

// sentinelState maps a connector sentinel (errors.Is) to its state.
func sentinelState(err error) (State, bool) {
	switch {
	case errors.Is(err, connector.ErrNeedsLogin):
		return StateNeedsLogin, true
	case errors.Is(err, connector.ErrAuthFailed):
		return StateAuthFailed, true
	case errors.Is(err, connector.ErrRateLimited):
		return StateRateLimited, true
	case errors.Is(err, connector.ErrBroken):
		return StateBroken, true
	}
	return "", false
}

// extFor returns the file extension of a supplier MIME type. Only types
// facto files are mapped; anything else (or unparsable) is "", and the
// namer files the document without an extension.
func extFor(mimeType string) string {
	mt, _, err := mime.ParseMediaType(mimeType)
	if err != nil {
		return ""
	}
	// ParseMediaType lowercases the type.
	if mt == "application/pdf" {
		return "pdf"
	}
	return ""
}
