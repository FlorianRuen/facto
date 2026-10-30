//go:build e2e

package e2e

// Validation of the fake site keys (J1 T22): fakesite, secrets, stdin,
// expect.requests and expect.browser. Format in scenario.go.

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"
)

// mode returns the fake site mode, "" without a fake site.
func (s *Scenario) mode() string {
	if s.FakeSite == nil {
		return ""
	}
	return s.FakeSite.Mode
}

// validateFakeSite checks fakesite, secrets and stdin.
func (s *Scenario) validateFakeSite() error {
	// The mode first: the placeholders allowed below depend on it.
	if f := s.FakeSite; f != nil && !slices.Contains(Modes, f.Mode) {
		return fmt.Errorf("fakesite.mode: %q, want one of %s", f.Mode, strings.Join(Modes, ", "))
	}
	if err := s.validateSecrets(); err != nil {
		return err
	}
	if len(s.Stdin) > maxStdin {
		return fmt.Errorf("stdin: more than %d lines", maxStdin)
	}
	for i, line := range s.Stdin {
		if strings.ContainsAny(line, "\r\n\x00") {
			return fmt.Errorf("stdin[%d]: one line each, no CR, LF or NUL", i)
		}
		allowed := map[string]bool{"totp": s.mode() == ModeTOTP, "outbox": s.mode() == ModeEmailOTP}
		if err := checkPlaceholdersWith(line, allowed); err != nil {
			return fmt.Errorf("stdin[%d]: %w", i, err)
		}
	}
	f := s.FakeSite
	if f == nil {
		return nil
	}
	for _, c := range []struct{ key, ref string }{{"fakesite.login", f.Login}, {"fakesite.password", f.Password}} {
		if c.ref == "" {
			return fmt.Errorf("%s: required (a secrets key)", c.key)
		}
		if _, ok := s.Secrets[c.ref]; !ok {
			return fmt.Errorf("%s: %q is not a secrets key", c.key, c.ref)
		}
	}
	switch {
	case f.Mode == ModeExpiredSession && f.ExpireAfter < 1:
		return errors.New("fakesite.expire_after: want >= 1 in mode expired-session")
	case f.Mode != ModeExpiredSession && f.ExpireAfter != 0:
		return errors.New("fakesite.expire_after: only in mode expired-session")
	case f.RateLimitAfter < 0 || f.RateLimitAfter > maxRateLimit:
		return fmt.Errorf("fakesite.rate_limit_after: want 0..%d", maxRateLimit)
	case f.Mode != ModeRateLimit && f.RateLimitAfter != 0:
		return errors.New("fakesite.rate_limit_after: only in mode rate-limit")
	}
	return validateInvoices(f.Invoices)
}

func (s *Scenario) validateSecrets() error {
	if len(s.Secrets) > maxSecrets {
		return fmt.Errorf("secrets: more than %d entries", maxSecrets)
	}
	for k, v := range s.Secrets {
		if err := checkSecretKey(k); err != nil {
			return fmt.Errorf("secrets: %w", err)
		}
		if v == "" {
			return fmt.Errorf("secrets: %s: empty value", k)
		}
		if err := checkPlaceholdersWith(v, map[string]bool{"totp": s.mode() == ModeTOTP}); err != nil {
			return fmt.Errorf("secrets: %s: %w", k, err)
		}
	}
	return nil
}

// checkSecretKey accepts <item>/<field>, two [A-Za-z0-9._-] segments
// other than "." and "..": the e2e file provider's reference shape.
func checkSecretKey(k string) error {
	if !secretKeyRE.MatchString(k) {
		return fmt.Errorf("key %q: want <item>/<field>, [A-Za-z0-9._-] segments", k)
	}
	item, field, _ := strings.Cut(k, "/")
	for _, seg := range []string{item, field} {
		if seg == "." || seg == ".." {
			return fmt.Errorf("key %q: dot segment", k)
		}
	}
	return nil
}

func validateInvoices(invs []FakeInvoice) error {
	if len(invs) > maxInvoices {
		return fmt.Errorf("fakesite.invoices: more than %d", maxInvoices)
	}
	seen := map[string]bool{}
	for i, inv := range invs {
		k := fmt.Sprintf("fakesite.invoices[%d]", i)
		switch {
		case !invoiceIDRE.MatchString(inv.ID):
			return fmt.Errorf("%s.id: want %s", k, invoiceIDRE)
		case seen[inv.ID]:
			return fmt.Errorf("%s.id: duplicate", k)
		case !contractRE.MatchString(inv.Contract):
			return fmt.Errorf("%s.contract: want %s", k, contractRE)
		case (inv.AmountCents == nil) != (inv.Currency == ""):
			return fmt.Errorf("%s: amount_cents and currency go together", k)
		case inv.Currency != "" && !currencyRE.MatchString(inv.Currency):
			return fmt.Errorf("%s.currency: want %s", k, currencyRE)
		case inv.Fixture == "":
			return fmt.Errorf("%s.fixture: required", k)
		}
		seen[inv.ID] = true
		if _, err := time.Parse(time.DateOnly, inv.IssuedAt); err != nil {
			return fmt.Errorf("%s.issued_at: want YYYY-MM-DD", k)
		}
		if err := checkFixture(k+".fixture", inv.Fixture); err != nil {
			return err
		}
	}
	return nil
}

// validateSite checks the expectations that need the fake site.
func (e Expect) validateSite(key string, site bool) error {
	if (len(e.Requests) > 0 || e.Browser != nil) && !site {
		return fmt.Errorf("%s: requests and browser need a fakesite", key)
	}
	if b := e.Browser; b != nil && !b.NoCDPPort && !b.ProfileRemoved {
		return fmt.Errorf("%s.browser: enable no_cdp_port or profile_removed", key)
	}
	for i, r := range e.Requests {
		if err := r.validate(fmt.Sprintf("%s.requests[%d]", key, i)); err != nil {
			return err
		}
	}
	return nil
}

func (r RequestExpect) validate(k string) error {
	set := 0
	for _, b := range []bool{r.Count != nil, r.Min != nil, r.Last} {
		if b {
			set++
		}
	}
	switch {
	case set != 1:
		return fmt.Errorf("%s: want exactly one of count, min, last", k)
	case r.Count != nil && *r.Count < 0, r.Min != nil && *r.Min < 0:
		return fmt.Errorf("%s: negative count", k)
	case r.Method != "" && !slices.Contains([]string{"GET", "POST", "HEAD"}, r.Method):
		return fmt.Errorf("%s.method: want GET, POST or HEAD", k)
	case r.Host != "" && !slices.Contains([]string{HostWWW, HostSSO, EvilHost}, r.Host):
		return fmt.Errorf("%s.host: %q is not served by the fake site", k, r.Host)
	case r.Status != 0 && (r.Status < 100 || r.Status > 599):
		return fmt.Errorf("%s.status: out of range", k)
	case r.Path != "" && !reqPathRE.MatchString(r.Path):
		return fmt.Errorf("%s.path: %q: want an absolute path, no query (the log keeps none)", k, r.Path)
	}
	if p := strings.TrimSuffix(r.Path, "*"); p != "" && p != "/" && path.Clean(p) != strings.TrimSuffix(p, "/") {
		return fmt.Errorf("%s.path: %q is not clean", k, r.Path)
	}
	return nil
}

// matches reports whether one logged request passes every set filter.
func (r RequestExpect) matches(l loggedRequest) bool {
	switch {
	case r.Method != "" && r.Method != l.Method,
		r.Host != "" && r.Host != l.Host,
		r.Status != 0 && r.Status != l.Status:
		return false
	case r.Path == "":
		return true
	case strings.HasSuffix(r.Path, "*"):
		return strings.HasPrefix(l.Path, strings.TrimSuffix(r.Path, "*"))
	default:
		return r.Path == l.Path
	}
}

func (r RequestExpect) filter() string {
	return fmt.Sprintf("{method:%q host:%q path:%q status:%d}", r.Method, r.Host, r.Path, r.Status)
}

// loggedRequest is one entry of the fake site's request log: never a query,
// a header, a cookie or a body.
type loggedRequest struct {
	Method string `json:"method"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Status int    `json:"status"`
}

// checkRequests applies every expectation to log and joins the failures.
func checkRequests(log []loggedRequest, exps []RequestExpect) error {
	var errs []error
	for i, e := range exps {
		n := 0
		for _, l := range log {
			if e.matches(l) {
				n++
			}
		}
		switch {
		case e.Count != nil && n != *e.Count:
			errs = append(errs, fmt.Errorf("requests[%d] %s: %d matching, want %d", i, e.filter(), n, *e.Count))
		case e.Min != nil && n < *e.Min:
			errs = append(errs, fmt.Errorf("requests[%d] %s: %d matching, want >= %d", i, e.filter(), n, *e.Min))
		case e.Last && (len(log) == 0 || !e.matches(log[len(log)-1])):
			errs = append(errs, fmt.Errorf("requests[%d] %s: the last request does not match", i, e.filter()))
		}
	}
	return errors.Join(errs...)
}

// checkPlaceholdersWith accepts {{canary:<kind>}} and the names allowed[name]
// is true for. {{home}} is refused: these values never name a path.
func checkPlaceholdersWith(s string, allowed map[string]bool) error {
	for _, m := range placeholderRE.FindAllStringSubmatch(s, -1) {
		if canaryKindRE.MatchString(m[1]) || allowed[m[1]] {
			continue
		}
		return fmt.Errorf("placeholder {{%s}} not allowed here", m[1])
	}
	return nil
}

// ExpandFunc replaces every {{name}} with fn(name).
func ExpandFunc(s string, fn func(name string) string) string {
	return placeholderRE.ReplaceAllStringFunc(s, func(m string) string {
		return fn(m[2 : len(m)-2])
	})
}
