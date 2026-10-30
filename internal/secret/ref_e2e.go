//go:build e2e

package secret

import "strings"

// SchemeE2E is the scheme of the e2e-only file secret provider
// (internal/secret/e2efile): e2e://<item>/<field>. It exists only in builds
// with -tags e2e (ADR 0009 A3).
const SchemeE2E = "e2e"

// init registers the e2e scheme with ParseRef. Build-tag registration is
// the only way to add a scheme to the e2e build without any runtime switch
// in the release build (A3); it runs once, before any concurrent use.
func init() {
	testSchemeParser = parseE2E
}

// parseE2E accepts e2e://<item>/<field>, both single segments matching
// [A-Za-z0-9._-]+ other than "." and "..". ok is false for another scheme.
func parseE2E(scheme, rest string) (Ref, bool, error) {
	if scheme != SchemeE2E {
		return Ref{}, false, nil
	}
	item, field, found := strings.Cut(rest, "/")
	if !found || !isSegment(item) || !isSegment(field) {
		return Ref{}, true, invalid("e2e: want e2e://<item>/<field>")
	}
	return Ref{Scheme: SchemeE2E, Item: item, Field: field}, true, nil
}
