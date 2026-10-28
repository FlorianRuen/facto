//go:build unix

// Red-team findings (J0 T30) against internal/orchestrator, now defended.
// Uses runAtk, atkConn, atkInfo, atkRef, atkNoCanary and atkReportBytes
// from attack_test.go.
package orchestrator_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/store"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// TestAttack_OrchInvalidConnectorIDNeverReachesReport registers a connector
// whose Info.ID is a secret (a buggy connector returning a token instead of
// its id). ValidateInfo refuses it, but the report must not print it.
func TestAttack_OrchInvalidConnectorIDNeverReachesReport(t *testing.T) {
	t.Parallel()
	tok := testsecrets.Canary(t, testsecrets.Token)
	res, r := runAtk(t, &atkConn{info: atkInfo(tok)})
	if len(res.Connectors) != 1 || res.Connectors[0].State != orchestrator.StateBroken {
		t.Fatalf("got %+v, want one broken connector", res.Connectors)
	}
	atkNoCanary(t, "log", r.log.Bytes(), tok)
	atkNoCanary(t, "report", atkReportBytes(t, res), tok)
}

// TestAttack_OrchProviderIDSecretNeverReachesReport lists a document whose
// ProviderID is a signed download URL holding a token (a buggy connector
// using the link as the id). Report lines must not carry the token.
func TestAttack_OrchProviderIDSecretNeverReachesReport(t *testing.T) {
	t.Parallel()
	tok := testsecrets.Canary(t, testsecrets.Token)
	ref := atkRef("https://billing.fournisseur.test/dl?token=" + tok)
	res, r := runAtk(t, &atkConn{
		info: atkInfo("leaky-id"),
		list: func() ([]connector.DocumentRef, error) { return []connector.DocumentRef{ref}, nil },
		fetch: func(connector.DocumentRef) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("%PDF-1.7 synthetic")), nil
		},
	})
	atkNoCanary(t, "log", r.log.Bytes(), tok)
	atkNoCanary(t, "report", atkReportBytes(t, res), tok)
	// The index (spec: "Index, reports, logs: no secret") and the filed
	// name, which may sit in a synced folder: Slug lowercases the token,
	// which is still the token (base32 is case-insensitive).
	var idx []byte
	for _, n := range []string{store.FileName, store.FileName + "-wal"} {
		b, err := os.ReadFile(filepath.Clean(filepath.Join(r.state, n)))
		if err == nil {
			idx = append(idx, b...)
		}
	}
	atkNoCanary(t, "index.db", idx, tok)
	for _, c := range res.Connectors {
		for _, d := range c.Documents {
			if strings.Contains(d.Path, strings.ToLower(tok)) {
				t.Errorf("filed file name carries the case-folded token: %s", d.Path)
			}
		}
	}
}
