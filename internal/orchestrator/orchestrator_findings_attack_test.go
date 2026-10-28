//go:build unix

// Red-team findings (J0 T30) against internal/orchestrator, now defended.
// Uses runAtk, atkConn, atkInfo, atkRef, atkNoCanary and atkReportBytes
// from attack_test.go.
package orchestrator_test

import (
	"testing"

	"github.com/FlorianRuen/facto/internal/orchestrator"
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
