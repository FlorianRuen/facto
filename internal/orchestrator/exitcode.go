package orchestrator

import "errors"

// ErrConfig marks a configuration error; the CLI wraps config loading and
// validation failures with it.
var ErrConfig = errors.New("orchestrator: configuration error")

// Process exit codes (docs/spec.md "Configuration, commands and scheduling").
const (
	ExitOK        = 0 // no run error, every connector ok (or none)
	ExitAttention = 1 // a connector is not ok, or the run failed
	ExitConfig    = 2 // the error wraps ErrConfig
)

// ExitCode returns ExitConfig when errors.Is(err, ErrConfig); else
// ExitAttention when err != nil (canceled or failed run) or any connector
// state is not exactly StateOK (unknown values fail closed); else ExitOK.
// Document statuses and warnings never change the code: a connector that
// found nothing new is ok, and per-document failures and inbox leftovers
// are reported, not exit-coded. Zero connectors is ExitOK (ADR 0007 D5).
func ExitCode(r Report, err error) int {
	switch {
	case errors.Is(err, ErrConfig):
		return ExitConfig
	case err != nil:
		return ExitAttention
	}
	for _, c := range r.Connectors {
		if c.State != StateOK {
			return ExitAttention
		}
	}
	return ExitOK
}
