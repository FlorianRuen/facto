//go:build e2e && !linux

package e2e

import (
	"errors"
	"runtime"
)

var errProbeUnsupported = errors.New("browser probe: not implemented on " + runtime.GOOS)

// probeBrowserTree is implemented on linux only (/proc). Elsewhere it
// reports an error, so a scenario asking for a probe fails instead of
// passing unchecked.
func probeBrowserTree(int, probeOptions) browserProbe {
	return browserProbe{Err: errProbeUnsupported}
}

// snapshotHostListeners is linux only, like probeBrowserTree.
func snapshotHostListeners() (hostListeners, error) { return nil, errProbeUnsupported }
