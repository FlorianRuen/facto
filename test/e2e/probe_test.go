//go:build e2e

package e2e

// Browser probes of the e2e harness (J1 T22, same checks as T13 on a real
// login): while the fake site serves a login page, the harness inspects
// facto's process tree; after the run it checks the profile is gone.

import (
	"errors"
	"fmt"
	"strings"
)

// browserProbe is one inspection of a process tree.
type browserProbe struct {
	// BrowserPIDs are the processes whose command line has a
	// --user-data-dir (Chrome's browser process).
	BrowserPIDs []int
	// Profiles are the --user-data-dir values seen.
	Profiles []string
	// Listeners describe every listening TCP socket held by a process of
	// the tree ("pid N: addr:port").
	Listeners []string
	// DebugPortArgs are --remote-debugging-port / --remote-debugging-address
	// arguments seen on a command line.
	DebugPortArgs []string
	// Processes is the number of processes fully inspected (command line,
	// descriptors and network namespace).
	Processes int
	// Inspected counts the fully inspected descendants (root excluded).
	Inspected int
	// InspectedBrowsers counts the fully inspected processes with a
	// non-empty --user-data-dir: the Chrome processes actually checked.
	InspectedBrowsers int
	// RootHardened is set when the root (facto, PR_SET_DUMPABLE=0) could
	// not be read and was covered by the host-namespace check instead.
	RootHardened bool
	// Err is set when the tree could not be fully inspected: a probe that
	// cannot see is a failure, never a pass.
	Err error
}

// probeOptions tunes probeBrowserTree.
type probeOptions struct {
	// HardenedRoot accepts an unreadable root (facto hardens itself with
	// PR_SET_DUMPABLE=0); descendants must still be fully readable.
	HardenedRoot bool
	// HostBaseline, when non-nil, enables the host-namespace check: the
	// LISTEN rows of the test process's network namespace recorded before
	// facto started (snapshotHostListeners).
	HostBaseline hostListeners
	// AllowListeners are the exact host LISTEN rows expected during the
	// run, as listenRow.Addr renders them: the fake site's own 127.0.0.1
	// listener (siteListener). The same port on any other address or
	// family (tcp6, [::1]) is never exempt.
	AllowListeners []string
}

// siteListener is the listenRow.Addr of a tcp4 listener on 127.0.0.1:port
// ("tcp 0100007F:<port in upper-case hex>", as /proc/net/tcp writes it).
func siteListener(port uint16) string {
	return fmt.Sprintf("tcp 0100007F:%04X", port)
}

// hostListeners maps the socket inode of each LISTEN row of the test
// process's network namespace to its address.
type hostListeners map[uint64]string

// requireBrowser fails unless the probe fully inspected at least one
// browser process with a non-empty profile, so "no listening CDP port" is
// never vacuous.
func (p browserProbe) requireBrowser() error {
	if p.Err != nil {
		return p.Err
	}
	if p.InspectedBrowsers > 0 {
		return nil
	}
	return errors.New("browser probe: no Chrome process (non-empty --user-data-dir) fully inspected in facto's process tree")
}

// clean reports the probe findings, nil when no debugging port exists.
func (p browserProbe) clean() error {
	if err := p.requireBrowser(); err != nil {
		return err
	}
	var errs []error
	if len(p.Listeners) > 0 {
		errs = append(errs, fmt.Errorf("listening TCP sockets in facto's process tree: %s", strings.Join(p.Listeners, ", ")))
	}
	if len(p.DebugPortArgs) > 0 {
		errs = append(errs, fmt.Errorf("debugging port arguments: %s", strings.Join(p.DebugPortArgs, ", ")))
	}
	return errors.Join(errs...)
}

// debugPortArgs returns the arguments that ask Chrome for a TCP debugging
// endpoint.
func debugPortArgs(argv []string) []string {
	var out []string
	for _, a := range argv {
		if strings.HasPrefix(a, "--remote-debugging-port") || strings.HasPrefix(a, "--remote-debugging-address") {
			out = append(out, a)
		}
	}
	return out
}
