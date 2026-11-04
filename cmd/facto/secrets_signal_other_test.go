//go:build !unix

package main

import "testing"

// canRaiseTerm: the Windows runtime never delivers SIGTERM and a process
// cannot send itself a console Ctrl-C; the cancel case covers the path.
const canRaiseTerm = false

func raiseTerm(t *testing.T) {
	t.Helper()
	t.Fatal("raiseTerm is not available on this OS")
}
