//go:build !e2e

package main

import "testing"

// TestKeyBackend_ReleaseHasNoTestHook: a release build links no e2e key
// source; the OS keyring stays the only default (ADR 0009 A3).
func TestKeyBackend_ReleaseHasNoTestHook(t *testing.T) {
	t.Parallel()
	if testKeyBackend != nil {
		t.Fatal("testKeyBackend is set in a build without -tags e2e")
	}
}

// TestKeyringBackend_ReleaseIsTheOSKeyring: a release build has no e2e
// keyring hook; keyring:// refs go to the OS keyring.
func TestKeyringBackend_ReleaseIsTheOSKeyring(t *testing.T) {
	t.Parallel()
	if testKeyringBackend != nil {
		t.Fatal("testKeyringBackend is set in a build without -tags e2e")
	}
}
