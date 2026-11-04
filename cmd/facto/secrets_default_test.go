//go:build !e2e

package main

// e2eBuild reports a build with -tags e2e.
const e2eBuild = false

// wantSchemes are the secret schemes of a default (release) build, sorted.
func wantSchemes() []string { return []string{"bw", "keyring"} }
