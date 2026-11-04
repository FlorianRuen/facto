//go:build e2e

package main

import "github.com/FlorianRuen/facto/connectors/fakeprovider"

// init wires the e2e-only hooks: the build ships connectors/fakeprovider,
// and FACTO_E2E_INTERACTIVE=1 lets prompts read plain stdin lines (A8).
// Release builds never link this file (`make release-e2e-check`).
func init() {
	registerTestConnectors = fakeprovider.Register
	e2eStdinPrompts = true
}
