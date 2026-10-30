// Package tools only pins the versions of facto's dev and security tools
// through the tool directives of its go.mod (ADR 0001). It holds no code.
//
// This file exists so that the module has one Go package: osv-scanner's Go
// call analysis (govulncheck) fails with "no packages matched" on a module
// without any, and a plain `osv-scanner --recursive .` then exits non-zero
// even once every finding is filtered by tools/osv-scanner.toml (SEC-J1-10).
package tools
