// Package proc hardens the facto process before it touches any secret: no
// core dump and, on Linux, no ptrace attach or /proc/<pid>/mem read by other
// processes of the same user (docs/spec.md "Process hardening").
package proc
