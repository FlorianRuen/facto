//go:build !race

package logx_test

// raceBuild reports whether the tests run under the race detector, where
// per-byte loops cost about 20 times more (tsan plus atomic coverage
// counters).
const raceBuild = false
