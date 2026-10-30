package cft

import "time"

// Pinned returns the manifest compiled into facto: Chrome for Testing
// stable for linux64 (J1 task T12, decision A10, ADR 0008).
//
// Trust-on-first-use: Chrome for Testing publishes download URLs but no
// checksum. Version and URL come from the "Stable" channel of
// https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json
// on PinnedAt; Size and SHA256 were computed from the archive downloaded
// through internal/httpx (NewPinned, exact host and path prefix), then
// recomputed by a second, independent download through Installer.Install
// (make chrome), which refuses any mismatch.
//
// Patching policy (ADR 0008): bump on every stable Chrome security release,
// never more than MaxPinAge behind; WarnIfStale warns at run time.
func Pinned() Manifest {
	return Manifest{
		Version:    "156.0.8078.80",
		Platform:   platformLinux64,
		URL:        "https://storage.googleapis.com/chrome-for-testing-public/156.0.8078.80/linux64/chrome-linux64.zip",
		Host:       "storage.googleapis.com",
		PathPrefix: "/chrome-for-testing-public/",
		Size:       201329937,
		SHA256:     "b711c720f774be355197f32edf37e0651418ba036d92446ee2da19ac017540a7",
		PinnedAt:   time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC),
	}
}
