//go:build unix

// Unix-only permission and symlink tests for the orchestrator (J0 task T23).
package orchestrator_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/orchestrator"
)

func mode(t *testing.T, p string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatalf("lstat %s: %v", p, err)
	}
	return fi.Mode()
}

func TestWriteReport_PrivatePerms(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	files, err := orchestrator.WriteReport(t.Context(), stateDir, mixedReport())
	if err != nil {
		t.Fatalf("WriteReport() error = %v", err)
	}
	if m := mode(t, filepath.Join(stateDir, orchestrator.ReportsDir)); !m.IsDir() || m.Perm() != 0o700 {
		t.Errorf("reports dir mode = %v, want drwx------", m)
	}
	for _, p := range []string{files.JSON, files.Text} {
		if m := mode(t, p); !m.IsRegular() || m.Perm() != 0o600 {
			t.Errorf("%s mode = %v, want -rw-------", p, m)
		}
	}
}

func TestWriteReport_RefusesInsecureReportsDir(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	reports := filepath.Join(stateDir, orchestrator.ReportsDir)
	if err := os.Mkdir(reports, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	groupReadable := fs.FileMode(0o755) // the insecure mode under test
	if err := os.Chmod(reports, groupReadable); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err := orchestrator.WriteReport(t.Context(), stateDir, mixedReport())
	if !errors.Is(err, fsx.ErrInsecurePerms) {
		t.Fatalf("WriteReport() error = %v, want fsx.ErrInsecurePerms", err)
	}
	entries, err := os.ReadDir(reports)
	if err != nil {
		t.Fatalf("read reports dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("reports written into an insecure dir: %v", entries)
	}
	if m := mode(t, reports); m.Perm() != 0o755 {
		t.Errorf("reports dir mode changed to %v; refuse, do not fix silently", m)
	}
}

func TestWriteReport_RefusesReportsSymlinkOutOfStateDir(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	stateDir := filepath.Join(base, "state")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{stateDir, outside} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(stateDir, orchestrator.ReportsDir)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := orchestrator.WriteReport(t.Context(), stateDir, mixedReport()); err == nil {
		t.Fatal("WriteReport() followed a reports symlink out of the state dir")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatalf("read outside: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("report written outside the state dir: %v", entries)
	}
}

func TestIngestInbox_FiledDocumentIsPrivate(t *testing.T) {
	t.Parallel()
	r := newRealRig(t)
	write(t, r.inboxDir, "2026-03-14_edf_invoice_84-12EUR_10234567.pdf", pdf("private"))
	res := r.run(t)
	if len(res.Documents) != 1 || res.Documents[0].Status != orchestrator.StatusFiled {
		t.Fatalf("documents = %+v, want one filed", res.Documents)
	}
	if m := mode(t, filepath.Join(r.out, filepath.FromSlash(edfPath))); m.Perm() != 0o600 {
		t.Errorf("filed document mode = %v, want -rw-------", m)
	}
	for _, d := range []string{"2026", "2026/energy", "2026/energy/edf"} {
		if m := mode(t, filepath.Join(r.out, filepath.FromSlash(d))); m.Perm() != 0o700 {
			t.Errorf("%s mode = %v, want drwx------", d, m)
		}
	}
}
