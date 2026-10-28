// Tests for the collection report (J0 task T23): a JSON report and a text
// summary written to <state dir>/reports through fsx. Spec: docs/spec.md
// "Run lifecycle" step 6, "Graceful degradation", "Data in memory and in
// output" (reports never contain a secret); docs/adr/0007 D1 (state dir), D2
// (unidentified inbox files reported as warnings).
//
// Expected API (implementer: follow exactly):
//
//	// Status is the outcome of one document.
//	type Status string
//	const (
//		StatusFiled            Status = "filed"             // Put and Insert succeeded (any version)
//		StatusNotDurable       Status = "not-durable"       // published and indexed, directory fsync failed; inbox file kept
//		StatusSkippedDuplicate Status = "skipped-duplicate" // dedup rule 2 (same SHA-256)
//		StatusSkippedKnownID   Status = "skipped-known-id"  // dedup rule 1 (set by the connector loop, T24)
//		StatusExists           Status = "exists"            // destination already had a file at the path (dest.ErrExists)
//		StatusTooLarge         Status = "too-large"         // over MaxSize
//		StatusInvalid          Status = "invalid"           // metadata cannot be named or indexed
//		StatusChanged          Status = "changed"           // inbox file changed since scan (inbox.ErrChanged)
//		StatusFailed           Status = "failed"            // any other error (details only in the redacted log)
//	)
//
//	// DocResult is one report line. It never carries error text.
//	type DocResult struct {
//		Source     string // "inbox" or the connector id
//		Origin     string // inbox item path, "" for connectors
//		Provider   string // index provider (slug)
//		ProviderID string
//		Status     Status
//		Version    int    // decided version; 0 when skipped or failed before dedup
//		Path       string // relative path filed at (filed, not-durable) or clashing with (exists); "" otherwise
//	}
//
//	type Warning struct {
//		Source string // "inbox"
//		Path   string
//		Reason string // inbox.Reason value
//	}
//
//	type Report struct {
//		StartedAt, FinishedAt time.Time
//		Documents []DocResult
//		Warnings  []Warning
//	}
//
//	// JSON renders the report as in testdata/TestReport_Golden/*.json.golden:
//	// 2-space indent, times in UTC RFC 3339, "counts" holds only non-zero
//	// statuses, empty lists are [], trailing newline.
//	func (r Report) JSON() ([]byte, error)
//
//	// Text renders the human summary as in testdata/TestReport_Golden/
//	// *.txt.golden. One line per document and per warning; no control or
//	// format character other than the '\n' line ends (untrusted file names
//	// are escaped).
//	func (r Report) Text() string
//
//	// ReportsDir is the report directory inside the state dir.
//	const ReportsDir = "reports"
//
//	// ReportFiles are the absolute paths WriteReport wrote.
//	type ReportFiles struct{ JSON, Text string }
//
//	// WriteReport writes r.JSON() and r.Text() through fsx (atomic, 0600)
//	// to <stateDir>/reports/<StartedAt UTC as 20060102T150405Z>.json and
//	// .txt, creating reports/ 0700. stateDir must exist (fs.ErrNotExist);
//	// an existing reports dir with group/world bits is refused
//	// (fsx.ErrInsecurePerms) and nothing is written; nothing is ever
//	// written outside stateDir.
//	func WriteReport(ctx context.Context, stateDir string, r Report) (ReportFiles, error)
package orchestrator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/inbox"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

var update = flag.Bool("update", false, "rewrite golden files")

// paris is a fixed non-UTC zone: report times must come out in UTC.
var paris = time.FixedZone("CET", 3600)

func mixedReport() orchestrator.Report {
	clk := clock.NewFake(time.Date(2026, time.March, 20, 10, 0, 0, 0, paris))
	started := clk.Now()
	clk.Advance(5 * time.Second)
	return orchestrator.Report{
		// The fake clock returns UTC; callers may pass any zone.
		StartedAt:  started.In(paris),
		FinishedAt: clk.Now().In(paris),
		Documents: []orchestrator.DocResult{
			{Source: "inbox", Origin: "2026-03-14_edf_invoice_84-12EUR_10234567.pdf", Provider: "edf", ProviderID: "10234567", Status: orchestrator.StatusFiled, Version: 1, Path: edfPath},
			{Source: "inbox", Origin: "edf/2026-03-14-scan.pdf", Provider: "edf", Status: orchestrator.StatusSkippedDuplicate},
			{Source: "inbox", Origin: "impots/2026-10-02_avis.pdf", Provider: "impots", ProviderID: "avis-2026", Status: orchestrator.StatusFiled, Version: 2, Path: "2026/housing/impots/2026-10-02_impots_tax-notice_avis-2026_v2.pdf"},
			{Source: "exemple", Provider: "exemple", ProviderID: "FA-0042", Status: orchestrator.StatusExists, Version: 1, Path: "2026/services/exemple/2026-02-01_exemple_invoice_fa-0042.pdf"},
			{Source: "exemple", Provider: "exemple", ProviderID: "FA-0043", Status: orchestrator.StatusFailed},
			{Source: "exemple", Provider: "exemple", ProviderID: "FA-0041", Status: orchestrator.StatusSkippedKnownID},
		},
		Warnings: []orchestrator.Warning{
			{Source: "inbox", Path: "big.pdf", Reason: string(inbox.ReasonTooLarge)},
			{Source: "inbox", Path: "unknown.pdf", Reason: string(inbox.ReasonUnidentified)},
		},
	}
}

func emptyReport() orchestrator.Report {
	at := time.Date(2026, time.March, 20, 10, 0, 0, 0, paris)
	return orchestrator.Report{StartedAt: at, FinishedAt: at}
}

func TestReport_Golden(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		r    orchestrator.Report
	}{
		{"mixed", mixedReport()},
		{"empty", emptyReport()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			js, err := tt.r.JSON()
			if err != nil {
				t.Fatalf("JSON() error = %v", err)
			}
			checkGolden(t, filepath.Join("testdata", "TestReport_Golden", tt.name+".json.golden"), js)
			checkGolden(t, filepath.Join("testdata", "TestReport_Golden", tt.name+".txt.golden"), []byte(tt.r.Text()))
		})
	}
}

func checkGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		dir, name := filepath.Split(path)
		r, err := fsx.Open(".")
		if err != nil {
			t.Fatalf("update golden: %v", err)
		}
		defer func() { _ = r.Close() }()
		if err := mkdirAll(r, filepath.ToSlash(filepath.Clean(dir))); err != nil {
			t.Fatalf("update golden: %v", err)
		}
		if err := r.WriteAtomic(t.Context(), filepath.ToSlash(filepath.Join(dir, name)), got); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read golden %s: %v (run go test -update and review)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch (run go test -update and review the diff)\n--- got\n%s\n--- want\n%s", path, got, want)
	}
}

func mkdirAll(r *fsx.Root, dir string) error {
	if dir == "." || dir == "" {
		return nil
	}
	if _, err := r.Lstat(dir); err == nil {
		return nil
	}
	if err := mkdirAll(r, filepath.ToSlash(filepath.Dir(dir))); err != nil {
		return err
	}
	return r.MkdirPrivate(dir)
}

func TestReport_TextEscapesUntrustedNames(t *testing.T) {
	t.Parallel()
	clean := mixedReport()
	evil := mixedReport()
	evil.Documents[1].Origin = "edf/evil\nfiled forged.pdf\r\x1b[31m\u202egpj.pdf\x00"
	evil.Warnings[1].Path = "unk\nnown\t\x7f\u2028.pdf"

	text := evil.Text()
	for i, r := range text {
		if r == '\n' {
			continue
		}
		if r == utf8.RuneError || unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			t.Fatalf("Text() has raw control/format rune %U at byte %d:\n%q", r, i, text)
		}
	}
	if got, want := strings.Count(text, "\n"), strings.Count(clean.Text(), "\n"); got != want {
		t.Fatalf("Text() has %d lines, want %d: a file name injected lines\n%s", got, want, text)
	}

	js, err := evil.JSON()
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}
	// JSON is for machines: C0 controls must be escaped (valid JSON) and the
	// name must round-trip exactly; display safety is the text summary's job.
	if bytes.ContainsAny(js, "\x1b\x00\r\t") {
		t.Fatalf("JSON() has raw control bytes: %q", js)
	}
	var decoded struct {
		Documents []struct {
			Origin string `json:"origin"`
		} `json:"documents"`
	}
	if err := json.Unmarshal(js, &decoded); err != nil {
		t.Fatalf("JSON() is not valid JSON: %v", err)
	}
	if len(decoded.Documents) < 2 || decoded.Documents[1].Origin != evil.Documents[1].Origin {
		t.Fatalf("JSON() did not round-trip the untrusted origin: %+v", decoded.Documents)
	}
}

func TestWriteReport_PrivateFilesInStateDir(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	r := mixedReport()

	files, err := orchestrator.WriteReport(t.Context(), stateDir, r)
	if err != nil {
		t.Fatalf("WriteReport() error = %v", err)
	}
	want := orchestrator.ReportFiles{
		JSON: filepath.Join(stateDir, orchestrator.ReportsDir, "20260320T090000Z.json"),
		Text: filepath.Join(stateDir, orchestrator.ReportsDir, "20260320T090000Z.txt"),
	}
	if files != want {
		t.Fatalf("WriteReport() files = %+v, want %+v", files, want)
	}
	if orchestrator.ReportsDir != "reports" {
		t.Errorf("ReportsDir = %q, want %q", orchestrator.ReportsDir, "reports")
	}
	wantJSON, err := r.JSON()
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}
	for path, content := range map[string][]byte{want.JSON: wantJSON, want.Text: []byte(r.Text())} {
		got, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !bytes.Equal(got, content) {
			t.Errorf("%s content differs from the rendered report", path)
		}
	}
	entries, err := os.ReadDir(filepath.Join(stateDir, orchestrator.ReportsDir))
	if err != nil {
		t.Fatalf("read reports dir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("reports dir holds %d entries, want exactly the 2 reports (no temp file left)", len(entries))
	}
}

func TestWriteReport_SecondRunAddsReports(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	first := mixedReport()
	second := emptyReport()
	second.StartedAt = second.StartedAt.Add(24 * time.Hour)
	second.FinishedAt = second.StartedAt
	for _, r := range []orchestrator.Report{first, second} {
		if _, err := orchestrator.WriteReport(t.Context(), stateDir, r); err != nil {
			t.Fatalf("WriteReport() error = %v", err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(stateDir, orchestrator.ReportsDir))
	if err != nil {
		t.Fatalf("read reports dir: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("reports dir holds %d entries, want 4 (earlier reports kept)", len(entries))
	}
}

func TestWriteReport_MissingStateDir(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "absent")
	_, err := orchestrator.WriteReport(t.Context(), missing, mixedReport())
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("WriteReport() error = %v, want fs.ErrNotExist", err)
	}
	if _, serr := os.Lstat(missing); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatal("WriteReport created the missing state dir")
	}
}

func TestWriteReport_ContextCanceled(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := orchestrator.WriteReport(ctx, stateDir, mixedReport())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WriteReport() error = %v, want context.Canceled", err)
	}
	entries, _ := os.ReadDir(filepath.Join(stateDir, orchestrator.ReportsDir))
	if len(entries) != 0 {
		t.Fatalf("reports written under a canceled context: %v", entries)
	}
}

func TestReport_NoCanary(t *testing.T) {
	t.Parallel()
	artDir := testsecrets.ArtifactDir(t)
	token := testsecrets.Canary(t, testsecrets.Token)
	cookie := testsecrets.Canary(t, testsecrets.Cookie)
	session := testsecrets.Canary(t, testsecrets.Session)

	r := newRig(t, nil)
	// Errors from every dependency carry secrets, the way a remote
	// destination or a driver error might quote a URL or a header.
	r.dst.err = errors.New("upload https://upload.example.invalid/f?access_token=" + token + " cookie=" + cookie + ": synthetic failure")
	r.idx.insertErr = errors.New("synthetic insert failure session=" + session)

	a, b, c := pdf("a"), pdf("b"), pdf("c")
	other := edfDoc()
	other.Ref = "10234568"
	src := newFakeInbox(r.ev,
		[]inbox.Item{item("a.pdf", edfDoc(), a), item("b.pdf", other, b), item("c.pdf", other, c)},
		map[string][]byte{"a.pdf": a, "b.pdf": b, "c.pdf": c},
		inbox.Warning{Path: "unknown.pdf", Reason: inbox.ReasonUnidentified},
	)
	src.openErr["c.pdf"] = errors.New("synthetic open failure bearer " + token)

	started := time.Date(2026, time.March, 20, 9, 0, 0, 0, time.UTC)
	res, err := r.o.IngestInbox(t.Context(), src)
	if err != nil {
		t.Fatalf("IngestInbox() error = %v", err)
	}
	rep := orchestrator.Report{StartedAt: started, FinishedAt: started.Add(time.Second), Documents: res.Documents, Warnings: res.Warnings}
	if len(rep.Documents) != 3 || len(rep.Warnings) != 1 {
		t.Fatalf("report = %+v, want 3 documents and 1 warning", rep)
	}

	files, err := orchestrator.WriteReport(t.Context(), artDir, rep)
	if err != nil {
		t.Fatalf("WriteReport() error = %v", err)
	}
	root, err := fsx.Open(artDir)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteAtomic(t.Context(), "orchestrator.log", r.log.Bytes()); err != nil {
		t.Fatalf("write log artifact: %v", err)
	}

	js, err := rep.JSON()
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}
	artifacts := map[string][]byte{"json": js, "text": []byte(rep.Text()), "log": r.log.Bytes()}
	for _, p := range []string{files.JSON, files.Text} {
		b, err := os.ReadFile(filepath.Clean(p))
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		artifacts[p] = b
	}
	for name, data := range artifacts {
		for _, secret := range []string{token, cookie, session, testsecrets.Prefix} {
			if bytes.Contains(data, []byte(secret)) {
				t.Errorf("%s contains a canary:\n%s", name, data)
			}
		}
	}
	if r.log.Len() == 0 {
		t.Error("nothing was logged for three failed documents")
	}
}
