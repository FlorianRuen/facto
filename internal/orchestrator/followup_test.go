// Tests for the T23 open points settled by the orchestrator: report names
// never collide within one second, a stored but unindexed document is logged
// at error level with a hint, and an inbox file that cannot be removed after
// filing is reported as a warning. All data is synthetic.
package orchestrator_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/inbox"
	"github.com/FlorianRuen/facto/internal/orchestrator"
)

func reportNames(t *testing.T, stateDir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(stateDir, orchestrator.ReportsDir))
	if err != nil {
		t.Fatalf("read reports dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestWriteReport_SameSecondGetsSuffix(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	first := mixedReport()
	second := mixedReport()
	second.Documents = second.Documents[:1]
	third := emptyReport()
	third.StartedAt = first.StartedAt

	var got []orchestrator.ReportFiles
	for _, r := range []orchestrator.Report{first, second, third} {
		f, err := orchestrator.WriteReport(t.Context(), stateDir, r)
		if err != nil {
			t.Fatalf("WriteReport() error = %v", err)
		}
		got = append(got, f)
	}
	dir := filepath.Join(stateDir, orchestrator.ReportsDir)
	for i, base := range []string{"20260320T090000Z", "20260320T090000Z-1", "20260320T090000Z-2"} {
		want := orchestrator.ReportFiles{JSON: filepath.Join(dir, base+".json"), Text: filepath.Join(dir, base+".txt")}
		if got[i] != want {
			t.Errorf("report %d files = %+v, want %+v", i, got[i], want)
		}
	}
	// The first report was not overwritten by the later ones.
	wantJSON, err := first.JSON()
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}
	if b := mustRead(t, got[0].JSON); !bytes.Equal(b, wantJSON) {
		t.Error("first report was overwritten")
	}
	if b := mustRead(t, got[1].Text); string(b) != second.Text() {
		t.Error("second report content differs")
	}
	if n := len(reportNames(t, stateDir)); n != 6 {
		t.Fatalf("reports dir holds %d entries, want 6", n)
	}
}

func TestWriteReport_UnpairedNameIsSkipped(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	root, err := fsx.Open(stateDir)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirPrivate(orchestrator.ReportsDir); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Only the text half of the name is taken.
	if err := root.WriteAtomic(t.Context(), orchestrator.ReportsDir+"/20260320T090000Z.txt", []byte("older\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	files, err := orchestrator.WriteReport(t.Context(), stateDir, mixedReport())
	if err != nil {
		t.Fatalf("WriteReport() error = %v", err)
	}
	if filepath.Base(files.JSON) != "20260320T090000Z-1.json" || filepath.Base(files.Text) != "20260320T090000Z-1.txt" {
		t.Fatalf("WriteReport() files = %+v, want the -1 pair", files)
	}
	want := []string{"20260320T090000Z-1.json", "20260320T090000Z-1.txt", "20260320T090000Z.txt"}
	if got := reportNames(t, stateDir); !slices.Equal(got, want) {
		t.Fatalf("reports dir = %q, want %q (no unpaired json left)", got, want)
	}
	if b := mustRead(t, filepath.Join(stateDir, orchestrator.ReportsDir, "20260320T090000Z.txt")); string(b) != "older\n" {
		t.Fatal("existing report was replaced")
	}
}

func TestIngest_InsertFailureLoggedAsErrorWithHint(t *testing.T) {
	t.Parallel()
	r := newRig(t, nil)
	r.idx.insertErr = errors.New("synthetic insert failure")
	got, err := r.o.Ingest(t.Context(), orchestrator.Input{
		Source: "edf", ProviderID: "10234567", Doc: edfDoc(), Content: bytes.NewReader(pdf("x")),
	})
	if err == nil || got.Status != orchestrator.StatusFailed || got.Path != "" {
		t.Fatalf("Ingest() = %+v, %v; want failed, no path, an error", got, err)
	}
	if b := r.dst.file(edfPath); b == nil {
		t.Fatal("test setup: the document should have been stored")
	}
	var errLine string
	for line := range strings.SplitSeq(r.log.String(), "\n") {
		if strings.Contains(line, `"level":"ERROR"`) {
			errLine = line
		}
	}
	if errLine == "" {
		t.Fatalf("no error-level log line:\n%s", r.log.String())
	}
	if !strings.Contains(errLine, edfPath) || !strings.Contains(errLine, "unindexed") {
		t.Fatalf("error log line lacks the stored path or the unindexed hint: %s", errLine)
	}
}

// doneFailInbox is a fakeInbox whose Done always fails.
type doneFailInbox struct {
	*fakeInbox
	err error
}

func (f *doneFailInbox) Done(context.Context, inbox.Item) error { return f.err }

func TestIngestInbox_DoneFailureKeepsStatusAndWarns(t *testing.T) {
	t.Parallel()
	r := newRig(t, nil)
	content := pdf("filed but stuck")
	src := &doneFailInbox{
		fakeInbox: newFakeInbox(r.ev, []inbox.Item{item("drop.pdf", edfDoc(), content)}, map[string][]byte{"drop.pdf": content},
			inbox.Warning{Path: "unknown.pdf", Reason: inbox.ReasonUnidentified}),
		err: errors.New("synthetic remove failure"),
	}
	res, err := r.o.IngestInbox(t.Context(), src)
	if err != nil {
		t.Fatalf("IngestInbox() error = %v", err)
	}
	if len(res.Documents) != 1 || res.Documents[0].Status != orchestrator.StatusFiled || res.Documents[0].Path != edfPath {
		t.Fatalf("documents = %+v, want one filed at %q", res.Documents, edfPath)
	}
	wantWarn := []orchestrator.Warning{
		{Source: "inbox", Path: "unknown.pdf", Reason: "unidentified"},
		{Source: "inbox", Path: "drop.pdf", Reason: "not-removed"},
	}
	if !slices.Equal(res.Warnings, wantWarn) {
		t.Fatalf("warnings = %+v, want %+v", res.Warnings, wantWarn)
	}
	if orchestrator.ReasonNotRemoved != "not-removed" {
		t.Errorf("ReasonNotRemoved = %q", orchestrator.ReasonNotRemoved)
	}
	if !strings.Contains(r.log.String(), `"level":"WARN"`) {
		t.Errorf("Done failure not logged at warn level:\n%s", r.log.String())
	}
}

func TestIngest_NilLoggerAndNoContent(t *testing.T) {
	t.Parallel()
	o, err := orchestrator.New(orchestrator.Deps{Index: newFakeIndex(&events{}), Dest: newFakeDest(&events{}), Namer: namer(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	got, err := o.Ingest(t.Context(), orchestrator.Input{Source: "edf", ProviderID: "10234567", Doc: edfDoc()})
	if err == nil || got.Status != orchestrator.StatusFailed {
		t.Fatalf("Ingest(no content) = %+v, %v; want failed and an error", got, err)
	}
}

func TestReport_TextEscapesBytesAndBackslash(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, origin, want string
	}{
		{"backslash", `a\b.pdf`, `a\\b.pdf`},
		{"invalid byte", "a\xffb.pdf", `a\xffb.pdf`},
		{"replacement char", "a\uFFFDb.pdf", `a\ufffdb.pdf`},
		{"astral tag char", "a\U000E0041b.pdf", `a\U000e0041b.pdf`},
		{"printable unicode kept", "facture-été.pdf", "facture-été.pdf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := emptyReport()
			r.Documents = []orchestrator.DocResult{{Source: "inbox", Origin: tt.origin, Status: orchestrator.StatusFailed}}
			if line := "- failed inbox " + tt.want + "\n"; !strings.HasSuffix(r.Text(), line) {
				t.Fatalf("Text() =\n%s\nwant it to end with %q", r.Text(), line)
			}
		})
	}
}
