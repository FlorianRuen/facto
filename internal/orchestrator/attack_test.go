//go:build unix

// Red-team attack tests for the pipeline (J0 task T30): hostile inbox
// content (Factur-X fields, subfolder names, symlinks, FIFOs, huge files,
// name clashes) against the REAL inbox, store and local destination, and
// hostile connectors (panics, errors, metadata carrying canaries) against
// Run. Logs and reports are written under testsecrets.ArtifactDir so that
// `make leakcheck` greps them. A test passes when the attack is defeated.
// Everything is synthetic.
package orchestrator_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/clock"
	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/dest"
	"github.com/FlorianRuen/facto/internal/dest/local"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/inbox"
	"github.com/FlorianRuen/facto/internal/normalize"
	"github.com/FlorianRuen/facto/internal/orchestrator"
	"github.com/FlorianRuen/facto/internal/store"
	"github.com/FlorianRuen/facto/internal/testsecrets"
)

// atkRig wires the real store, local destination and inbox under base:
// base/out (output, holding inbox/), base/state, base/outside (a folder an
// attacker would like facto to read from or write into).
type atkRig struct {
	base, out, inboxDir, state, outside string
	st                                  *store.Store
	o                                   *orchestrator.Orchestrator
	log                                 *bytes.Buffer
}

func newAtkRig(t *testing.T) *atkRig {
	t.Helper()
	base := t.TempDir()
	r := &atkRig{
		base:     base,
		out:      filepath.Join(base, "out"),
		inboxDir: filepath.Join(base, "out", "inbox"),
		state:    filepath.Join(base, "state"),
		outside:  filepath.Join(base, "outside"),
		log:      &bytes.Buffer{},
	}
	root, err := fsx.Open(base)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = root.Close() }()
	for _, d := range []string{"out", "out/inbox", "outside"} {
		if err := root.MkdirPrivate(d); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	st, err := store.Open(t.Context(), r.state, clock.NewFake(time.Date(2026, time.March, 20, 9, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	r.st = st
	loc, err := local.New(t.Context(), r.out)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	t.Cleanup(func() { _ = loc.Close() })
	o, err := orchestrator.New(orchestrator.Deps{
		Index: st, Dest: loc, Namer: namer(t),
		// Plain handler: the orchestrator must wrap it in logx itself.
		Log: slog.New(slog.NewJSONHandler(&lockedWriter{w: r.log}, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.o = o
	return r
}

// put writes rel under dir through fsx, creating parents.
func atkPut(t *testing.T, dir, rel string, data []byte) {
	t.Helper()
	root, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = root.Close() }()
	if d := path.Dir(rel); d != "." {
		if err := root.MkdirPrivate(d); err != nil {
			t.Fatalf("mkdir %q: %v", d, err)
		}
	}
	if err := root.WriteAtomic(t.Context(), rel, data); err != nil {
		t.Fatalf("write %q: %v", rel, err)
	}
}

func (r *atkRig) ingest(t *testing.T) orchestrator.InboxResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	ib, err := inbox.New(r.inboxDir, inbox.Options{Providers: map[string]inbox.ProviderDefaults{"edf": {Category: "energy"}}})
	if err != nil {
		t.Fatalf("inbox.New: %v", err)
	}
	defer func() { _ = ib.Close() }()
	res, err := r.o.IngestInbox(ctx, ib)
	if err != nil {
		t.Fatalf("IngestInbox: %v", err)
	}
	return res
}

// tree lists every entry under dir (slash paths, Lstat semantics).
func atkTree(t *testing.T, dir string) map[string]fs.FileMode {
	t.Helper()
	out := map[string]fs.FileMode{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = fi.Mode()
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}

// checkConfined fails when anything appeared outside out/ and state/, when
// outside/ changed, or when a filed path is not canonical.
func (r *atkRig) checkConfined(t *testing.T, outsideBefore map[string]fs.FileMode, res orchestrator.InboxResult, planted ...string) {
	t.Helper()
	for p := range atkTree(t, r.base) {
		top, _, _ := strings.Cut(p, "/")
		if top != "." && top != "out" && top != "state" && top != "outside" {
			t.Errorf("entry written outside the output and state folders: %q", p)
		}
	}
	after := atkTree(t, r.outside)
	if len(after) != len(outsideBefore) {
		t.Errorf("outside/ changed: before %v, after %v", outsideBefore, after)
	}
	for p, m := range atkTree(t, r.out) {
		if m.Type()&fs.ModeSymlink != 0 && !strings.HasPrefix(p, "inbox/") && !slices.Contains(planted, p) {
			t.Errorf("symlink created in output: %q", p)
		}
		if m.IsRegular() && m.Perm() != 0o600 && !strings.HasPrefix(p, "inbox/") {
			t.Errorf("filed %q has mode %v, want 0600", p, m.Perm())
		}
		if m.IsDir() && p != "." && m.Perm() != 0o700 {
			t.Errorf("dir %q has mode %v, want 0700", p, m.Perm())
		}
	}
	for _, d := range res.Documents {
		if d.Path == "" {
			continue
		}
		dir, file := path.Split(d.Path)
		if err := dest.ValidatePath(normalize.Path{Dir: strings.TrimSuffix(dir, "/"), File: file}); err != nil {
			t.Errorf("filed path %q is not canonical: %v", d.Path, err)
		}
		if strings.HasPrefix(d.Path, "inbox/") || strings.HasPrefix(d.Path, ".facto") {
			t.Errorf("document filed into a reserved folder: %q", d.Path)
		}
	}
}

// atkCII builds a synthetic CII document with hostile number and seller.
func atkCII(number, seller string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<rsm:CrossIndustryInvoice xmlns:rsm="urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100"` +
		` xmlns:ram="urn:un:unece:uncefact:data:standard:ReusableAggregateBusinessInformationEntity:100"` +
		` xmlns:udt="urn:un:unece:uncefact:data:standard:UnqualifiedDataType:100">` +
		`<rsm:ExchangedDocument><ram:ID>` + number + `</ram:ID><ram:TypeCode>380</ram:TypeCode>` +
		`<ram:IssueDateTime><udt:DateTimeString format="102">20260314</udt:DateTimeString></ram:IssueDateTime></rsm:ExchangedDocument>` +
		`<rsm:SupplyChainTradeTransaction><ram:ApplicableHeaderTradeAgreement><ram:SellerTradeParty><ram:Name>` + seller +
		`</ram:Name></ram:SellerTradeParty></ram:ApplicableHeaderTradeAgreement>` +
		`<ram:ApplicableHeaderTradeSettlement><ram:InvoiceCurrencyCode>EUR</ram:InvoiceCurrencyCode>` +
		`<ram:SpecifiedTradeSettlementHeaderMonetarySummation><ram:GrandTotalAmount>12.34</ram:GrandTotalAmount>` +
		`</ram:SpecifiedTradeSettlementHeaderMonetarySummation></ram:ApplicableHeaderTradeSettlement>` +
		`</rsm:SupplyChainTradeTransaction></rsm:CrossIndustryInvoice>`)
}

// atkPDF embeds xml as factur-x.xml in a minimal synthetic PDF. tag makes
// the content unique.
func atkPDF(xml []byte, tag string) []byte {
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(factur-x.xml) 5 0 R] >> >> >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
		fmt.Sprintf("<< /Type /EmbeddedFile /Subtype /text#2Fxml /Length %d >>\nstream\n%s\nendstream", len(xml), xml),
		"<< /Type /Filespec /F (factur-x.xml) /UF (factur-x.xml) /EF << /F 4 0 R >> >>",
	}
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
	offs := make([]int, len(objs))
	for i, o := range objs {
		offs[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	x := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, o := range offs {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n%% %s\n", len(objs)+1, x, tag)
	return b.Bytes()
}

// TestAttack_OrchFacturXFieldsCannotEscapeOutput drops Factur-X invoices
// whose number and seller name are traversal strings, device names,
// over-long names, bidi overrides and reserved folder names.
func TestAttack_OrchFacturXFieldsCannotEscapeOutput(t *testing.T) {
	t.Parallel()
	r := newAtkRig(t)
	long := strings.Repeat("A", 300)
	cases := []struct{ number, seller string }{
		{"../../.ssh/id_rsa", "Fournisseur Exemple"},
		{"FA-1", "../../.ssh"},
		{"..\\..\\..\\Windows\\win.ini", "..\\..\\evil"},
		{"/etc/passwd", "/etc"},
		{"CON", "CON"},
		{"AUX.txt", "nul"},
		{long, long},
		{"FA-2", "inbox"},
		{"FA-3", ".facto"},
		{"FA-4\u202egnp.exe", "\u202eFournisseur"},
		{"a&#x2F;..&#x2F;..&#x2F;b", "x&#x2F;..&#x2F;..&#x2F;y"},
		{"%2e%2e%2f%2e%2e%2fetc", "%2e%2e"},
		{"FA-5", strings.Repeat("../", 100)},
	}
	for i, c := range cases {
		atkPut(t, r.inboxDir, fmt.Sprintf("drop-%02d.pdf", i), atkPDF(atkCII(c.number, c.seller), fmt.Sprint(i)))
	}
	before := atkTree(t, r.outside)
	res := r.ingest(t)
	r.checkConfined(t, before, res)
	filed := 0
	for _, d := range res.Documents {
		if d.Status == orchestrator.StatusFiled {
			filed++
		}
	}
	// Every hostile invoice still has a usable seller or falls back, so most
	// are filed: the attack must have reached the destination to mean anything.
	if filed < len(cases)/2 {
		t.Errorf("only %d of %d hostile invoices filed: %s", filed, len(cases), statuses(res.Documents))
	}
	for _, d := range res.Documents {
		for _, bad := range []string{"..", ".ssh", "\\", "\u202e"} {
			if strings.Contains(d.Path, bad) {
				t.Errorf("filed path %q contains %q", d.Path, bad)
			}
		}
	}
}

// TestAttack_OrchHostileSubfolderNames creates provider subfolders whose
// names are refused by SafeName or Slug and checks their files stay put.
func TestAttack_OrchHostileSubfolderNames(t *testing.T) {
	t.Parallel()
	r := newAtkRig(t)
	names := []string{"...", "CON", "a\\..\\b", "edf ", " edf", "\u202eedf", "e\x01df", "edf:stream", "e?df", "-", "lpt1.txt"}
	for i, n := range names {
		atkPut(t, r.inboxDir, n+"/2026-03-14_edf_invoice_ref"+fmt.Sprint(i)+".pdf", []byte("synthetic "+fmt.Sprint(i)))
	}
	before := atkTree(t, r.outside)
	res := r.ingest(t)
	r.checkConfined(t, before, res)
	if len(res.Documents) != 0 {
		t.Errorf("files of refused subfolders were ingested: %+v", res.Documents)
	}
	for i, n := range names {
		p := filepath.Join(r.inboxDir, n, "2026-03-14_edf_invoice_ref"+fmt.Sprint(i)+".pdf")
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("file in refused subfolder %q is gone: %v", n, err)
		}
	}
	rep := orchestrator.Report{Warnings: res.Warnings}
	for _, line := range strings.Split(rep.Text(), "\n") {
		if strings.ContainsAny(line, "\x01\r\u202e") {
			t.Errorf("report line carries a raw control/bidi character: %q", line)
		}
	}
}

// TestAttack_OrchSymlinksFIFOsAndHugeFiles plants a symlink to a secret
// outside the output folder, a symlinked provider subfolder, a FIFO and a
// 2 GiB sparse file in the inbox. Nothing may be read, followed or block.
func TestAttack_OrchSymlinksFIFOsAndHugeFiles(t *testing.T) {
	t.Parallel()
	r := newAtkRig(t)
	secret := testsecrets.Canary(t, testsecrets.Session)
	atkPut(t, r.outside, "2026-03-14_edf_invoice_secret.pdf", []byte("session="+secret))
	if err := os.Symlink(filepath.Join(r.outside, "2026-03-14_edf_invoice_secret.pdf"),
		filepath.Join(r.inboxDir, "2026-03-14_edf_invoice_link.pdf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(r.outside, filepath.Join(r.inboxDir, "edf")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(r.inboxDir, "2026-03-15_edf_invoice_fifo.pdf"), 0o600); err != nil {
		t.Fatal(err)
	}
	atkPut(t, r.inboxDir, "2026-03-16_edf_invoice_huge.pdf", []byte("x"))
	if err := os.Truncate(filepath.Join(r.inboxDir, "2026-03-16_edf_invoice_huge.pdf"), 2<<30); err != nil {
		t.Fatal(err)
	}
	before := atkTree(t, r.outside)

	done := make(chan orchestrator.InboxResult, 1)
	go func() { done <- r.ingest(t) }()
	var res orchestrator.InboxResult
	select {
	case res = <-done:
	case <-time.After(45 * time.Second):
		t.Fatal("IngestInbox blocked (FIFO or huge file)")
	}
	r.checkConfined(t, before, res)
	if len(res.Documents) != 0 {
		t.Errorf("symlink/FIFO/huge file was ingested: %+v", res.Documents)
	}
	reasons := map[string]string{}
	for _, w := range res.Warnings {
		reasons[w.Path] = w.Reason
	}
	want := map[string]string{
		"2026-03-14_edf_invoice_link.pdf": string(inbox.ReasonNotRegular),
		"edf":                             string(inbox.ReasonNotRegular),
		"2026-03-15_edf_invoice_fifo.pdf": string(inbox.ReasonNotRegular),
		"2026-03-16_edf_invoice_huge.pdf": string(inbox.ReasonTooLarge),
	}
	for p, w := range want {
		if reasons[p] != w {
			t.Errorf("warning for %q = %q, want %q", p, reasons[p], w)
		}
	}
	art := testsecrets.ArtifactDir(t)
	if _, err := orchestrator.WriteReport(t.Context(), art, orchestrator.Report{Documents: res.Documents, Warnings: res.Warnings}); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	atkSave(t, art, "log.json", r.log.Bytes())
	for p, m := range atkTree(t, r.out) {
		if !m.IsRegular() || strings.HasPrefix(p, "inbox/") {
			continue
		}
		if b := mustRead(t, filepath.Join(r.out, p)); bytes.Contains(b, []byte(secret)) {
			t.Errorf("secret outside the inbox was copied into %q", p)
		}
	}
}

// atkSave writes data to dir/name through fsx.
func atkSave(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	root, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("fsx.Open: %v", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteAtomic(t.Context(), name, data); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// TestAttack_OrchNeverOverwritesOrEscapesThroughPlantedEntries plants a file
// at the exact target path, a dangling symlink at another target, and a
// year folder that is a symlink leading outside the output folder.
func TestAttack_OrchNeverOverwritesOrEscapesThroughPlantedEntries(t *testing.T) {
	t.Parallel()
	r := newAtkRig(t)
	// 1. Planted regular file at the target of a 2026 drop.
	target := "2026/energy/edf/2026-03-14_edf_invoice_planted.pdf"
	atkPut(t, r.out, target, []byte("planted by someone else"))
	atkPut(t, r.inboxDir, "2026-03-14_edf_invoice_planted.pdf", []byte("dropped"))
	// 2. Dangling symlink at a target, pointing outside.
	if err := os.Symlink(filepath.Join(r.outside, "created-through-link"),
		filepath.Join(r.out, "2026/energy/edf/2026-03-15_edf_invoice_dangling.pdf")); err != nil {
		t.Fatal(err)
	}
	atkPut(t, r.inboxDir, "2026-03-15_edf_invoice_dangling.pdf", []byte("dropped 2"))
	// 3. Year folder symlinked outside the output folder.
	if err := os.Symlink(r.outside, filepath.Join(r.out, "2027")); err != nil {
		t.Fatal(err)
	}
	atkPut(t, r.inboxDir, "2027-01-02_edf_invoice_escape.pdf", []byte("dropped 3"))
	// 4. Two drops rendering the same name in one run.
	atkPut(t, r.inboxDir, "2026-04-01_edf_invoice_same.pdf", []byte("first"))
	atkPut(t, r.inboxDir, "edf/2026-04-01_edf_invoice_same.pdf", []byte("second"))

	before := atkTree(t, r.outside)
	res := r.ingest(t)
	r.checkConfined(t, before, res, "2027", "2026/energy/edf/2026-03-15_edf_invoice_dangling.pdf")

	if got := string(mustRead(t, filepath.Join(r.out, target))); got != "planted by someone else" {
		t.Errorf("planted file overwritten: %q", got)
	}
	if _, err := os.Lstat(filepath.Join(r.outside, "created-through-link")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a dangling symlink was followed to create a file outside: %v", err)
	}
	for _, n := range []string{"2026-03-14_edf_invoice_planted.pdf", "2026-03-15_edf_invoice_dangling.pdf", "2027-01-02_edf_invoice_escape.pdf"} {
		if _, err := os.Lstat(filepath.Join(r.inboxDir, n)); err != nil {
			t.Errorf("inbox file %q removed although not filed: %v", n, err)
		}
	}
	got := map[string]bool{}
	for p, m := range atkTree(t, r.out) {
		if m.IsRegular() && strings.Contains(p, "2026-04-01_edf_invoice_same") {
			got[string(mustRead(t, filepath.Join(r.out, p)))] = true
		}
	}
	if !got["first"] || !got["second"] {
		t.Errorf("same-name drops lost one version: %v (%s)", got, statuses(res.Documents))
	}
}

// atkConn is a hostile connector driven by closures.
type atkConn struct {
	info  connector.Info
	login func(env connector.Env) (connector.Session, error)
	list  func() ([]connector.DocumentRef, error)
	fetch func(ref connector.DocumentRef) (io.ReadCloser, error)
}

func (c *atkConn) Info() connector.Info { return c.info }
func (c *atkConn) Login(_ context.Context, env connector.Env) (connector.Session, error) {
	if c.login == nil {
		return "session", nil
	}
	return c.login(env)
}

func (c *atkConn) List(context.Context, connector.Session, connector.Period) ([]connector.DocumentRef, error) {
	if c.list == nil {
		return nil, nil
	}
	return c.list()
}

func (c *atkConn) Fetch(_ context.Context, _ connector.Session, ref connector.DocumentRef) (io.ReadCloser, error) {
	return c.fetch(ref)
}

func atkInfo(id string) connector.Info {
	return connector.Info{ID: id, Name: "Synthetic", Category: "energy", Kinds: []connector.DocKind{connector.Invoice}, AllowedDomains: []string{"billing.fournisseur.test"}}
}

func atkRef(id string) connector.DocumentRef {
	return connector.DocumentRef{ProviderID: id, Kind: connector.Invoice, IssuedAt: time.Date(2026, 2, 3, 0, 0, 0, 0, time.UTC), MimeType: "application/pdf"}
}

// atkBody panics or not on Read and Close.
type atkBody struct {
	readPanic, closePanic any
	r                     io.Reader
}

func (b *atkBody) Read(p []byte) (int, error) {
	if b.readPanic != nil {
		panic(b.readPanic)
	}
	return b.r.Read(p)
}

func (b *atkBody) Close() error {
	if b.closePanic != nil {
		panic(b.closePanic)
	}
	return nil
}

type atkSecretHolderError struct {
	User   string
	Cookie string
	Req    *http.Request
}

func (h atkSecretHolderError) Error() string { return "holder " + h.Cookie }

// runAtk runs src on a fresh rig and returns the report and the log; both
// are written under ArtifactDir.
func runAtk(t *testing.T, conns ...connector.Connector) (orchestrator.RunResult, *atkRig) {
	t.Helper()
	r := newAtkRig(t)
	res, err := r.o.Run(t.Context(), connList(conns), connector.Year(2026))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	art := testsecrets.ArtifactDir(t)
	rep := orchestrator.Report{StartedAt: time.Date(2026, 3, 20, 9, 0, 0, 0, time.UTC), FinishedAt: time.Date(2026, 3, 20, 9, 1, 0, 0, time.UTC)}
	rep.AddRun(res)
	if _, err := orchestrator.WriteReport(t.Context(), art, rep); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	atkSave(t, art, "log.json", r.log.Bytes())
	return res, r
}

func atkNoCanary(t *testing.T, what string, data []byte, canaries ...string) {
	t.Helper()
	for _, c := range canaries {
		if bytes.Contains(data, []byte(c)) {
			t.Errorf("%s contains canary %s…", what, c[:20])
		}
	}
}

func atkReportBytes(t *testing.T, res orchestrator.RunResult) []byte {
	t.Helper()
	rep := orchestrator.Report{}
	rep.AddRun(res)
	js, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	return append(js, rep.Text()...)
}

// TestAttack_OrchConnectorPanicsAndErrorsNeverLeakCanaries makes connectors
// panic with, and fail with, values that hold canaries: strings, errors,
// structs embedding a request with a cookie, bodies panicking in Read and
// Close, and logs through Env.Log.
func TestAttack_OrchConnectorPanicsAndErrorsNeverLeakCanaries(t *testing.T) {
	t.Parallel()
	pw := testsecrets.Canary(t, testsecrets.Password)
	ck := testsecrets.Canary(t, testsecrets.Cookie)
	tok := testsecrets.Canary(t, testsecrets.Token)
	sess := testsecrets.Canary(t, testsecrets.Session)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://billing.fournisseur.test/x?token="+tok, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", "sid="+ck)
	holder := atkSecretHolderError{User: "synthetic", Cookie: ck, Req: req}
	pdfBody := func() io.Reader { return strings.NewReader("%PDF-1.7 synthetic") }

	conns := []connector.Connector{
		&atkConn{info: atkInfo("p-login-string"), login: func(connector.Env) (connector.Session, error) { panic("password=" + pw) }},
		&atkConn{info: atkInfo("p-list-error"), list: func() ([]connector.DocumentRef, error) {
			panic(fmt.Errorf("list %s: %w", sess, io.EOF))
		}},
		&atkConn{info: atkInfo("p-fetch-struct"), list: func() ([]connector.DocumentRef, error) {
			return []connector.DocumentRef{atkRef("r1")}, nil
		}, fetch: func(connector.DocumentRef) (io.ReadCloser, error) { panic(holder) }},
		&atkConn{info: atkInfo("p-read"), list: func() ([]connector.DocumentRef, error) {
			return []connector.DocumentRef{atkRef("r2")}, nil
		}, fetch: func(connector.DocumentRef) (io.ReadCloser, error) {
			return &atkBody{readPanic: req, closePanic: "close " + tok, r: pdfBody()}, nil
		}},
		&atkConn{info: atkInfo("p-close"), list: func() ([]connector.DocumentRef, error) {
			return []connector.DocumentRef{atkRef("r3")}, nil
		}, fetch: func(connector.DocumentRef) (io.ReadCloser, error) {
			return &atkBody{closePanic: &holder, r: pdfBody()}, nil
		}},
		&atkConn{info: atkInfo("e-login"), login: func(env connector.Env) (connector.Session, error) {
			env.Log.Info("trying login", "user", "synthetic", "note", "pw is "+pw, "req", req)
			return nil, fmt.Errorf("auth failed with %s: %w", pw, connector.ErrAuthFailed)
		}},
		&atkConn{info: atkInfo("e-list"), list: func() ([]connector.DocumentRef, error) {
			return nil, fmt.Errorf("GET https://u:%s@billing.fournisseur.test/list?sid=%s: %w", pw, sess, holder)
		}},
		&atkConn{info: atkInfo("e-fetch"), list: func() ([]connector.DocumentRef, error) {
			return []connector.DocumentRef{atkRef("r4"), atkRef("r5")}, nil
		}, fetch: func(ref connector.DocumentRef) (io.ReadCloser, error) {
			if ref.ProviderID == "r4" {
				return nil, fmt.Errorf("download with cookie %s failed", ck)
			}
			return nil, fmt.Errorf("session %s expired: %w", sess, connector.ErrNeedsLogin)
		}},
		&atkConn{info: atkInfo("e-read"), list: func() ([]connector.DocumentRef, error) {
			return []connector.DocumentRef{atkRef("r6")}, nil
		}, fetch: func(connector.DocumentRef) (io.ReadCloser, error) {
			return io.NopCloser(&errReader{err: fmt.Errorf("stream reset, token %s", tok)}), nil
		}},
	}
	res, r := runAtk(t, conns...)
	for _, c := range res.Connectors {
		if c.State == orchestrator.StateOK && c.ID != "e-read" { // a read error only fails its document
			t.Errorf("connector %s reported ok", c.ID)
		}
	}
	atkNoCanary(t, "log", r.log.Bytes(), pw, ck, tok, sess)
	atkNoCanary(t, "report", atkReportBytes(t, res), pw, ck, tok, sess)
}
