package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/logx"
)

// Status is the outcome of one document.
type Status string

// Document statuses.
const (
	StatusFiled            Status = "filed"             // Put and Insert succeeded (any version)
	StatusNotDurable       Status = "not-durable"       // published and indexed, directory fsync failed; inbox file kept
	StatusSkippedDuplicate Status = "skipped-duplicate" // dedup rule 2 (same SHA-256)
	StatusSkippedKnownID   Status = "skipped-known-id"  // dedup rule 1 (set by the connector loop)
	StatusExists           Status = "exists"            // destination already had a file at the path (dest.ErrExists)
	StatusTooLarge         Status = "too-large"         // over MaxSize
	StatusInvalid          Status = "invalid"           // metadata cannot be named or indexed
	StatusChanged          Status = "changed"           // inbox file changed since scan (inbox.ErrChanged)
	StatusFailed           Status = "failed"            // any other error (details only in the redacted log)
)

// DocResult is one report line. It never carries error text.
type DocResult struct {
	Source     string // "inbox" or the connector id
	Origin     string // inbox item path, "" for connectors
	Provider   string // index provider (slug)
	ProviderID string
	Status     Status
	Version    int    // decided version; 0 when skipped or failed before dedup
	Path       string // relative path filed at (filed, not-durable) or clashing with (exists); "" otherwise
}

// Warning is a file the run left in place, with the reason why.
type Warning struct {
	Source string // "inbox"
	Path   string
	Reason string // inbox.Reason value, or ReasonNotRemoved
}

// ConnectorStatus is one connector line of the report.
type ConnectorStatus struct {
	ID    string
	State State
}

// Report is the outcome of one run.
type Report struct {
	StartedAt, FinishedAt time.Time
	Connectors            []ConnectorStatus // empty = not rendered (pre-T24 format)
	Documents             []DocResult
	Warnings              []Warning
}

// AddRun appends one ConnectorStatus per res.Connectors entry, in order, and
// their Documents after the existing ones.
func (r *Report) AddRun(res RunResult) {
	for _, c := range res.Connectors {
		r.Connectors = append(r.Connectors, ConnectorStatus{ID: c.ID, State: c.State})
		r.Documents = append(r.Documents, c.Documents...)
	}
}

// cleaned returns d with the supplier- or file-provided strings (Origin,
// ProviderID, Path) passed through logx.Clean: a report never carries a
// token, a URL query or userinfo, even from a source the connector loop does
// not validate.
func (d DocResult) cleaned() DocResult {
	d.Origin = logx.Clean(d.Origin)
	d.ProviderID = logx.Clean(d.ProviderID)
	d.Path = logx.Clean(d.Path)
	return d
}

// reportVersion is the JSON report format version.
const reportVersion = 1

type jsonReport struct {
	ReportVersion int            `json:"report_version"`
	StartedAt     string         `json:"started_at"`
	FinishedAt    string         `json:"finished_at"`
	Connectors    []jsonConn     `json:"connectors,omitempty"`
	Counts        map[Status]int `json:"counts"`
	Documents     []jsonDoc      `json:"documents"`
	Warnings      []jsonWarning  `json:"warnings"`
}

type jsonConn struct {
	ID    string `json:"id"`
	State State  `json:"state"`
}

type jsonDoc struct {
	Source     string `json:"source"`
	Origin     string `json:"origin,omitempty"`
	Provider   string `json:"provider,omitempty"`
	ProviderID string `json:"provider_id,omitempty"`
	Status     Status `json:"status"`
	Version    int    `json:"version,omitempty"`
	Path       string `json:"path,omitempty"`
}

type jsonWarning struct {
	Source string `json:"source"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// counts returns the number of documents per status (non-zero only).
func (r Report) counts() map[Status]int {
	c := map[Status]int{}
	for _, d := range r.Documents {
		c[d.Status]++
	}
	return c
}

// JSON renders the report: 2-space indent, times in UTC RFC 3339, "counts"
// holds only non-zero statuses, empty lists are [], trailing newline.
// Origin, ProviderID and paths go through logx.Clean.
func (r Report) JSON() ([]byte, error) {
	out := jsonReport{
		ReportVersion: reportVersion,
		StartedAt:     r.StartedAt.UTC().Format(time.RFC3339),
		FinishedAt:    r.FinishedAt.UTC().Format(time.RFC3339),
		Counts:        r.counts(),
		Documents:     make([]jsonDoc, 0, len(r.Documents)),
		Warnings:      make([]jsonWarning, 0, len(r.Warnings)),
	}
	for _, c := range r.Connectors {
		out.Connectors = append(out.Connectors, jsonConn(c))
	}
	for _, d := range r.Documents {
		out.Documents = append(out.Documents, jsonDoc(d.cleaned()))
	}
	for _, w := range r.Warnings {
		w.Path = logx.Clean(w.Path)
		out.Warnings = append(out.Warnings, jsonWarning(w))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return nil, fmt.Errorf("report json: %w", err)
	}
	return buf.Bytes(), nil
}

// Text renders the human summary: one line per document and per warning, no
// control or format character other than the '\n' line ends (untrusted file
// names are escaped). Origin, ProviderID and paths go through logx.Clean
// first.
func (r Report) Text() string {
	var b strings.Builder
	b.WriteString("facto report\n")
	b.WriteString("started: " + r.StartedAt.UTC().Format(time.RFC3339) + "\n")
	b.WriteString("finished: " + r.FinishedAt.UTC().Format(time.RFC3339) + "\n")

	counts := r.counts()
	if len(counts) == 0 {
		b.WriteString("summary: no documents\n")
	} else {
		statuses := make([]Status, 0, len(counts))
		for s := range counts {
			statuses = append(statuses, s)
		}
		slices.Sort(statuses)
		parts := make([]string, 0, len(statuses))
		for _, s := range statuses {
			parts = append(parts, escape(string(s))+" "+strconv.Itoa(counts[s]))
		}
		b.WriteString("summary: " + strings.Join(parts, ", ") + "\n")
	}
	b.WriteString("warnings: " + strconv.Itoa(len(r.Warnings)) + "\n")

	if len(r.Connectors) > 0 {
		b.WriteString("\nconnectors:\n")
		for _, c := range r.Connectors {
			b.WriteString("- " + escapeJoin([]string{string(c.State), c.ID}) + "\n")
		}
	}
	if len(r.Documents) > 0 {
		b.WriteString("\ndocuments:\n")
		for _, d := range r.Documents {
			d = d.cleaned()
			fields := []string{string(d.Status), d.Source}
			switch {
			case d.Origin != "":
				fields = append(fields, d.Origin)
			case d.ProviderID != "":
				fields = append(fields, d.ProviderID)
			}
			line := "- " + escapeJoin(fields)
			if d.Path != "" {
				line += " -> " + escape(d.Path)
			}
			b.WriteString(line + "\n")
		}
	}
	if len(r.Warnings) > 0 {
		b.WriteString("\nwarnings:\n")
		for _, w := range r.Warnings {
			b.WriteString("- " + escapeJoin([]string{w.Reason, w.Source, logx.Clean(w.Path)}) + "\n")
		}
	}
	return b.String()
}

func escapeJoin(fields []string) string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = escape(f)
	}
	return strings.Join(out, " ")
}

// escape makes an untrusted string safe on one terminal line: every rune
// that is not printable (controls, format characters such as bidi
// overrides, line and paragraph separators, non-ASCII spaces), every
// invalid byte, U+FFFD and the backslash itself are written as Go-style
// escapes.
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\\':
			b.WriteString(`\\`)
		case r == utf8.RuneError || !unicode.IsPrint(r):
			if r > 0xFFFF {
				fmt.Fprintf(&b, `\U%08x`, r)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// ReportsDir is the report directory inside the state dir.
const ReportsDir = "reports"

// reportStamp names report files after the run start.
const reportStamp = "20060102T150405Z"

// maxReportSuffix bounds the "-<n>" suffixes tried when reports of the same
// second already exist.
const maxReportSuffix = 99

// ReportFiles are the absolute paths WriteReport wrote.
type ReportFiles struct{ JSON, Text string }

// WriteReport writes r.JSON() and r.Text() through fsx (0600, never
// replacing anything) to <stateDir>/reports/<StartedAt UTC as
// 20060102T150405Z>.json and .txt, creating reports/ 0700. When reports of
// the same second exist, "-1", "-2"… is appended to the name. stateDir must
// exist (fs.ErrNotExist); an existing reports dir with group/world bits is
// refused (fsx.ErrInsecurePerms) and nothing is written; nothing is ever
// written outside stateDir. On fsx.ErrNotDurable the files are returned with
// the error.
func WriteReport(ctx context.Context, stateDir string, r Report) (ReportFiles, error) {
	if err := ctx.Err(); err != nil {
		return ReportFiles{}, fmt.Errorf("write report: %w", err)
	}
	js, err := r.JSON()
	if err != nil {
		return ReportFiles{}, fmt.Errorf("write report: %w", err)
	}
	text := []byte(r.Text())

	root, err := fsx.Open(stateDir)
	if err != nil {
		return ReportFiles{}, fmt.Errorf("write report: %w", err)
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirPrivate(ReportsDir); err != nil {
		return ReportFiles{}, fmt.Errorf("write report: %w", err)
	}
	dir, err := root.OpenDir(ReportsDir)
	if err != nil {
		return ReportFiles{}, fmt.Errorf("write report: %w", err)
	}
	defer func() { _ = dir.Close() }()

	stamp := r.StartedAt.UTC().Format(reportStamp)
	for n := 0; n <= maxReportSuffix; n++ {
		base := stamp
		if n > 0 {
			base += "-" + strconv.Itoa(n)
		}
		files := ReportFiles{
			JSON: filepath.Join(stateDir, ReportsDir, base+".json"),
			Text: filepath.Join(stateDir, ReportsDir, base+".txt"),
		}
		err := writePair(ctx, dir, base, js, text)
		switch {
		case err == nil:
			return files, nil
		case errors.Is(err, fs.ErrExist):
			continue
		case errors.Is(err, fsx.ErrNotDurable):
			return files, fmt.Errorf("write report: %w", err)
		default:
			return ReportFiles{}, fmt.Errorf("write report: %w", err)
		}
	}
	return ReportFiles{}, fmt.Errorf("write report: %s: %w", stamp, fs.ErrExist)
}

// writePair writes base.json then base.txt, never replacing either. When the
// text file cannot be written the new JSON file is removed again, so a pair
// is always written under one name.
func writePair(ctx context.Context, dir *fsx.Root, base string, js, text []byte) error {
	var notDurable error
	if err := dir.WriteNew(ctx, base+".json", bytes.NewReader(js)); err != nil {
		if !errors.Is(err, fsx.ErrNotDurable) {
			return fmt.Errorf("json: %w", err)
		}
		notDurable = fmt.Errorf("json: %w", err)
	}
	if err := dir.WriteNew(ctx, base+".txt", bytes.NewReader(text)); err != nil {
		if !errors.Is(err, fsx.ErrNotDurable) {
			// Never leave a JSON report without its summary.
			if rmErr := dir.Remove(base + ".json"); rmErr != nil {
				return fmt.Errorf("remove unpaired json after text failure: %w", rmErr)
			}
		}
		return fmt.Errorf("text: %w", err)
	}
	return notDurable
}
