package normalize_test

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/fsx"
	"github.com/FlorianRuen/facto/internal/normalize"
)

// fileRE: rendered names only ever use these bytes (uppercase only for the
// currency code).
var fileRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// FuzzRender_StaysInsideDir: whatever a supplier (or an inbox file) puts in
// the fields, the rendered path is a well-formed relative path strictly
// inside the output root, with one safe file component.
func FuzzRender_StaysInsideDir(f *testing.F) {
	f.Add("../../.ssh", "a/b", "housing", "pdf", "EUR", int64(8412), true, int64(1773446400), 1, 2, false)
	f.Add("edf", "10234567", "housing", "pdf", "EUR", int64(8412), true, int64(1773446400), 1, 1, false)
	f.Add("a\x00b", "\x00", "\x00", "\x00", "\x00", int64(0), false, int64(0), 2, 0, true)
	f.Add("..", "..", "..", "..", "..", int64(-1), true, int64(-62135596800), 3, 7, false)
	f.Add("CON", "nul.txt", "aux", "exe", "eur", int64(1), true, int64(253402300799), 4, 3, true)
	f.Add(`..\..\windows`, "/etc/passwd", "/", "/../sh", "€", int64(-9223372036854775808), true, int64(1), 5, 100, false)
	f.Add(strings.Repeat("é", 300), strings.Repeat("x_", 300), strings.Repeat("c", 300), strings.Repeat("p", 300), "EUR", int64(9223372036854775807), true, int64(1773446400), 0, 99999, true)
	f.Add("\u202egnp.exe", "a\xffb", "東京", ".", "", int64(5), true, int64(1773446400), 1, 2, false)

	root := filepath.Join("out", "root")
	f.Fuzz(func(t *testing.T, provider, ref, category, ext, currency string, amount int64, hasAmount bool, unix int64, kind, version int, french bool) {
		lang := "en"
		if french {
			lang = "fr"
		}
		n, err := normalize.NewNamer(normalize.Config{Language: lang})
		if err != nil {
			t.Fatalf("NewNamer: %v", err)
		}
		d := normalize.Doc{
			Provider: provider, Category: category, Ref: ref, Ext: ext, Currency: currency,
			Kind: connector.DocKind(kind), Date: time.Unix(unix, 0), Version: version,
		}
		if hasAmount {
			d.AmountCents = &amount
		}
		p, err := n.Render(d)
		if err != nil {
			if !errors.Is(err, normalize.ErrInvalidDoc) {
				t.Fatalf("Render error wraps no sentinel: %v", err)
			}
			if p != (normalize.Path{}) {
				t.Fatalf("Render returned %+v alongside %v", p, err)
			}
			return
		}

		if p.File == "" || len(p.File) > fsx.MaxNameLen {
			t.Fatalf("File %q: length %d outside (0, %d]", p.File, len(p.File), fsx.MaxNameLen)
		}
		if fsx.SafeName(p.File) != p.File || !fileRE.MatchString(p.File) || strings.HasPrefix(p.File, ".") {
			t.Fatalf("File %q is not a safe single component", p.File)
		}
		if p.Dir == "" {
			t.Fatalf("default dir template rendered an empty Dir for %+v", d)
		}
		for _, seg := range strings.Split(p.Dir, "/") {
			if seg == "" || seg == "." || seg == ".." || fsx.SafeName(seg) != seg || !fileRE.MatchString(seg) {
				t.Fatalf("Dir %q has unsafe segment %q", p.Dir, seg)
			}
		}
		full, err := fsx.JoinWithin(root, p.Dir, p.File)
		if err != nil {
			t.Fatalf("JoinWithin(%q, %q, %q): %v", root, p.Dir, p.File, err)
		}
		rel, err := filepath.Rel(root, full)
		if err != nil || !filepath.IsLocal(rel) || filepath.ToSlash(rel) != p.Rel() {
			t.Fatalf("path %q escapes %q or differs from Rel() %q", full, root, p.Rel())
		}
	})
}
