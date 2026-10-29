// Tests for fsx.SafeName and fsx.JoinWithin (J0 task T8). Core fsx tests live
// in fsx_test.go (helpers checkErr and errAny come from there).
//
// Expected API (implementer: follow exactly):
//
//	// MaxNameLen is the maximum length, in bytes, of a SafeName result. It
//	// leaves room under the 255-byte NAME_MAX for the WriteAtomic temp prefix
//	// and a "_vN" version suffix.
//	const MaxNameLen = 200
//
//	// SafeName turns any string (supplier-provided invoice number, seller name,
//	// inbox file name, test name…) into ONE path component that is safe on
//	// Linux, macOS and Windows. It never fails and never returns "", "." or "..".
//	// Steps, in order:
//	//  1. every rune that is invalid UTF-8, NUL, a C0/C1 control or DEL,
//	//     a Unicode format character (unicode.Cf: bidi overrides, zero-width…),
//	//     a separator ('/' or '\\') or a Windows-forbidden character
//	//     (< > : " | ? *) is replaced by '_';
//	//  2. runs of dots are collapsed to one dot (so ".." never appears);
//	//  3. leading and trailing dots and spaces are trimmed (no hidden files, no
//	//     Windows trailing dot/space);
//	//  4. if the stem (text before the first dot), compared case-insensitively,
//	//     is a Windows reserved device name (CON, PRN, AUX, NUL, COM1–COM9,
//	//     LPT1–LPT9) the result is prefixed with '_';
//	//  5. the result is truncated to at most MaxNameLen bytes on a rune
//	//     boundary, keeping the extension (from the last dot, up to 10 bytes)
//	//     when there is one, then steps 2 and 3 are applied again;
//	//  6. an empty result becomes "_".
//	// SafeName is idempotent: SafeName(SafeName(s)) == SafeName(s). Other
//	// Unicode (accents, CJK) is kept as is: transliteration is normalize's job.
//	func SafeName(s string) string
//
//	// JoinWithin joins slash-separated relative parts under root and returns
//	// the cleaned OS path (filepath.Join semantics). It is lexical only (symlinks
//	// are handled by Root/os.Root). It fails with ErrInvalidName when root is
//	// empty, a part is empty, absolute or contains NUL, or the result is not
//	// strictly inside root (equal to root, or escaping it through "..").
//	// Parts may contain several segments ("2026/housing") and inner ".." that
//	// stays inside root ("a/../b").
//	func JoinWithin(root string, parts ...string) (string, error)
package fsx_test

import (
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/FlorianRuen/facto/internal/fsx"
)

// windowsReserved is the set of device names Windows refuses as a file stem.
var windowsReserved = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// checkSafeName asserts every invariant a SafeName result must hold, whatever
// the input. Shared by the table test and the fuzz target.
func checkSafeName(t *testing.T, in, got string) {
	t.Helper()
	switch got {
	case "", ".", "..":
		t.Fatalf("SafeName(%q) = %q: empty or dot name", in, got)
	}
	if strings.Contains(got, "..") {
		t.Fatalf("SafeName(%q) = %q: contains \"..\"", in, got)
	}
	if strings.ContainsAny(got, "/\\\x00") {
		t.Fatalf("SafeName(%q) = %q: contains a separator or NUL", in, got)
	}
	if strings.ContainsAny(got, `<>:"|?*`) {
		t.Fatalf("SafeName(%q) = %q: contains a Windows-forbidden character", in, got)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("SafeName(%q) = %q: invalid UTF-8", in, got)
	}
	for _, r := range got {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			t.Fatalf("SafeName(%q) = %q: contains control/format rune %U", in, got, r)
		}
	}
	if len(got) > fsx.MaxNameLen {
		t.Fatalf("SafeName(%q): len = %d, want <= %d", in, len(got), fsx.MaxNameLen)
	}
	if strings.HasPrefix(got, ".") || strings.HasPrefix(got, " ") {
		t.Fatalf("SafeName(%q) = %q: leading dot or space", in, got)
	}
	if strings.HasSuffix(got, ".") || strings.HasSuffix(got, " ") {
		t.Fatalf("SafeName(%q) = %q: trailing dot or space", in, got)
	}
	stem, _, _ := strings.Cut(got, ".")
	if windowsReserved[strings.ToUpper(stem)] {
		t.Fatalf("SafeName(%q) = %q: Windows reserved device name", in, got)
	}
	if !filepath.IsLocal(got) || filepath.Base(got) != got {
		t.Fatalf("SafeName(%q) = %q: not a single local path component", in, got)
	}
	if again := fsx.SafeName(got); again != got {
		t.Fatalf("SafeName not idempotent: SafeName(%q) = %q, SafeName(that) = %q", in, got, again)
	}
}

// safeNameCases is shared with the fuzz seed corpus.
var safeNameCases = []struct {
	name string
	in   string
	want string // "" = check invariants only
}{
	// Benign names are untouched.
	{name: "plain pdf", in: "invoice.pdf", want: "invoice.pdf"},
	{name: "spec name", in: "2026-03-14_edf_invoice_84-12EUR_10234567.pdf", want: "2026-03-14_edf_invoice_84-12EUR_10234567.pdf"},
	{name: "accents kept", in: "facture-électricité.pdf", want: "facture-électricité.pdf"},
	{name: "cjk kept", in: "請求書.pdf", want: "請求書.pdf"},
	{name: "inner space kept", in: "Fournisseur Exemple SAS", want: "Fournisseur Exemple SAS"},

	// Traversal and separators.
	{name: "traversal to ssh key", in: "../../.ssh/id_rsa", want: "_._.ssh_id_rsa"},
	{name: "slash", in: "a/b", want: "a_b"},
	{name: "backslash", in: `a\b`, want: "a_b"},
	{name: "windows traversal", in: `..\..\Windows\win.ini`, want: "_._Windows_win.ini"},
	{name: "absolute path", in: "/etc/passwd", want: "_etc_passwd"},
	{name: "dotdot", in: "..", want: "_"},
	{name: "dot", in: ".", want: "_"},
	{name: "empty", in: "", want: "_"},
	{name: "only dots and spaces", in: ". . .", want: "_"},
	{name: "dot runs collapsed", in: "invoice..pdf", want: "invoice.pdf"},
	{name: "many dots", in: "a....b", want: "a.b"},
	{name: "hidden file", in: ".bashrc", want: "bashrc"},

	// NUL, control, format characters.
	{name: "NUL alone", in: "\x00", want: "_"},
	{name: "NUL inside", in: "a\x00b", want: "a_b"},
	{name: "NUL extension truncation trick", in: "invoice.pdf\x00.exe", want: "invoice.pdf_.exe"},
	{name: "tab", in: "tab\there", want: "tab_here"},
	{name: "newline", in: "line\nbreak", want: "line_break"},
	{name: "DEL", in: "a\x7fb", want: "a_b"},
	{name: "C1 control", in: "a\u0085b", want: "a_b"},
	{name: "bidi override spoofs extension", in: "invoice\u202Efdp.exe", want: "invoice_fdp.exe"},
	{name: "zero width space", in: "a\u200Bb", want: "a_b"},
	{name: "invalid utf8", in: "\xff\xfe.pdf", want: "__.pdf"},

	// Windows-forbidden characters and trailing dot/space.
	{name: "windows forbidden chars", in: `a<b>c:d"e|f?g*h`, want: "a_b_c_d_e_f_g_h"},
	{name: "drive letter", in: `C:\Users`, want: "C__Users"},
	{name: "trailing dot", in: "name.", want: "name"},
	{name: "trailing space", in: "name ", want: "name"},
	{name: "trailing dot and space", in: "name. ", want: "name"},
	{name: "leading spaces", in: "  name", want: "name"},

	// Windows reserved device names.
	{name: "CON", in: "CON", want: "_CON"},
	{name: "con lowercase with extension", in: "con.txt", want: "_con.txt"},
	{name: "Nul mixed case", in: "Nul", want: "_Nul"},
	{name: "LPT9 with extension", in: "LPT9.pdf", want: "_LPT9.pdf"},
	{name: "COM1", in: "COM1", want: "_COM1"},
	{name: "aux double extension", in: "aux.tar.gz", want: "_aux.tar.gz"},
	{name: "reserved after trim", in: " CON ", want: "_CON"},
	{name: "COM10 not reserved", in: "COM10", want: "COM10"},
	{name: "CONSOLE not reserved", in: "CONSOLE", want: "CONSOLE"},
	{name: "xCON not reserved", in: "xCON", want: "xCON"},
	{name: "CON space before extension", in: "CON .pdf", want: "_CON .pdf"},
	{name: "nul spaces before extension", in: "nul  .txt", want: "_nul  .txt"},
	{name: "COM superscript one", in: "COM\u00b9", want: "_COM\u00b9"},
	{name: "COM superscript two with extension", in: "com\u00b2.pdf", want: "_com\u00b2.pdf"},
	{name: "COM superscript three", in: "COM\u00b3", want: "_COM\u00b3"},
	{name: "LPT superscript one", in: "LPT\u00b9.txt", want: "_LPT\u00b9.txt"},
	{name: "LPT superscript two", in: "lpt\u00b2", want: "_lpt\u00b2"},
	{name: "LPT superscript three", in: "LPT\u00b3", want: "_LPT\u00b3"},
	{name: "CONIN$", in: "CONIN$", want: "_CONIN$"},
	{name: "conout$ with extension", in: "conout$.log", want: "_conout$.log"},
	{name: "COM0", in: "COM0", want: "_COM0"},
	{name: "LPT0 with extension", in: "lpt0.pdf", want: "_lpt0.pdf"},
	{name: "COM superscript four not reserved", in: "COM\u2074", want: "COM\u2074"},
	{name: "CONIN not reserved", in: "CONIN", want: "CONIN"},
	{name: "truncation exposes reserved stem", in: "CON" + strings.Repeat(" ", 250) + "x", want: "_CON"},

	// Length cap.
	{name: "300 chars", in: strings.Repeat("a", 300), want: strings.Repeat("a", fsx.MaxNameLen)},
	{name: "300 chars keeps extension", in: strings.Repeat("a", 300) + ".pdf", want: strings.Repeat("a", fsx.MaxNameLen-4) + ".pdf"},
	{name: "300 two-byte runes", in: strings.Repeat("é", 300)},
	{name: "300 four-byte runes with extension", in: strings.Repeat("😀", 300) + ".pdf"},
	{name: "truncation lands before a dot", in: strings.Repeat("a", fsx.MaxNameLen-1) + ". tail"},
	{name: "long traversal", in: strings.Repeat("../", 200) + "x"},
}

func TestSafeName(t *testing.T) {
	t.Parallel()

	for _, tt := range safeNameCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := fsx.SafeName(tt.in)
			if tt.want != "" && got != tt.want {
				t.Errorf("SafeName(%q) = %q, want %q", tt.in, got, tt.want)
			}
			checkSafeName(t, tt.in, got)
		})
	}
}

func TestSafeName_LongMultibyteStaysValidAndFull(t *testing.T) {
	t.Parallel()

	got := fsx.SafeName(strings.Repeat("é", 300))
	// 2-byte runes: truncation on a rune boundary loses at most 1 byte.
	if len(got) < fsx.MaxNameLen-1 {
		t.Fatalf("len = %d, want >= %d (truncated too aggressively)", len(got), fsx.MaxNameLen-1)
	}
	if strings.Trim(got, "é") != "" {
		t.Fatalf("SafeName altered valid runes: %q", got)
	}

	got = fsx.SafeName(strings.Repeat("😀", 300) + ".pdf")
	if !strings.HasSuffix(got, ".pdf") {
		t.Fatalf("SafeName dropped the extension: %q", got)
	}
}

func FuzzSafeName_NeverContainsSeparatorOrDotDot(f *testing.F) {
	for _, tt := range safeNameCases {
		f.Add(tt.in)
	}
	for _, s := range []string{
		"....//....//", `..\/..\/`, "\u202E..", " . .. . ", "COM1 .pdf",
		"a\x00/../b", "\xc0\xae\xc0\xae/", "．．／", "%2e%2e%2f", "~/.ssh",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		checkSafeName(t, s, fsx.SafeName(s))
	})
}

func TestJoinWithin(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	tests := []struct {
		name  string
		parts []string
		want  string // joined under root with filepath.Join
	}{
		{name: "single file", parts: []string{"a.pdf"}, want: "a.pdf"},
		{name: "year category provider file", parts: []string{"2026", "housing", "edf", "2026-03-14_edf_invoice.pdf"}, want: "2026/housing/edf/2026-03-14_edf_invoice.pdf"},
		{name: "multi-segment part", parts: []string{"2026/housing", "a.pdf"}, want: "2026/housing/a.pdf"},
		{name: "inner dotdot staying inside", parts: []string{"a/../b"}, want: "b"},
		{name: "dotdot across parts staying inside", parts: []string{"a", "../b"}, want: "b"},
		{name: "redundant separators", parts: []string{"a//b/./c"}, want: "a/b/c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := fsx.JoinWithin(root, tt.parts...)
			if err != nil {
				t.Fatalf("JoinWithin(%q, %q): %v", root, tt.parts, err)
			}
			want := filepath.Join(root, filepath.FromSlash(tt.want))
			if got != want {
				t.Fatalf("JoinWithin(%q, %q) = %q, want %q", root, tt.parts, got, want)
			}
		})
	}
}

func TestJoinWithin_RejectsEscape(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "out")
	tests := []struct {
		name  string
		root  string
		parts []string
	}{
		{name: "parent", root: root, parts: []string{".."}},
		{name: "parent then file", root: root, parts: []string{"../x"}},
		{name: "sibling with shared prefix", root: root, parts: []string{"../out-evil/x"}},
		{name: "deep escape", root: root, parts: []string{"a/../../x"}},
		{name: "escape across parts", root: root, parts: []string{"a", "..", "..", "x"}},
		{name: "ssh key", root: root, parts: []string{"../../.ssh/id_rsa"}},
		{name: "absolute part", root: root, parts: []string{"/etc/passwd"}},
		{name: "absolute later part", root: root, parts: []string{"2026", "/etc/passwd"}},
		{name: "NUL in part", root: root, parts: []string{"a\x00b"}},
		{name: "empty part", root: root, parts: []string{"2026", "", "a.pdf"}},
		{name: "no parts is the root itself", root: root, parts: nil},
		{name: "dot is the root itself", root: root, parts: []string{"."}},
		{name: "back to root", root: root, parts: []string{"a", ".."}},
		{name: "empty root", root: "", parts: []string{"a.pdf"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := fsx.JoinWithin(tt.root, tt.parts...)
			checkErr(t, "JoinWithin", err, fsx.ErrInvalidName)
			if got != "" {
				t.Fatalf("JoinWithin(%q, %q) = %q on error, want \"\"", tt.root, tt.parts, got)
			}
		})
	}
}

// TestJoinWithin_SafeNamePartsNeverEscape ties both guards together: any
// supplier string passed through SafeName is a valid JoinWithin part.
func TestJoinWithin_SafeNamePartsNeverEscape(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	for _, tt := range safeNameCases {
		got, err := fsx.JoinWithin(root, "2026", fsx.SafeName(tt.in))
		if err != nil {
			t.Fatalf("JoinWithin(root, 2026, SafeName(%q)): %v", tt.in, err)
		}
		if filepath.Dir(got) != filepath.Join(root, "2026") {
			t.Fatalf("SafeName(%q) produced %q outside root/2026", tt.in, got)
		}
	}
}
