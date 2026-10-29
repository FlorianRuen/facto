package facturx_test

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"strings"
	"testing"
)

// synthAttachment is one embedded file of a synthetic PDF.
type synthAttachment struct {
	key   string // EmbeddedFiles name-tree key; "" = fileName
	file  string // /F and /UF of the file specification ("" = omitted)
	desc  string // /Desc ("" = omitted)
	data  []byte
	flate bool // store data FlateDecode-compressed
}

// buildPDF writes a minimal, valid, uncompressed one-page PDF 1.7 by hand, with
// correct xref offsets, embedding atts in the catalog's EmbeddedFiles name
// tree (and /AF, as Factur-X does). Everything in it is synthetic. Names must
// not contain '(', ')' or '\'.
func buildPDF(t testing.TB, atts ...synthAttachment) []byte {
	t.Helper()

	var objs []string // objs[i] is the body of object i+1
	add := func(body string) int {
		objs = append(objs, body)
		return len(objs)
	}
	catalog := add("") // filled in last
	pages := add("")
	page := add(fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 595 842] >>", pages))
	objs[pages-1] = fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", page)

	var names, af []string
	for _, a := range atts {
		data := a.data
		filter := ""
		if a.flate {
			var z bytes.Buffer
			zw := zlib.NewWriter(&z)
			if _, err := zw.Write(a.data); err != nil {
				t.Fatalf("zlib: %v", err)
			}
			if err := zw.Close(); err != nil {
				t.Fatalf("zlib: %v", err)
			}
			data = z.Bytes()
			filter = " /Filter /FlateDecode"
		}
		stream := add(fmt.Sprintf("<< /Type /EmbeddedFile /Subtype /text#2Fxml /Length %d%s >>\nstream\n%s\nendstream",
			len(data), filter, data))
		spec := "<< /Type /Filespec"
		if a.file != "" {
			spec += fmt.Sprintf(" /F (%s) /UF (%s)", a.file, a.file)
		}
		if a.desc != "" {
			spec += fmt.Sprintf(" /Desc (%s)", a.desc)
		}
		spec += fmt.Sprintf(" /AFRelationship /Data /EF << /F %d 0 R /UF %d 0 R >> >>", stream, stream)
		fs := add(spec)
		key := a.key
		if key == "" {
			key = a.file
		}
		names = append(names, fmt.Sprintf("(%s) %d 0 R", key, fs))
		af = append(af, fmt.Sprintf("%d 0 R", fs))
	}
	cat := fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R", pages)
	if len(atts) > 0 {
		// Name-tree keys must be sorted; callers pass them in the order they
		// want to test, so sort here.
		sortNames(names)
		cat += fmt.Sprintf(" /Names << /EmbeddedFiles << /Names [%s] >> >> /AF [%s]",
			strings.Join(names, " "), strings.Join(af, " "))
	}
	objs[catalog-1] = cat + " >>"

	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n% synthetic facto test fixture\n")
	offsets := make([]int, len(objs))
	for i, body := range objs {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, catalog, xref)
	return b.Bytes()
}

// sortNames sorts "(key) N 0 R" entries by key (insertion sort, tiny inputs).
func sortNames(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
