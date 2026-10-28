package facturx_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/normalize/facturx"
)

// FuzzParseCII: arbitrary input never panics, every error wraps a package
// sentinel, and no data is returned alongside an error.
func FuzzParseCII(f *testing.F) {
	for _, tc := range []string{"minimum", "basic", "en16931"} {
		f.Add(string(readTestdataF(f, filepath.Join("testdata", "TestParseCII_ProfilesGolden", tc+".xml"))))
	}
	f.Add(full())
	f.Add(`<!DOCTYPE x [<!ENTITY a "b">]><x/>`)
	f.Add("")
	f.Fuzz(func(t *testing.T, doc string) {
		inv, err := facturx.ParseCII(strings.NewReader(doc))
		if err == nil {
			return
		}
		for _, s := range []error{facturx.ErrTooLarge, facturx.ErrUnsafeXML, facturx.ErrNotCII, facturx.ErrInvalid} {
			if errors.Is(err, s) {
				if inv != (facturx.Invoice{}) {
					t.Fatalf("data returned alongside %v: %+v", err, inv)
				}
				return
			}
		}
		t.Fatalf("error wraps no sentinel: %v", err)
	})
}

func readTestdataF(f *testing.F, path string) []byte {
	f.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		f.Fatalf("read %s: %v", path, err)
	}
	return b
}
