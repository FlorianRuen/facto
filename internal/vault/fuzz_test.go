package vault_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/FlorianRuen/facto/internal/vault"
)

// FuzzOpen_NeverPanics feeds arbitrary bytes to Open under the golden key and
// ids. Seeds: the synthetic golden v1 file and corruptions of it.
func FuzzOpen_NeverPanics(f *testing.F) {
	data, err := readTestdata("testdata/TestSeal_GoldenV1/v1.golden")
	if err != nil {
		f.Fatalf("read golden: %v", err)
	}
	golden, err := decodeHexLines(data)
	if err != nil {
		f.Fatalf("decode golden: %v", err)
	}
	const pt = "synthetic session blob v1\n"

	f.Add(golden)
	f.Add([]byte{})
	f.Add([]byte("FACTOSES"))
	f.Add([]byte("FACTOSES\x01"))
	f.Add(golden[:vault.HeaderSize])
	f.Add(golden[:len(golden)-1])
	f.Add(append(bytes.Clone(golden), 0x00))
	for _, i := range []int{0, 8, 9, 32, 33, len(golden) - 1} {
		b := bytes.Clone(golden)
		b[i] ^= 0x01
		f.Add(b)
	}
	v2 := bytes.Clone(golden)
	v2[8] = 0x02
	f.Add(v2)

	f.Fuzz(func(t *testing.T, file []byte) {
		key, err := vault.ParseKey(encodeKey(fixedKeyBytes()))
		if err != nil {
			t.Fatalf("ParseKey: %v", err)
		}
		got, err := vault.Open(t.Context(), testInstall, testID, key, bytes.NewReader(file))
		if err != nil {
			if !errors.Is(err, vault.ErrInvalid) {
				t.Fatalf("Open error = %v, want ErrInvalid for any malformed file", err)
			}
			if !got.IsZero() {
				t.Fatalf("Open returned plaintext alongside an error")
			}
			return
		}
		if !bytes.Equal(file, golden) || got.Expose() != pt {
			t.Fatalf("Open accepted a file that is not the golden one (%d bytes)", len(file))
		}
	})
}
