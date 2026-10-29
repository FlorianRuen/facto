package vault_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/testsecrets"
	"github.com/FlorianRuen/facto/internal/vault"
)

func TestErrors_NeverCarryFileBytes(t *testing.T) {
	t.Parallel()
	art := testsecrets.ArtifactDir(t)
	canary := testsecrets.Canary(t, testsecrets.Session)
	cookie := testsecrets.Canary(t, testsecrets.Cookie)
	c := []byte(canary)

	raw := randBytes(t, 32)
	key := mustKey(t, raw)
	sealedCookie := mustSeal(t, testID, key, []byte(cookie))

	tests := []struct {
		name    string
		install string
		id      string
		key     vault.Key
		file    []byte
	}{
		{"bad magic", testInstall, testID, key, append(bytes.Clone(c), c...)},
		{"short canary file", testInstall, testID, key, c[:40]},
		{"canary after v1 header", testInstall, testID, key, append([]byte("FACTOSES\x01"), append(bytes.Clone(c), c...)...)},
		{"canary after v2 header", testInstall, testID, key, append([]byte("FACTOSES\x02"), append(bytes.Clone(c), c...)...)},
		{"oversized canary file", testInstall, testID, key, bytes.Repeat(c, vault.MaxFileSize/len(c)+2)},
		{"cookie file wrong key", testInstall, testID, mustKey(t, randBytes(t, 32)), sealedCookie},
		{"cookie file wrong id", testInstall, "edf", key, sealedCookie},
		{"cookie file wrong install", otherInstall, testID, key, sealedCookie},
	}

	var first string
	for i, tc := range tests {
		got, err := openBytes(t, tc.install, tc.id, tc.key, tc.file)
		wantInvalid(t, got, err)
		out := renderAll(t, err)
		writeArtifact(t, art, fmt.Sprintf("open-error-%d.txt", i), []byte(out))
		for _, f := range []string{
			testsecrets.Prefix,
			canary[13:],
			cookie[13:],
			hex.EncodeToString(tc.file[:min(len(tc.file), 48)][min(len(tc.file), 9):]),
		} {
			if f != "" && strings.Contains(out, f) {
				t.Fatalf("%s: Open error rendering carries file bytes:\n%s", tc.name, out)
			}
		}
		// ADR 0009: one opaque error, no detail about which check failed.
		if i == 0 {
			first = err.Error()
		} else if err.Error() != first {
			t.Fatalf("%s: error %q differs from %q; ErrInvalid must not say which check failed", tc.name, err.Error(), first)
		}
	}

	// The sealed file never holds the plaintext in clear.
	writeArtifact(t, art, "sealed-cookie.sess.hex", encodeHexLines(sealedCookie))
	if bytes.Contains(sealedCookie, []byte(cookie[13:])) {
		t.Fatalf("sealed file holds the plaintext in clear")
	}
}

func TestOpen_PlaintextRenderingMasked(t *testing.T) {
	t.Parallel()
	art := testsecrets.ArtifactDir(t)
	cookie := testsecrets.Canary(t, testsecrets.Cookie)
	key := mustKey(t, randBytes(t, 32))
	file := mustSeal(t, testID, key, []byte(cookie))
	got, err := openBytes(t, testInstall, testID, key, file)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	out := renderAll(t, got)
	writeArtifact(t, art, "opened-plaintext.txt", []byte(out))
	if strings.Contains(out, testsecrets.Prefix) {
		t.Fatalf("rendering the opened plaintext leaked it:\n%s", out)
	}
	got.Wipe()
}
