package facturx_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/normalize/facturx"
)

func TestParseCII_FieldCharacters(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		seller  string
		want    string
		wantErr bool
	}{
		{"accented", "Électricité de Synthèse", "Électricité de Synthèse", false},
		{"astral plane", "Synth &#x1F4A1; SAS", "Synth \U0001F4A1 SAS", false},
		{"literal replacement char", "Synth � SAS", "", true},
		{"replacement char reference", "Synth &#xFFFD; SAS", "", true},
		{"low surrogate reference", "Synth &#xDC00; SAS", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			inv, err := facturx.ParseCII(strings.NewReader(atkCIIOpen + atkSeller(tt.seller) + atkCIIClose))
			if tt.wantErr {
				if !errors.Is(err, facturx.ErrInvalid) {
					t.Fatalf("ParseCII error = %v, want ErrInvalid", err)
				}
				if inv != (facturx.Invoice{}) {
					t.Fatalf("ParseCII returned %+v on error, want the zero value", inv)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCII error = %v", err)
			}
			if inv.SellerName != tt.want {
				t.Fatalf("SellerName = %q, want %q", inv.SellerName, tt.want)
			}
		})
	}
}
