// Informational red-team finding (J0 T30) against internal/normalize/facturx,
// now defended: encoding/xml accepts "&#xD800;" (not a legal XML Char) and
// yields U+FFFD; ParseCII refuses such a field with ErrInvalid. Uses
// atkCIIOpen, atkCIIClose and atkSeller from attack_test.go.
package facturx_test

import (
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/normalize/facturx"
)

func TestAttack_ParseCIIRejectsSurrogateCharRef(t *testing.T) {
	t.Parallel()
	for _, ref := range []string{"&#xD800;", "&#xDFFF;", "&#xFFFE;"} {
		inv, err := facturx.ParseCII(strings.NewReader(atkCIIOpen + atkSeller("a"+ref+"b") + atkCIIClose))
		if err == nil {
			t.Errorf("ParseCII accepted the illegal character reference %s: seller %q", ref, inv.SellerName)
		}
	}
}
