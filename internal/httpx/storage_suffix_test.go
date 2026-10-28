// Tests for the third review round on httpx: object-storage and
// edge/PaaS suffixes where unrelated tenants share a parent domain.
//
// Expected behaviour (implementer: follow exactly, and list them in the
// ParseAllowlist doc comment): besides the suffixes of review_test.go,
// ParseAllowlist (and so connector.ValidateInfo) refuses, wrapping
// ErrInvalidAllowlist and case-insensitively, any entry equal to, or "*."
// followed by:
//
//   - s3.amazonaws.com
//   - s3.<region>.amazonaws.com for ANY region label (pattern, not a fixed
//     list: "s3.eu-west-3.amazonaws.com", "s3.us-east-1.amazonaws.com",
//     "s3.ap-southeast-2.amazonaws.com", "s3.xx-future-9.amazonaws.com"…)
//   - blob.core.windows.net, r2.dev, workers.dev, storage.googleapis.com,
//     googleusercontent.com, onrender.com, fly.dev
//
// One tenant's host stays valid, exact or as a wildcard below it
// ("mybucket.s3.eu-west-3.amazonaws.com", "*.factoacct.blob.core.windows.net").
package httpx_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/connector"
	"github.com/FlorianRuen/facto/internal/httpx"
)

var storageSuffixes = []string{
	"s3.amazonaws.com",
	"s3.eu-west-3.amazonaws.com", "s3.us-east-1.amazonaws.com",
	"s3.ap-southeast-2.amazonaws.com", "s3.xx-future-9.amazonaws.com",
	"blob.core.windows.net", "r2.dev", "workers.dev", "storage.googleapis.com",
	"googleusercontent.com", "onrender.com", "fly.dev",
}

var storageTenantAllowlists = [][]string{
	{"mybucket.s3.amazonaws.com"},
	{"mybucket.s3.eu-west-3.amazonaws.com"},
	{"*.mybucket.s3.eu-west-3.amazonaws.com"},
	{"factoacct.blob.core.windows.net"},
	{"*.factoacct.blob.core.windows.net"},
	{"pub-0123abcd.r2.dev"},
	{"facto-demo.workers.dev"},
	{"doc-00-facto.googleusercontent.com"},
	{"facto-demo.onrender.com"},
	{"facto-demo.fly.dev"},
	{"fournisseur.example", "*.fournisseur.example", "facto-demo.fly.dev"},
}

func storageSuffixAllowlists() [][]string {
	var out [][]string
	for _, s := range storageSuffixes {
		out = append(out, []string{s}, []string{"*." + s}, []string{"*." + strings.ToUpper(s)})
	}
	return append(out,
		[]string{"*.S3.Eu-West-3.AmazonAWS.com"},
		[]string{"fournisseur.example", "*.r2.dev"},
		[]string{"facto-demo.fly.dev", "*.storage.googleapis.com"},
	)
}

func TestParseAllowlist_RejectsStorageAndEdgeSuffixes(t *testing.T) {
	t.Parallel()
	for _, list := range storageSuffixAllowlists() {
		t.Run("refuses "+strings.Join(list, ","), func(t *testing.T) {
			t.Parallel()
			if _, err := httpx.ParseAllowlist(list); !errors.Is(err, httpx.ErrInvalidAllowlist) {
				t.Errorf("ParseAllowlist(%q) error = %v, want ErrInvalidAllowlist", list, err)
			}
			c, err := httpx.New(list, httpx.Options{})
			if !errors.Is(err, httpx.ErrInvalidAllowlist) || c != nil {
				t.Errorf("New(%q) = %v, %v; want nil, ErrInvalidAllowlist", list, c, err)
			}
			if err := connector.ValidateInfo(connector.Info{ID: "fournisseur", Name: "Fournisseur", AllowedDomains: list}); err == nil {
				t.Errorf("connector.ValidateInfo(AllowedDomains %q) = nil, want an error", list)
			}
		})
	}
	for _, list := range storageTenantAllowlists {
		t.Run("keeps "+strings.Join(list, ","), func(t *testing.T) {
			t.Parallel()
			a, err := httpx.ParseAllowlist(list)
			if err != nil {
				t.Fatalf("ParseAllowlist(%q) error = %v, want valid", list, err)
			}
			if err := connector.ValidateInfo(connector.Info{ID: "fournisseur", Name: "Fournisseur", AllowedDomains: list}); err != nil {
				t.Errorf("connector.ValidateInfo(AllowedDomains %q) = %v, want valid", list, err)
			}
			host := strings.TrimPrefix(list[len(list)-1], "*.")
			if strings.HasPrefix(list[len(list)-1], "*.") {
				host = "x." + host
			}
			if !a.Allows(host) {
				t.Errorf("Allows(%q) = false for %q", host, list)
			}
		})
	}
}
