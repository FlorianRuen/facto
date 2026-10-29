package httpx_test

import (
	"errors"
	"testing"

	"github.com/FlorianRuen/facto/internal/httpx"
)

// TestParseAllowlist_AmazonAWSWildcards: AWS hosts many multi-tenant
// endpoints below amazonaws.com (legacy s3-<region>, s3-website-<region>,
// s3-fips, s3-accesspoint, execute-api, elb…) and new ones appear, so a
// wildcard below amazonaws.com is refused, unless its base is one tenant
// directly below a known shared endpoint ("*.mybucket.s3.eu-west-3…", kept
// valid by storage_suffix_test.go). A single exact tenant host stays valid.
func TestParseAllowlist_AmazonAWSWildcards(t *testing.T) {
	t.Parallel()
	tests := []struct {
		entry string
		ok    bool
	}{
		{entry: "*.s3-eu-west-3.amazonaws.com"},
		{entry: "*.s3-website-eu-west-3.amazonaws.com"},
		{entry: "*.S3-Website-Us-East-1.AmazonAWS.com"},
		{entry: "*.s3-fips.us-east-1.amazonaws.com"},
		{entry: "*.s3-fips.dualstack.us-east-1.amazonaws.com"},
		{entry: "*.s3-accesspoint.eu-west-3.amazonaws.com"},
		{entry: "*.s3-accesspoint.dualstack.eu-west-3.amazonaws.com"},
		{entry: "*.execute-api.eu-west-3.amazonaws.com"},
		{entry: "*.elb.amazonaws.com"},
		{entry: "*.eu-west-3.elb.amazonaws.com"},
		{entry: "*.ec2.eu-west-3.amazonaws.com"},
		{entry: "*.eu-west-3.amazonaws.com"},
		{entry: "*.compute.amazonaws.com"},
		{entry: "*.abc123.execute-api.eu-west-3.amazonaws.com"},
		{entry: "*.mybucket.s3-eu-west-3.amazonaws.com"},
		{entry: "*.mybucket.s3.amazonaws.com", ok: true},
		{entry: "*.mybucket.s3-website.eu-west-3.amazonaws.com", ok: true},
		{entry: "abc123.execute-api.eu-west-3.amazonaws.com", ok: true},
		{entry: "my-lb-1234.eu-west-3.elb.amazonaws.com", ok: true},
		{entry: "mybucket.s3-eu-west-3.amazonaws.com", ok: true},
		{entry: "mybucket.s3-website-eu-west-3.amazonaws.com", ok: true},
		{entry: "ap-123456789012.s3-accesspoint.eu-west-3.amazonaws.com", ok: true},
		{entry: "mybucket.s3-fips.us-east-1.amazonaws.com", ok: true},
	}
	for _, tc := range tests {
		t.Run(tc.entry, func(t *testing.T) {
			t.Parallel()
			a, err := httpx.ParseAllowlist([]string{tc.entry})
			if tc.ok {
				if err != nil {
					t.Fatalf("ParseAllowlist(%q) error = %v, want valid", tc.entry, err)
				}
				host := tc.entry
				if len(host) > 2 && host[:2] == "*." {
					host = "x" + host[1:]
				}
				if !a.Allows(host) {
					t.Errorf("Allows(%q) = false for %q", host, tc.entry)
				}
				return
			}
			if !errors.Is(err, httpx.ErrInvalidAllowlist) {
				t.Errorf("ParseAllowlist(%q) error = %v, want ErrInvalidAllowlist", tc.entry, err)
			}
		})
	}
}
