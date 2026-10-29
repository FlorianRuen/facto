package httpx_test

import (
	"errors"
	"testing"

	"github.com/FlorianRuen/facto/internal/httpx"
)

// TestParseAllowlist_S3EndpointVariants covers the S3 website and dualstack
// regional endpoints, refused like s3.<region>.amazonaws.com, while one
// bucket's host below them stays valid.
func TestParseAllowlist_S3EndpointVariants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		entry string
		ok    bool
	}{
		{entry: "s3-website.eu-west-3.amazonaws.com"},
		{entry: "*.s3-website.eu-west-3.amazonaws.com"},
		{entry: "s3.dualstack.us-east-1.amazonaws.com"},
		{entry: "*.S3.DualStack.us-east-1.amazonaws.com"},
		{entry: "mybucket.s3-website.eu-west-3.amazonaws.com", ok: true},
		{entry: "mybucket.s3.dualstack.us-east-1.amazonaws.com", ok: true},
		{entry: "ec2.eu-west-3.amazonaws.com", ok: true},
	}
	for _, tc := range tests {
		t.Run(tc.entry, func(t *testing.T) {
			t.Parallel()
			_, err := httpx.ParseAllowlist([]string{tc.entry})
			if tc.ok && err != nil {
				t.Errorf("ParseAllowlist(%q) error = %v, want valid", tc.entry, err)
			}
			if !tc.ok && !errors.Is(err, httpx.ErrInvalidAllowlist) {
				t.Errorf("ParseAllowlist(%q) error = %v, want ErrInvalidAllowlist", tc.entry, err)
			}
		})
	}
}
