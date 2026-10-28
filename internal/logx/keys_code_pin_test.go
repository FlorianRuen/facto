// Tests for the default sensitive keys "code", "pin" and "key" (J0
// hardening). They are short fragments (<= 4 letters), so the whole-word
// rule applies: they mask a key having them as a whole word ("code",
// "otp_code", "PinCode", "api_key", "X-Key", "country_code") and keep a key
// where they are only part of a word ("keyboard", "pincode", "zipcode",
// "postcode", "barcode", "hotkey"). Masking "country_code" or "status_code"
// is the accepted cost of the rule.
package logx_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
)

func TestHandler_MasksCodePinKeyWords(t *testing.T) {
	t.Parallel()
	const v = "plain-value-4245"
	sensitive := []string{
		"code", "Code", "CODE", "otp_code", "smsCode", "verification-code", "country_code", "PinCode",
		"pin", "PIN", "user_pin", "pinValue",
		"key", "Key", "KEY", "api_key", "X-Key", "privateKey", "key_id",
	}
	for _, key := range sensitive {
		t.Run("masks "+key, func(t *testing.T) {
			t.Parallel()
			got, raw := logBoth(t, key, v)
			if got != logx.Mask {
				t.Errorf("%s = %v, want %q", key, got, logx.Mask)
			}
			if strings.Contains(raw, v) {
				t.Errorf("output leaks the value:\n%s", raw)
			}
		})
	}
	kept := []string{
		"keyboard", "hotkey", "monkey", "keystone",
		"pincode", "spinner", "pinned", "shipping",
		"zipcode", "postcode", "barcode", "codec", "encoded", "decoder",
	}
	for _, key := range kept {
		t.Run("keeps "+key, func(t *testing.T) {
			t.Parallel()
			got, _ := logBoth(t, key, v)
			if got != v {
				t.Errorf("%s = %v, want %q kept", key, got, v)
			}
		})
	}

	runLeakCases(t, []leakCase{
		{name: "url.Values code", value: url.Values{"code": {"4245"}, "login": {"synthetic-user"}}, forbidden: []string{"4245"}, kept: []string{"synthetic-user"}},
		{name: "url.Values pin", value: url.Values{"pin": {"4245"}}, forbidden: []string{"4245"}},
		{name: "map key key", value: map[string]string{"key": shortPW}, forbidden: []string{shortPW}},
		{name: "struct field Code", value: struct{ Login, Code string }{"synthetic-user", shortPW}, forbidden: []string{shortPW}, kept: []string{"synthetic-user"}},
		{name: "struct field Keyboard kept", value: struct{ Keyboard string }{"synthetic-layout"}, kept: []string{"synthetic-layout"}},
	})
}
