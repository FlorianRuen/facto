package logx_test

import (
	"strings"
	"testing"

	"github.com/FlorianRuen/facto/internal/logx"
)

// panicky panics in String: the walker must fail closed, not crash.
type panicky struct{}

func (panicky) String() string { panic("boom") }

func TestHandler_WalkEdgeCases(t *testing.T) {
	t.Parallel()
	selfMap := map[string]any{"user": "u1"}
	selfMap["self"] = selfMap
	selfSlice := []any{"u1", nil}
	selfSlice[1] = selfSlice
	type hidden struct {
		Name string
		fn   func()
		ch   chan int
		err  error
	}
	tests := []struct {
		name      string
		value     any
		want      []string
		forbidden []string
	}{
		{name: "map holding itself", value: selfMap, want: []string{"u1", "<cycle>"}},
		{name: "slice holding itself", value: selfSlice, want: []string{"u1", "<cycle>"}},
		{name: "panicking Stringer", value: panicky{}, want: []string{logx.Mask}},
		{
			name:      "uninspectable unexported fields",
			value:     hidden{Name: "u1", fn: func() {}, ch: make(chan int), err: leakError{"zz-hidden-err"}},
			want:      []string{"u1", "<func()>", "<chan int>", "<logx_test.leakError>"},
			forbidden: []string{"zz-hidden-err"},
		},
		{name: "non-string map keys", value: map[int]string{2: "b", 1: "a"}, want: []string{"map[1:a 2:b]"}},
		{name: "nil pointer", value: (*hidden)(nil), want: []string{"<nil>"}},
		{name: "scalars", value: []any{true, int8(-3), uint(4), 1.5, complex(1, 2)}, want: []string{"[true -3 4 1.5 (1+2i)]"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, _, last := jsonLogger(t, logx.Options{})
			l.Info("m", "v", tc.value)
			got, ok := last()["v"].(string)
			if !ok {
				t.Fatalf("v = %#v, want a string", last()["v"])
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("v = %q, want it to contain %q", got, w)
				}
			}
			for _, f := range tc.forbidden {
				if strings.Contains(got, f) {
					t.Errorf("v = %q leaks %q", got, f)
				}
			}
		})
	}
}

// leakError is an error whose message must not be printed from an unexported
// field.
type leakError struct{ s string }

func (e leakError) Error() string { return e.s }

func TestHandler_WideCompositeCut(t *testing.T) {
	t.Parallel()
	m := make(map[string]int, 1000)
	for i := range 1000 {
		m[strings.Repeat("k", 3)+string(rune('a'+i%26))+strings.Repeat("x", i%7)] = i
	}
	l, _, last := jsonLogger(t, logx.Options{MaxErrorLen: 32})
	l.Info("m", "v", m)
	got, _ := last()["v"].(string)
	if !strings.HasSuffix(got, logx.TruncatedSuffix) {
		t.Errorf("v = %q, want TruncatedSuffix", got)
	}
}
