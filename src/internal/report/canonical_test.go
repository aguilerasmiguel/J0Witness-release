package report

import (
	"bytes"
	"testing"
)

// T011: estabilidad byte a byte del serializador canónico.
func TestCanonicalMarshalDeterministic(t *testing.T) {
	v := map[string]any{
		"zeta": []int{3, 2, 1},
		"alfa": map[string]any{"y": 1, "x": "<script>&"},
	}
	a, err := CanonicalMarshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		b, err := CanonicalMarshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("iteración %d difiere:\n%s\n%s", i, a, b)
		}
	}
	if !bytes.HasSuffix(a, []byte("\n")) {
		t.Fatal("falta LF final")
	}
	if !bytes.Contains(a, []byte(`<script>&`)) {
		t.Fatal("no debe escapar HTML: '<script>&' tiene que aparecer literal")
	}
}
