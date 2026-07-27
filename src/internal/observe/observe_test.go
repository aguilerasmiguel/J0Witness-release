package observe

import (
	"strings"
	"testing"
)

// T008: constructores y serialización determinista de evidencia.
func TestNewCanonicalEvidence(t *testing.T) {
	ev := map[string]any{"zeta": 1, "alfa": "x", "media": []string{"a"}}
	o1, err := New([]byte("index.php"), FileModified, ev, SrcCorediff, High, 42)
	if err != nil {
		t.Fatal(err)
	}
	o2, _ := New([]byte("index.php"), FileModified, ev, SrcCorediff, High, 42)
	if o1.EvidenceJSON != o2.EvidenceJSON {
		t.Fatal("evidencia no determinista")
	}
	// Las claves de mapa se serializan ordenadas.
	if !strings.Contains(o1.EvidenceJSON, `"alfa":"x"`) ||
		strings.Index(o1.EvidenceJSON, "alfa") > strings.Index(o1.EvidenceJSON, "zeta") {
		t.Fatalf("claves sin ordenar: %s", o1.EvidenceJSON)
	}
	if o1.SubjectDisplay != "index.php" {
		t.Fatalf("display: %q", o1.SubjectDisplay)
	}
}

// Caso límite de la spec: rutas con bytes no UTF-8 o saltos de línea se
// registran de forma segura sin romper la salida.
func TestDisplayPathHostileNames(t *testing.T) {
	cases := map[string]string{
		"normal.php":                       "normal.php",
		"con\nsalto":                       "con\\nsalto",
		"con\rretorno":                     "con\\rretorno",
		string([]byte{0xff, 0xfe}) + "bin": "\\xff\\xfebin",
	}
	for in, want := range cases {
		if got := DisplayPath([]byte(in)); got != want {
			t.Errorf("DisplayPath(%q) = %q, quiere %q", in, got, want)
		}
	}
}
