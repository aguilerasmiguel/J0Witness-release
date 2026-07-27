package cli

import "testing"

// D5: los inertes se degradan (no fuerzan exit 1) y los ejecutables mantienen
// su severidad plena — verificado sobre las recetas negativas y las positivas
// preexistentes.
func TestD5SeverityAwareness(t *testing.T) {
	h := newHarness(t)
	// Negativos: inertes degradados.
	for _, name := range []string{"core-image-modified", "obsolete-image-benign", "type-mismatch-benign"} {
		t.Run(name, func(t *testing.T) {
			r, exit, doc, stderr := h.scanCase(t, name)
			assertExpectations(t, r, exit, doc, stderr)
		})
	}
	// Positivos preexistentes: ejecutables NO degradan.
	for _, name := range []string{"core-replaced-file", "obsolete-turned-shell", "type-mismatch"} {
		t.Run(name+"/no-degrada", func(t *testing.T) {
			r, exit, doc, stderr := h.scanCase(t, name)
			assertExpectations(t, r, exit, doc, stderr)
		})
	}
}
