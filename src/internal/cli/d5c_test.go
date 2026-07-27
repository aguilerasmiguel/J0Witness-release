package cli

import "testing"

// D5c: J0W-CORE-003 colapsa en UN solo hallazgo cuando un subárbol ENTERO del
// baseline está ausente-por-completo (>= collapseThreshold=8 archivos, ningún
// hermano presente); un directorio PARCIALMENTE presente NUNCA colapsa
// (Principio VI: un borrado dirigido de 1-2 archivos no puede esconderse
// detrás del colapso de bloque). Las recetas ya afirman (vía not_findings)
// que los individuales/el colapsado, según el caso, están ausentes del
// informe; aquí se ancla además el RECUENTO exacto de J0W-CORE-003 por caso,
// que es lo que realmente distingue "un hallazgo resumido" de "N
// individuales" (not_findings por sí solo no descarta un tercer subject
// inesperado).
func TestD5cCollapseMissingSubtrees(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name      string
		wantCore3 int
	}{
		// media/vendor/lib/ (8 .js/.css) borrado por completo → colapsa en 1.
		{"core-missing-subtree-inert", 1},
		// vendor/pkg/ (8 .php) borrado por completo → colapsa en 1 (clase
		// "executable", medium).
		{"core-missing-subtree-code", 1},
		// Solo 2 de los 8 de media/vendor/lib/ borrados (parcial) → 2
		// individuales, SIN colapsar.
		{"core-missing-subtree-partial", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, exit, doc, stderr := h.scanCase(t, c.name)
			assertExpectations(t, r, exit, doc, stderr)
			p := parseReport(t, doc)
			got := 0
			for _, f := range p.Findings {
				if f.RuleID == "J0W-CORE-003" {
					got++
				}
			}
			if got != c.wantCore3 {
				t.Errorf("caso %s: %d hallazgos J0W-CORE-003, esperaba %d\ninforme: %s", c.name, got, c.wantCore3, doc)
			}
		})
	}
}
