package cli

import (
	"encoding/json"
	"testing"
)

// T019 (SC-001): los negativos del corpus producen exit 0 y cero hallazgos de
// severidad media o superior.
//
// Fase 2d (Task 6, caso "standard-negative" del corpus de admin renombrado):
// estos árboles son el esqueleto administrator/ estándar (sin renombrar), y
// además de no emitir J0W-LAYOUT-001 (fase 2c) tampoco deben emitir
// coverage.layout en absoluto (fase 2c/2d: el campo es omitempty y solo se
// puebla cuando el árbol NO es estándar) — no se añade una receta nueva
// "layout-standard-negative.yaml" porque clean-minicms/clean-upgraded/
// clean-ascii-upload YA son exactamente ese caso (minicms estándar, sin
// mutaciones de admin); se extiende esta prueba en vez de duplicar receta.
func TestScanCleanCases(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{"clean-minicms", "clean-upgraded", "clean-ascii-upload"} {
		t.Run(name, func(t *testing.T) {
			r, exit, doc, stderr := h.scanCase(t, name)
			assertExpectations(t, r, exit, doc, stderr)
			p := parseReport(t, doc)
			for _, f := range p.Findings {
				if sevRank[f.Severity] >= sevRank["medium"] {
					t.Errorf("negativo %s con hallazgo >= medium: %s %s (%s)", name, f.RuleID, f.Subject, f.Severity)
				}
				// Fase 2c (task 5): minicms tiene el esqueleto admin estándar
				// (administrator/{components,manifests,includes}); un árbol
				// estándar no debe disparar el pre-flight de layout.
				if f.RuleID == "J0W-LAYOUT-001" {
					t.Errorf("negativo %s con J0W-LAYOUT-001: layout estándar no debe emitir el hallazgo (%+v)", name, f)
				}
			}

			var rep struct {
				Coverage struct {
					Layout json.RawMessage `json:"layout"`
				} `json:"coverage"`
			}
			if err := json.Unmarshal(doc, &rep); err != nil {
				t.Fatalf("informe no parsea: %v\n%s", err, doc)
			}
			if len(rep.Coverage.Layout) != 0 {
				t.Errorf("negativo %s con coverage.layout presente (%s): un árbol estándar no debe declarar remapeo/no-estándar", name, rep.Coverage.Layout)
			}
		})
	}
}
