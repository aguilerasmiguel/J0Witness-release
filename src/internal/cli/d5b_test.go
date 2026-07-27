package cli

import "testing"

// D5b: J0W-CORE-003 (archivo del core ausente) se calibra por clase —
// ejecutable se queda medium (core-missing-file, cubierto en
// TestScanFindingCases), asset inerte degrada a low, ausencia esperada
// (dist-default) degrada a info, y un desconocido no-código se queda medium
// por defecto conservador.
func TestD5bMissingFileSeverityByClass(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{"core-missing-inert", "core-missing-expected", "core-missing-unknown"} {
		t.Run(name, func(t *testing.T) {
			r, exit, doc, stderr := h.scanCase(t, name)
			assertExpectations(t, r, exit, doc, stderr)
		})
	}
}
