package cli

import "testing"

func TestDataflowDetectors(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{
		"code-split-eval", "code-split-input", "code-dynamic-call",
		"code-sanitized-split", "code-reassigned-split",
		// Negativos añadidos tras la validación real (Principio VI): fijan
		// los 3 falsos positivos hallados en el sitio real y ya corregidos
		// en el modelo (new $v(...), despacho convencional, assert booleano).
		"code-new-dynamic-class", "code-conventional-dispatch", "code-assert-boolean-check",
	} {
		t.Run(name, func(t *testing.T) {
			r, exit, doc, stderr := h.scanCase(t, name)
			assertExpectations(t, r, exit, doc, stderr)
		})
	}
}
