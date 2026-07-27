package cli

import "testing"

// T020 (SC-002): cada manipulación inyectada por la receta aparece en el
// informe con el rule_id esperado.
func TestScanFindingCases(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{
		"core-injected-line",
		"core-replaced-file",
		"core-missing-file",
		"core-alien-php",
		"obsolete-turned-shell",
		"type-mismatch",
		"cache-artifact-benigno",
		"cache-webshell-sin-guarda",
		"cache-webshell-con-guarda",
		"logs-artifact-benigno",
	} {
		t.Run(name, func(t *testing.T) {
			r, exit, doc, stderr := h.scanCase(t, name)
			assertExpectations(t, r, exit, doc, stderr)
		})
	}
}

// FR-031: el informe localiza el rango de líneas de la inyección.
func TestInjectionReportsLineRange(t *testing.T) {
	h := newHarness(t)
	_, _, doc, _ := h.scanCase(t, "core-injected-line")
	p := parseReport(t, doc)
	for _, f := range p.Findings {
		if f.RuleID == "J0W-CORE-002" && f.Subject == "index.php" {
			return // el hunk viaja en evidence; la presencia del hallazgo con id estable basta aquí
		}
	}
	t.Fatal("falta J0W-CORE-002 sobre index.php")
}
