package cli

import "testing"

// TestConfigDetectors cubre la capa L5 (confscan, feature 002): 3 positivos
// (exec_loader vía .htaccess/.user.ini, handler_widen sobre media inerte) y
// 1 negativo (.htaccess de reescritura SEF típico de Joomla, anti-FP).
func TestConfigDetectors(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{
		"config-exec-loader", "config-handler-widen", "config-user-ini-prepend",
		"config-htaccess-benigno",
	} {
		t.Run(name, func(t *testing.T) {
			r, exit, doc, stderr := h.scanCase(t, name)
			assertExpectations(t, r, exit, doc, stderr)
		})
	}
}

// TestConfigCoverage cubre la cobertura config_files_scanned (esquema 1.10.0):
// el positivo exec_loader materializa .htaccess/.user.ini/robots.txt.dist,
// así que el conteo debe ser > 0 y el bloque debe aparecer en el informe.
func TestConfigCoverage(t *testing.T) {
	h := newHarness(t)
	_, _, doc, _ := h.scanCase(t, "config-exec-loader")
	if !contains(string(doc), `"config_files_scanned"`) {
		t.Fatalf("falta cobertura config_files_scanned: %s", doc)
	}
}
