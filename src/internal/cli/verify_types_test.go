package cli

import "testing"

// TestExtVerificationCorpusByType (fase 2c, Task 7): el matrix de estados de
// verificación (verificado/troyano/inerte/versión/ausente) para los tipos que
// no tenían corpus todavía — plugin y librería, el piso exigido por el brief
// (plugin: ejecutable, el más crítico; librería: raíz por <libraryname>,
// manifiesto en subdirectorio) — más module y template, para los que el
// matrix completo resultó igual de barato una vez generalizado add_extension/
// add_extension_baseline con `kind` (ver internal/corpus/corpus.go,
// MultiExtProvider). Mismo patrón que TestExtVerificationCorpus
// (verify_test.go) para el componente: un harness nuevo por caso.
func TestExtVerificationCorpusByType(t *testing.T) {
	for _, name := range []string{
		"ext-plg-verified",
		"ext-plg-trojan",
		"ext-plg-modified-inert",
		"ext-plg-version-mismatch",
		"ext-plg-official-missing",

		"ext-lib-verified",
		"ext-lib-trojan",
		"ext-lib-modified-inert",
		"ext-lib-version-mismatch",
		"ext-lib-official-missing",

		"ext-mod-verified",
		"ext-mod-trojan",
		"ext-mod-modified-inert",
		"ext-mod-version-mismatch",
		"ext-mod-official-missing",

		"ext-tpl-verified",
		"ext-tpl-trojan",
		"ext-tpl-modified-inert",
		"ext-tpl-version-mismatch",
		"ext-tpl-official-missing",
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			r, exit, doc, stderr := h.scanCase(t, name)
			assertExpectations(t, r, exit, doc, stderr)
		})
	}
}
