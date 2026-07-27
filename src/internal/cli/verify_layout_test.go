package cli

import (
	"encoding/json"
	"testing"
)

// TestLayoutNonstandardCorpus (fase 2c, Task 7; reajustado en fase 2d, Task
// 3): admin renombrado, y un plugin en plugins/ (fuera de
// administrator/panel) que verifica limpio pese al renombrado (las
// extensiones de sitio no dependen de dónde vive el admin). Desde la task 3
// de fase 2d, layout.Resolve auto-detecta el admin renombrado ANTES de
// adquirir y su Canonicalize lo remapea a administrator/ en el inventario,
// así que el árbol se reconoce limpio (exit 0) en vez del J0W-LAYOUT-001 low
// que emitía la fase 2c — esa observación (ahora layout_remap) la repone la
// task 4, momento en el que este recorte debe restaurarse (ver el
// comentario en testdata/corpus/layout-nonstandard.yaml). El contrato
// genérico (assertExpectations) cubre el exit code y la ausencia de
// J0W-EXT-008/009; aquí, además, se confirma explícitamente que
// plg_system_labplg queda verified:true — la prueba positiva de que la
// degradación (o, ahora, el remapeo) del layout admin NO se propaga al lado
// sitio (Principio VII).
func TestLayoutNonstandardCorpus(t *testing.T) {
	h := newHarness(t)
	r, exit, doc, stderr := h.scanCase(t, "layout-nonstandard")
	assertExpectations(t, r, exit, doc, stderr)

	var rep parsedVerificationReport
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatalf("informe no parsea: %v\n%s", err, doc)
	}
	var found bool
	for _, e := range rep.Extensions {
		if e.Name != "plg_system_labplg" {
			continue
		}
		found = true
		if e.Type != "plugin" {
			t.Errorf("plg_system_labplg: type=%q, esperaba plugin", e.Type)
		}
		if !e.Verified {
			t.Error("plg_system_labplg: verified debe ser true pese al admin renombrado")
		}
	}
	if !found {
		t.Fatalf("plg_system_labplg no aparece en coverage.extensions: %+v", rep.Extensions)
	}
}
