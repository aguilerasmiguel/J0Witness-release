package cli

import (
	"testing"

	"j0witness/internal/layout"
	"j0witness/internal/observe"
)

// TestLayoutFromObsNonstandard fija el contrato de claves de evidencia entre
// el lado que emite (scan.go, fase 2d task 4: observe.New(nil,
// observe.LayoutRemap, map[string]any{"admin_dir_found": ..., "standard":
// false, ...}, ...)) y el lado que lee (layoutFromObs): un cambio de nombre
// de clave silencioso compilaría y pasaría cualquier test que no ejercite
// este camino, corrompiendo coverage.layout en informes re-renderizados de
// sitios con admin renombrado. Este caso (remap_applied:false) es el
// "no-resuelto": layout.Config resultante debe marcar NonstandardUnresolved.
func TestLayoutFromObsNonstandard(t *testing.T) {
	o, err := observe.New(nil, observe.LayoutRemap, map[string]any{
		"admin_dir_found": "panel", "standard": false, "remap_applied": false,
	}, observe.SrcAcquire, observe.High, 1)
	if err != nil {
		t.Fatal(err)
	}
	got := layoutFromObs([]observe.Observation{o})
	want := layout.Config{AdminDirFound: "panel", NonstandardUnresolved: true}
	if got != want {
		t.Fatalf("layoutFromObs = %+v, quiere %+v", got, want)
	}
}

// TestLayoutFromObsStandard cubre el caso sin observación layout_remap
// persistida (árbol estándar en el scan original, scan.go no la emite): el
// re-render debe reconstruir layout.Config{} (identidad: sin remapeo).
func TestLayoutFromObsStandard(t *testing.T) {
	got := layoutFromObs(nil)
	want := layout.Config{}
	if got != want {
		t.Fatalf("layoutFromObs(nil) = %+v, quiere %+v", got, want)
	}
}

// TestLayoutFromObsRemapApplied cubre el caso "no estándar pero remapeado"
// (fase 2d, T5): admin_dir renombrado y resuelto (operador o auto-detect), sin
// J0W-LAYOUT-001. layoutFromObs debe reconstruir el layout.Config completo —
// AdminDir/ApiDir/Source — para que tanto coverage.layout como Realize salgan
// idénticos a los del run original.
func TestLayoutFromObsRemapApplied(t *testing.T) {
	o, err := observe.New(nil, observe.LayoutRemap, map[string]any{
		"standard": false, "remap_applied": true,
		"admin_dir": "adm1ng", "api_dir": "", "remap_source": "operator",
		"admin_dir_found": "",
	}, observe.SrcAcquire, observe.High, 1)
	if err != nil {
		t.Fatal(err)
	}
	got := layoutFromObs([]observe.Observation{o})
	want := layout.Config{AdminDir: "adm1ng", Source: layout.SourceOperator}
	if got != want {
		t.Fatalf("layoutFromObs = %+v, quiere %+v", got, want)
	}
	if !got.RemapApplied() {
		t.Fatal("RemapApplied() debe ser true")
	}
	if got.Realize("administrator/x.php") != "adm1ng/x.php" {
		t.Fatalf("Realize = %q, quiere adm1ng/x.php", got.Realize("administrator/x.php"))
	}
}
