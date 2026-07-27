package corediff

import (
	"sort"
	"strconv"
	"testing"
)

func TestCollapseMissingSubtrees(t *testing.T) {
	present := map[string]bool{
		"media/css/app.css": true, // media/ y media/css presentes
		"index.php":         true,
		"images/logo.png":   true, // images/ presente
	}
	// 10 ausentes bajo media/vendor (ausente por completo) + 2 bajo images/banners
	// (images/ presente → parcial → NO colapsa) + 1 .php suelto ausente.
	var missing []string
	for i := 0; i < 10; i++ {
		missing = append(missing, "media/vendor/tinymce/f"+string(rune('0'+i))+".js")
	}
	missing = append(missing, "images/banners/b1.png", "images/banners/b2.png", "libraries/gone.php")
	sort.Strings(missing)

	subs, collapsed := CollapseMissingSubtrees(missing, present)

	// Un solo subárbol colapsado: media/vendor, 10 archivos, clase inert_asset.
	if len(subs) != 1 {
		t.Fatalf("subtrees: %+v", subs)
	}
	if subs[0].Dir != "media/vendor" || subs[0].Count != 10 || subs[0].Class != "inert_asset" {
		t.Fatalf("subtree: %+v", subs[0])
	}
	if len(subs[0].Sample) != collapseSampleSize {
		t.Fatalf("sample size: %v", subs[0].Sample)
	}
	// Las 10 rutas de media/vendor están en collapsed; las de images/banners y el .php NO.
	for _, m := range missing {
		want := len(m) > len("media/vendor/") && m[:len("media/vendor/")] == "media/vendor/"
		if collapsed[m] != want {
			t.Errorf("collapsed[%q]=%v want %v", m, collapsed[m], want)
		}
	}
}

func TestCollapseBelowThresholdNotCollapsed(t *testing.T) {
	// 3 ausentes bajo un dir ausente-por-completo < umbral → no colapsa.
	present := map[string]bool{"index.php": true}
	missing := []string{"media/vendor/a.js", "media/vendor/b.js", "media/vendor/c.js"}
	subs, collapsed := CollapseMissingSubtrees(missing, present)
	if len(subs) != 0 || len(collapsed) != 0 {
		t.Fatalf("no debería colapsar: subs=%+v collapsed=%+v", subs, collapsed)
	}
}

func TestCollapseAggregateClassIsMax(t *testing.T) {
	// Subárbol ausente-completo con assets + un .php → clase agregada = executable (medium).
	present := map[string]bool{"index.php": true}
	var missing []string
	for i := 0; i < 8; i++ {
		missing = append(missing, "vendor/lib/a"+string(rune('0'+i))+".js")
	}
	missing = append(missing, "vendor/lib/run.php")
	sort.Strings(missing)
	subs, _ := CollapseMissingSubtrees(missing, present)
	if len(subs) != 1 || subs[0].Class != "executable" {
		t.Fatalf("clase agregada debe ser executable (máx): %+v", subs)
	}
}

func TestCollapseAggregateClassUnknownIsNotSynthesizedExecutable(t *testing.T) {
	// D5c review final MINOR 1: un subárbol ausente-por-completo compuesto
	// solo de archivos de tipo DESCONOCIDO (ni ejecutable, ni asset inerte,
	// ni ausencia-esperada) no debe "lavarse" a Class:"executable" — debe
	// reflejar la clase REAL del miembro de máx rango, que aquí es "" para
	// los 8. "vendor/keep.txt" ancla vendor/ como presente para que
	// vendor/cfg (y no vendor/ entero) sea el dir maximal ausente-por-completo.
	present := map[string]bool{"index.php": true, "vendor/keep.txt": true}
	var missing []string
	for i := 0; i < 8; i++ {
		missing = append(missing, "vendor/cfg/a"+string(rune('0'+i))+".xml")
	}
	sort.Strings(missing)
	subs, _ := CollapseMissingSubtrees(missing, present)
	if len(subs) != 1 || subs[0].Dir != "vendor/cfg" || subs[0].Count != 8 || subs[0].Class != "" {
		t.Fatalf("clase agregada de subárbol desconocido debe ser \"\" (no executable): %+v", subs)
	}
}

func TestCollapsePartialDirectoryNotCollapsed(t *testing.T) {
	// libraries/foo tiene un archivo presente (keep.php) junto a >= collapseThreshold
	// ausentes hermanos en el MISMO directorio: es un dir PARCIAL, no ausente-por-completo.
	// Esto fuerza la guarda !fullyAbsent(path.Dir(p)) de collapseRoot (a diferencia de
	// TestCollapseMissingSubtrees, donde images/banners no colapsa solo por estar bajo
	// el umbral, no por ser parcial).
	present := map[string]bool{"libraries/foo/keep.php": true}
	var missing []string
	for i := 0; i < 8; i++ {
		missing = append(missing, "libraries/foo/gone"+strconv.Itoa(i)+".js")
	}
	sort.Strings(missing)
	subs, collapsed := CollapseMissingSubtrees(missing, present)
	// libraries/foo está PARCIALMENTE presente (keep.php) → NO colapsa pese a 8 ausentes hermanos.
	if len(subs) != 0 {
		t.Fatalf("dir parcial no debe colapsar: %+v", subs)
	}
	if len(collapsed) != 0 {
		t.Fatalf("nada colapsado: %+v", collapsed)
	}
}
