package fingerprint

import (
	"os"
	"path/filepath"
	"testing"

	"j0witness/internal/layout"
	"j0witness/internal/safefs"
)

// TestDeclaredThroughRealizingOpener (fase 2d, Task 6, fix round 1) prueba
// que Declared encuentra la versión declarada en
// administrator/manifests/files/joomla.xml incluso cuando el admin está
// renombrado, SIEMPRE que se le inyecte un Opener que revierta la ruta
// canónica a la real (layout.RealizingOpener). Antes del fix, Declared solo
// aceptaba *safefs.FS y abría cada fuente literal contra el árbol real: en
// un árbol renombrado esa fuente es inalcanzable y Declared se queda
// callado ("" — nunca inventa, Principio VI), sin que nada lo delate,
// porque en minicms libraries/src/Version.php siempre gana antes. Este
// árbol es mínimo y deliberadamente NO tiene libraries/src/Version.php: su
// ÚNICA fuente declarada es joomla.xml, para que la degradación (o su
// ausencia, tras el fix) sea observable sin ambigüedad.
func TestDeclaredThroughRealizingOpener(t *testing.T) {
	dir := t.TempDir()
	xml := "<?xml version=\"1.0\"?>\n<extension><version>9.9.9</version></extension>\n"
	manifestReal := filepath.Join(dir, "adm1ng", "manifests", "files", "joomla.xml")
	if err := os.MkdirAll(filepath.Dir(manifestReal), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestReal, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}

	fsys, err := safefs.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Sin envoltura: Open literal de "administrator/manifests/files/joomla.xml"
	// (declaredSources[1]) falla contra un árbol real que solo tiene
	// adm1ng/... — Declared no tiene otra fuente que probar y debe volver "".
	if got := Declared(fsys); got != "" {
		t.Fatalf("Declared(fsys) sin realize = %q, esperaba \"\" (la fuente canónica no existe en el árbol real renombrado)", got)
	}

	// Con la envoltura: RealizingOpener revierte administrator/... ->
	// adm1ng/... antes de abrir (Cfg.AdminDir="adm1ng"), y la fuente SÍ se
	// encuentra.
	cfg := layout.Config{AdminDir: "adm1ng", Source: layout.SourceOperator}
	opener := layout.NewRealizingOpener(fsys, cfg)
	if got := Declared(opener); got != "9.9.9" {
		t.Fatalf("Declared(realizingOpener) = %q, esperaba \"9.9.9\" (joomla.xml realizado a adm1ng/...)", got)
	}
}

// TestDeclaredStandardPathUnaffected confirma el guard de passthrough: sobre
// un árbol ESTÁNDAR (sin remapeo, Config{} — AdminDir=""), Declared(fsys) y
// Declared(RealizingOpener) deben coincidir exactamente, porque Realize es
// identidad cuando Cfg.AdminDir=="" (fase 2d, Task 6: el camino estándar
// debe quedar byte-idéntico).
func TestDeclaredStandardPathUnaffected(t *testing.T) {
	dir := t.TempDir()
	xml := "<?xml version=\"1.0\"?>\n<extension><version>9.9.9</version></extension>\n"
	manifestReal := filepath.Join(dir, "administrator", "manifests", "files", "joomla.xml")
	if err := os.MkdirAll(filepath.Dir(manifestReal), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestReal, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}

	fsys, err := safefs.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	direct := Declared(fsys)
	wrapped := Declared(layout.NewRealizingOpener(fsys, layout.Config{}))
	if direct != "9.9.9" || wrapped != direct {
		t.Fatalf("Declared directo=%q, envuelto=%q; esperaba ambos \"9.9.9\" (passthrough transparente sin remapeo)", direct, wrapped)
	}
}
