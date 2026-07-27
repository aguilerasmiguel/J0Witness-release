package cli

import (
	"os"
	"path/filepath"
	"testing"

	"j0witness/internal/lab"
)

// TestScanAdministratorDirFlag (fase 2d, task 3) ancla el orden
// resolver-antes-de-adquirir end-to-end: un minicms con administrator/
// renombrado a adm1ng/ (conserva el mismo esqueleto reconocible —
// components/, manifests/, includes/) escaneado con
// --administrator-dir=adm1ng debe canonicalizar adm1ng/* -> administrator/*
// en la adquisición, ANTES de que DetectRoots y el fingerprint recorran el
// inventario. Sin la canonicalización, DetectRoots vería dos raíces (site +
// adm1ng, éste con su propio esqueleto administrator-like) o, si eso no
// dispara, el fingerprint no vería administrator/index.php y el core diff
// reportaría todo el árbol admin como "ausente" — cualquiera de las dos
// cosas rompería el exit 0 limpio que se espera aquí.
func TestScanAdministratorDirFlag(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.root, "renamed-admin")
	if err := lab.WriteTree(target, "1.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(target, "administrator"), filepath.Join(target, "adm1ng")); err != nil {
		t.Fatal(err)
	}

	exit, doc, stderr := h.run(t, "scan", target, "--administrator-dir", "adm1ng")
	if exit != int(ExitOKClean) {
		t.Fatalf("exit=%d, esperaba %d (OK_CLEAN); stderr=%s\ninforme=%s", exit, ExitOKClean, stderr, doc)
	}
	assertNoLayoutFinding(t, doc)
}

// TestScanAdministratorDirAutoDetect es la contraparte sin bandera: la
// auto-detección de layout.Resolve (vía layout.DetectAdmin, sin
// --administrator-dir) debe lograr el mismo resultado, porque adm1ng/
// conserva el esqueleto reconocible y es el único candidato de primer nivel
// fuera de las raíces de sitio conocidas.
func TestScanAdministratorDirAutoDetect(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.root, "renamed-admin-auto")
	if err := lab.WriteTree(target, "1.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(target, "administrator"), filepath.Join(target, "adm1ng")); err != nil {
		t.Fatal(err)
	}

	exit, doc, stderr := h.run(t, "scan", target)
	if exit != int(ExitOKClean) {
		t.Fatalf("exit=%d, esperaba %d (OK_CLEAN); stderr=%s\ninforme=%s", exit, ExitOKClean, stderr, doc)
	}
	assertNoLayoutFinding(t, doc)
}

// assertNoLayoutFinding parsea el informe y falla si contiene un hallazgo
// J0W-LAYOUT-001. Solo mirar el exit code no basta: J0W-LAYOUT-001 es Low, y
// Low no dispara el --fail-on medium por defecto, así que una regresión que
// emitiera el hallazgo en un árbol remapeado (admin renombrado + flag u
// auto-detección) pasaría desapercibida si solo se comprueba el exit code.
func assertNoLayoutFinding(t *testing.T, doc []byte) {
	t.Helper()
	p := parseReport(t, doc)
	for _, f := range p.Findings {
		if f.RuleID == "J0W-LAYOUT-001" {
			t.Errorf("árbol remapeado con J0W-LAYOUT-001: no debe emitirse (%+v)", f)
		}
	}
}
