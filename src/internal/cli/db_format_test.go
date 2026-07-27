package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestScanDBSurfacesFindingAndReportRerenders cubre el extremo a extremo de la
// capa L7 (feature 011, internal/dbscan): `scan --db <dump>` correlaciona el
// volcado con el árbol ya conocido y surge J0W-DB-003 (payload ejecutable
// residente en #__modules); el exit code refleja el hallazgo (ExitOKFindings).
// Después, `report` (sin --db) re-renderiza el MISMO hallazgo desde las
// observaciones ya persistidas (Principio II: la derivación es regenerable
// sin re-analizar) — es la garantía de que dbscan se integró como una capa
// más, no como un camino aparte que solo `scan` conoce.
func TestScanDBSurfacesFindingAndReportRerenders(t *testing.T) {
	h := newHarness(t)
	dump := filepath.Join(t.TempDir(), "d.sql")
	// El literal PHP `eval(base64_decode(...))` de abajo es texto dentro de un
	// volcado SQL sintético: es el payload MALICIOSO que dbscan.Analyze (vía
	// codescan.SuspiciousContent) debe DETECTAR en #__modules, nunca código que
	// este test ejecute (Principio IX: el dump se parsea, jamás se ejecuta).
	if err := os.WriteFile(dump, []byte("INSERT INTO `j_modules` (id, title, module, content, published) VALUES "+
		"(1,'x','mod_custom','<?php eval(base64_decode($_POST[0])); ?>',1);\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, code, doc, stderr := h.scanCaseArgs(t, "clean-minicms", "--db", dump)
	if !bytes.Contains(doc, []byte("J0W-DB-003")) {
		t.Fatalf("scan --db debe reportar J0W-DB-003 por el payload en el módulo\nstderr: %s\ninforme: %s", stderr, doc)
	}
	if code != int(ExitOKFindings) {
		t.Errorf("exit = %d, want %d\nstderr: %s", code, ExitOKFindings, stderr)
	}

	// report re-renderiza desde el inventario persistido, sin --db:
	rep := h.report(t, "--format", "json")
	if !bytes.Contains(rep, []byte("J0W-DB-003")) {
		t.Fatal("report debe re-derivar el hallazgo de BD desde las observaciones persistidas")
	}
}
