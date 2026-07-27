package cli

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
)

// TestReportBadExclusionsExitCode (review Task 1, fix round 1): un
// --exclusions malformado en `report` debe rechazarse como error de uso
// (exit 2), igual que en `scan` (offline_test.go: TestSuppressions) — no
// como error interno (exit 10). loadRunData propaga el fallo de
// finding.LoadSuppressions envuelto en finding.ErrSuppressions
// específicamente para que runReport pueda distinguirlo y preservar este
// exit code.
func TestReportBadExclusionsExitCode(t *testing.T) {
	h := newHarness(t)
	h.scanCase(t, "core-injected-line")

	excl := filepath.Join(h.root, "bad-excl.yaml")
	writeFile(t, excl, `- rule: J0W-CORE-001
  path: "*"
  reason: ""
`)
	exit, _, stderr := h.run(t, "report", h.workdir, "--exclusions", excl)
	if exit != int(ExitUsageError) {
		t.Fatalf("exclusions malformado en report debe ser ExitUsageError (2), es %d\n%s", exit, stderr)
	}
}

// stripRun elimina el único bloque no determinista.
func stripRun(t *testing.T, doc []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatalf("informe no parsea: %v", err)
	}
	delete(m, "run")
	return m
}

// T043 (SC-005, escenario 8): dos escaneos del mismo árbol y baseline →
// informes idénticos salvo el bloque run.
func TestScanDeterminism(t *testing.T) {
	h := newHarness(t)
	r, _, doc1, _ := h.scanCase(t, "core-injected-line")
	target := filepath.Join(h.root, "case-"+r.Case)
	_, doc2, stderr := h.run(t, "scan", target)
	if len(doc2) == 0 {
		t.Fatalf("segundo escaneo sin informe: %s", stderr)
	}
	m1, m2 := stripRun(t, doc1), stripRun(t, doc2)
	if !reflect.DeepEqual(m1, m2) {
		t.Fatalf("los informes difieren fuera del bloque run:\n1: %s\n2: %s", doc1, doc2)
	}
}

// T043/T044 (FR-008): report re-renderiza desde el inventario sin re-recorrer
// y reproduce los hallazgos del scan.
func TestReportRerender(t *testing.T) {
	h := newHarness(t)
	_, _, scanDoc, _ := h.scanCase(t, "core-injected-line")
	exit, repDoc, stderr := h.run(t, "report", h.workdir)
	if exit != 1 {
		t.Fatalf("report exit %d (esperaba 1, hay hallazgos)\n%s", exit, stderr)
	}
	s := parseReport(t, scanDoc)
	r := parseReport(t, repDoc)
	if len(s.Findings) != len(r.Findings) {
		t.Fatalf("scan=%d hallazgos, report=%d", len(s.Findings), len(r.Findings))
	}
	for i := range s.Findings {
		if s.Findings[i].ID != r.Findings[i].ID {
			t.Fatalf("ids divergen en %d: %s vs %s", i, s.Findings[i].ID, r.Findings[i].ID)
		}
	}
}
