package cli

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"j0witness/internal/lab"
)

// TestScanFormatSARIF cubre el despacho `scan --format sarif`: ancla que
// scan.go despacha de verdad a report.RenderSARIF y escribe SARIF 2.1.0
// válido a stdout (version, driver.name), espejo de TestScanFormatPDF.
func TestScanFormatSARIF(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.root, "clean-sarif")
	if err := lab.WriteTree(target, "1.1.0"); err != nil {
		t.Fatal(err)
	}

	exit, sarif, stderr := h.run(t, "scan", target, "--format", "sarif")
	if exit != int(ExitOKClean) {
		t.Fatalf("exit=%d, esperaba %d (OK_CLEAN); stderr=%s", exit, ExitOKClean, stderr)
	}
	assertLooksLikeSARIF(t, sarif)
}

// TestReportFormatSARIF cubre `report <workdir> --format sarif`:
// re-renderiza el run persistido (sin re-recorrer) y produce SARIF válido,
// espejo de TestReportFormatPDF.
func TestReportFormatSARIF(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.root, "clean-sarif-report")
	if err := lab.WriteTree(target, "1.1.0"); err != nil {
		t.Fatal(err)
	}
	exit, _, stderr := h.run(t, "scan", target)
	if exit != int(ExitOKClean) {
		t.Fatalf("scan previo: exit=%d, esperaba %d; stderr=%s", exit, ExitOKClean, stderr)
	}

	exit, sarif, stderr := h.run(t, "report", h.workdir, "--format", "sarif")
	if exit != int(ExitOKClean) {
		t.Fatalf("report --format sarif: exit=%d, esperaba %d; stderr=%s", exit, ExitOKClean, stderr)
	}
	assertLooksLikeSARIF(t, sarif)
}

// assertLooksLikeSARIF ancla las comprobaciones mínimas de sanidad de un
// documento SARIF 2.1.0 emitido por stdout: parsea como JSON, version
// "2.1.0" y runs[0].tool.driver.name == "J0Witness".
func assertLooksLikeSARIF(t *testing.T, doc []byte) {
	t.Helper()
	var s struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(doc, &s); err != nil {
		t.Fatalf("stdout no parsea como SARIF/JSON: %v\n%s", err, doc)
	}
	if s.Version != "2.1.0" {
		t.Fatalf("version=%q, esperaba \"2.1.0\"", s.Version)
	}
	if len(s.Runs) == 0 {
		t.Fatalf("runs vacío")
	}
	if got := s.Runs[0].Tool.Driver.Name; got != "J0Witness" {
		t.Fatalf("runs[0].tool.driver.name=%q, esperaba \"J0Witness\"", got)
	}
}
