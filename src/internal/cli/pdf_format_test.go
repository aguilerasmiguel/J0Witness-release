package cli

import (
	"bytes"
	"path/filepath"
	"testing"

	"j0witness/internal/lab"
	"j0witness/internal/report"
)

// TestScanFormatPDF (Task 3, informe PDF) cubre el despacho `scan --format
// pdf` en dos partes:
//
//  1. Una invocación real de la CLI (`scan target --format pdf`) produce un
//     PDF válido (cabecera %PDF-, tamaño no trivial) — ancla que scan.go
//     despacha de verdad a report.RenderPDF y escribe los bytes a stdout.
//  2. La reproducibilidad "mismo informe → mismos bytes PDF" se prueba
//     tomando el JSON canónico de UNA sola invocación (`--format json`) y
//     llamando report.RenderPDF DOS VECES sobre esos mismos bytes en el
//     mismo proceso — sin volver a invocar la CLI.
//
// Por qué no "ejecutar `scan --format pdf` dos veces y comparar stdout":
// cada invocación (scan.go / report.go) calcula `Finished: time.Now()` en el
// momento del render (ver assembleReport), y RenderPDF proyecta
// r.Run.FinishedAt (resolución de segundo, RFC3339) en la cabecera del PDF.
// Si las dos invocaciones caen a caballo de una frontera de segundo de
// reloj, el PDF difiere aunque el árbol escaneado sea idéntico — confirmado
// empíricamente (go test -run TestScanFormatPDF -count=10 falló 2/10 con esa
// comparación). Eso NO es un bug de RenderPDF (ya probado determinista y
// libre de reloj en internal/report/pdf_test.go,
// TestRenderPDFDeterministic): es la misma no-determinism del bloque `run`
// que el brief de la tarea documenta para dos escaneos distintos, solo que
// también alcanza a dos invocaciones consecutivas del MISMO objetivo. La
// forma correcta y libre de reloj de anclar "mismo informe → mismos bytes"
// es la del punto 2 arriba.
func TestScanFormatPDF(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.root, "clean-pdf")
	if err := lab.WriteTree(target, "1.1.0"); err != nil {
		t.Fatal(err)
	}

	// 1. Despacho real de la CLI: --format pdf produce un PDF válido.
	exit, pdf, stderr := h.run(t, "scan", target, "--format", "pdf")
	if exit != int(ExitOKClean) {
		t.Fatalf("exit=%d, esperaba %d (OK_CLEAN); stderr=%s", exit, ExitOKClean, stderr)
	}
	assertLooksLikePDF(t, pdf)

	// 2. Reproducibilidad libre de reloj: mismo JSON canónico → mismos
	// bytes PDF, sin volver a invocar la CLI (evita la frontera de
	// segundo de r.Run.FinishedAt entre invocaciones separadas).
	exit, doc, stderr := h.run(t, "scan", target, "--format", "json")
	if exit != int(ExitOKClean) {
		t.Fatalf("scan --format json: exit=%d, esperaba %d; stderr=%s", exit, ExitOKClean, stderr)
	}
	if !bytes.HasPrefix(bytes.TrimSpace(doc), []byte("{")) {
		t.Fatalf("--format json no parece JSON: %q", doc[:min(16, len(doc))])
	}
	a, err := report.RenderPDF(doc)
	if err != nil {
		t.Fatalf("RenderPDF (1a llamada): %v", err)
	}
	b, err := report.RenderPDF(doc)
	if err != nil {
		t.Fatalf("RenderPDF (2a llamada): %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("RenderPDF no reproducible sobre el mismo informe: %d vs %d bytes", len(a), len(b))
	}
	assertLooksLikePDF(t, a)
}

// TestReportFormatPDF cubre `report <workdir> --format pdf`: re-renderiza el
// run persistido (sin re-recorrer) y produce un PDF válido. No se compara
// contra una segunda invocación de `report` por la misma razón que
// TestScanFormatPDF documenta (r.Run.FinishedAt depende de time.Now() en
// cada render); la reproducibilidad libre de reloj ya queda cubierta ahí y
// en internal/report/pdf_test.go.
func TestReportFormatPDF(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.root, "clean-pdf-report")
	if err := lab.WriteTree(target, "1.1.0"); err != nil {
		t.Fatal(err)
	}
	exit, _, stderr := h.run(t, "scan", target)
	if exit != int(ExitOKClean) {
		t.Fatalf("scan previo: exit=%d, esperaba %d; stderr=%s", exit, ExitOKClean, stderr)
	}

	exit, pdf, stderr := h.run(t, "report", h.workdir, "--format", "pdf")
	if exit != int(ExitOKClean) {
		t.Fatalf("report --format pdf: exit=%d, esperaba %d; stderr=%s", exit, ExitOKClean, stderr)
	}
	assertLooksLikePDF(t, pdf)
}

// assertLooksLikePDF ancla las dos comprobaciones mínimas de sanidad de un
// PDF emitido por stdout: cabecera %PDF- y tamaño no trivial (un documento
// vacío o truncado sería mucho más pequeño que el mínimo real observado en
// internal/report/pdf_test.go).
func assertLooksLikePDF(t *testing.T, doc []byte) {
	t.Helper()
	if !bytes.HasPrefix(doc, []byte("%PDF-")) {
		n := len(doc)
		if n > 8 {
			n = 8
		}
		t.Fatalf("stdout no empieza por %%PDF-: %q (%d bytes)", doc[:n], len(doc))
	}
	if len(doc) < 400 {
		t.Fatalf("PDF sospechosamente pequeño: %d bytes", len(doc))
	}
}
