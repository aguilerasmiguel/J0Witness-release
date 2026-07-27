package cli

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"j0witness/internal/corpus"
	"j0witness/internal/lab"

	_ "modernc.org/sqlite" // driver puro Go, sin CGO (Principio IX) — mismo que internal/inventory
)

// TestScanTamperedBaselineRefused cubre el gate BASELINE_UNTRUSTED: un
// escaneo limpio incorpora y verifica el baseline de clean-minicms
// (Principio VIII: el catálogo embebido es la única raíz de confianza), pero
// si el state.sqlite persistido se manipula tras esa incorporación —
// simulando que un atacante alteró el sha256 de paquete almacenado— el
// re-escaneo debe rechazarse en vez de confiar ciegamente en el store.
func TestScanTamperedBaselineRefused(t *testing.T) {
	h := newHarness(t)

	// Escaneo limpio inicial: el baseline (versión 1.1.0, ver
	// testdata/corpus/clean-minicms.yaml) ya fue cacheado por newHarness vía
	// `baseline add` para todas las lab.MiniVersions, así que este primer
	// escaneo debe pasar y verificar assurance=verified.
	_, exit, _, stderr := h.scanCase(t, "clean-minicms")
	if exit != 0 {
		t.Fatalf("escaneo limpio inicial: exit %d, esperaba 0\nstderr: %s", exit, stderr)
	}

	// Manipula el package_sha256 almacenado para la versión 1.1.0: ya no
	// coincide con lo que el catálogo embebido declara para esa versión, así
	// que Verify debe detectarlo como ErrUntrusted (identidad del paquete).
	tamperStoredBaselineSHA(t, h, "1.1.0")

	// Re-escanea el mismo caso: debe rechazarse antes de clasificar nada.
	_, exit, _, stderr = h.scanCase(t, "clean-minicms")
	if exit != int(ExitBaselineUntrusted) {
		t.Fatalf("baseline manipulado debe dar exit %d (BASELINE_UNTRUSTED), got %d\nstderr: %s", ExitBaselineUntrusted, exit, stderr)
	}
	if !strings.Contains(stderr, "catálogo") {
		t.Errorf("el mensaje debe declarar la discrepancia con el catálogo embebido; stderr: %s", stderr)
	}
}

// docBaselineVerification extrae únicamente el bloque baseline_verification
// del documento JSON canónico, para las aserciones de
// TestScanReportsBaselineVerification (evita acoplar el test al resto del
// documento).
type docBaselineVerification struct {
	BaselineVerification *struct {
		VerifiedAgainst string `json:"verified_against"`
		CatalogVersion  string `json:"catalog_version"`
		PackageSHA256   string `json:"package_sha256"`
		ManifestSource  string `json:"manifest_source"`
		Assurance       string `json:"assurance"`
	} `json:"baseline_verification"`
}

// TestScanReportsBaselineVerification cubre Task 3: un escaneo limpio (el
// baseline de clean-minicms fue cacheado por newHarness vía `baseline add`,
// así que resolveBaseline lo re-verifica contra el catálogo embebido y
// obtiene assurance=verified, ver TestScanTamperedBaselineRefused arriba)
// debe declarar el bloque top-level baseline_verification en el informe
// JSON — y un `report` re-render del mismo run (Principio II: derivado de la
// observación BaselineVerified persistida, sin re-verificar) debe reproducir
// el MISMO bloque, byte a byte.
func TestScanReportsBaselineVerification(t *testing.T) {
	h := newHarness(t)

	_, exit, doc, stderr := h.scanCase(t, "clean-minicms")
	if exit != 0 {
		t.Fatalf("escaneo limpio: exit %d, esperaba 0\nstderr: %s", exit, stderr)
	}

	var scanned docBaselineVerification
	if err := json.Unmarshal(doc, &scanned); err != nil {
		t.Fatalf("informe de scan no parsea: %v\n%s", err, doc)
	}
	if scanned.BaselineVerification == nil {
		t.Fatalf("baseline_verification ausente en el informe de scan:\n%s", doc)
	}
	if scanned.BaselineVerification.Assurance != "verified" {
		t.Errorf("assurance = %q, quiere \"verified\"", scanned.BaselineVerification.Assurance)
	}
	if scanned.BaselineVerification.VerifiedAgainst != "embedded-catalog" {
		t.Errorf("verified_against = %q, quiere \"embedded-catalog\"", scanned.BaselineVerification.VerifiedAgainst)
	}
	if scanned.BaselineVerification.CatalogVersion == "" {
		t.Errorf("catalog_version vacío")
	}
	if scanned.BaselineVerification.PackageSHA256 == "" {
		t.Errorf("package_sha256 vacío")
	}
	if scanned.BaselineVerification.ManifestSource == "" {
		t.Errorf("manifest_source vacío")
	}

	// El re-render (`report`) parte del inventario persistido — NO re-verifica
	// el baseline — y debe reproducir el mismo bloque desde la observación
	// BaselineVerified ya guardada.
	rendered := h.report(t)
	var reReported docBaselineVerification
	if err := json.Unmarshal(rendered, &reReported); err != nil {
		t.Fatalf("informe re-renderizado no parsea: %v\n%s", err, rendered)
	}
	if reReported.BaselineVerification == nil {
		t.Fatalf("baseline_verification ausente en el re-render:\n%s", rendered)
	}
	if *reReported.BaselineVerification != *scanned.BaselineVerification {
		t.Errorf("el re-render no reproduce el bloque: scan=%+v report=%+v",
			*scanned.BaselineVerification, *reReported.BaselineVerification)
	}
}

// TestScanEmitsBaselineAssuranceProgress cubre la mejora de la revisión final
// (Principio VII): un operador que solo mira el exit code (0/1) no ve el
// bloque baseline_verification del JSON, así que assurance=partial (paquete
// no cacheado, solo auto-consistencia) pasaría inadvertido. La línea
// `phase=baseline` a stderr hace visible el nivel de confianza en cada
// escaneo exitoso, sin depender de parsear el informe. h.run/h.scanCase
// siempre añaden --quiet (harness_test.go), así que este test invoca `Main`
// directamente, sin esa bandera, reusando el catálogo y el caché ya
// poblados por newHarness.
func TestScanEmitsBaselineAssuranceProgress(t *testing.T) {
	h := newHarness(t)
	r, err := corpus.Load(filepath.Join(recipesDir(t), "clean-minicms.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(h.root, "case-progress-"+r.Case)
	if err := r.Materialize(lab.MiniProvider{}, target); err != nil {
		t.Fatal(err)
	}
	h.cacheExtensionBaselines(t, r, target)

	var stdout, stderr bytes.Buffer
	exit := Main([]string{"scan", target,
		"--workdir", h.workdir, "--cache-dir", h.cacheDir, "--catalog", h.catalog,
	}, &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("escaneo limpio: exit %d, esperaba 0\nstderr: %s", exit, stderr.String())
	}
	msg := stderr.String()
	if !strings.Contains(msg, "phase=baseline") || !strings.Contains(msg, "assurance=verified") {
		t.Errorf("stderr debe declarar la assurance del baseline (phase=baseline … assurance=verified); stderr: %s", msg)
	}
	if !strings.Contains(msg, "verified_against=embedded-catalog") {
		t.Errorf("stderr debe declarar verified_against=embedded-catalog; stderr: %s", msg)
	}
}

// tamperStoredBaselineSHA abre el state.sqlite del harness (el mismo
// almacén que openStateStore/store.FindBaseline leen) y corrompe el
// package_sha256 registrado para `version`, simulando un state.sqlite
// manipulado tras `baseline add`.
func tamperStoredBaselineSHA(t *testing.T, h *harness, version string) {
	t.Helper()
	dbPath := filepath.Join(h.workdir, "state.sqlite")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("abriendo %s: %v", dbPath, err)
	}
	defer db.Close()
	res, err := db.Exec(`UPDATE baselines SET package_sha256 = ? WHERE cms = 'joomla' AND version = ?`,
		strings.Repeat("d", 64), version)
	if err != nil {
		t.Fatalf("tamperando baseline %s: %v", version, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		t.Fatalf("rows affected: %v", err)
	}
	if n == 0 {
		t.Fatalf("no había fila de baseline para version=%s en %s (tamper no-op)", version, dbPath)
	}
}
