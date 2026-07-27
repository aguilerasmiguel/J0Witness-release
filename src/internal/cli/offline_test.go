package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"j0witness/internal/lab"
)

// T047 (US3-2): sin baseline en caché, falla explícita con exit 4 indicando
// qué falta y cómo obtenerlo; stdout queda vacío (nada de informes parciales).
func TestScanWithoutBaselineFailsExplicitly(t *testing.T) {
	root := t.TempDir()
	cat, err := lab.WriteCatalog(root)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "site")
	if err := lab.WriteTree(target, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exit := Main([]string{"scan", target,
		"--workdir", filepath.Join(root, "state"),
		"--cache-dir", filepath.Join(root, "cache"),
		"--catalog", cat, "--quiet"}, &stdout, &stderr)
	if exit != int(ExitBaselineUnavailable) {
		t.Fatalf("exit %d, esperaba 4\n%s", exit, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout debe quedar vacío sin baseline, hay: %s", stdout.String())
	}
	msg := stderr.String()
	for _, want := range []string{"1.0.0", "baseline add"} {
		if !strings.Contains(msg, want) {
			t.Errorf("el error no indica %q: %s", want, msg)
		}
	}
}

// T047/T049 (FR-023): fetch sin --allow-network no toca la red y termina con
// exit 4 e instrucciones de obtención manual.
func TestFetchWithoutNetworkAuthorization(t *testing.T) {
	root := t.TempDir()
	cat, err := lab.WriteCatalog(root)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exit := Main([]string{"baseline", "fetch", "1.0.0",
		"--workdir", filepath.Join(root, "state"),
		"--cache-dir", filepath.Join(root, "cache"),
		"--catalog", cat, "--quiet"}, &stdout, &stderr)
	if exit != int(ExitBaselineUnavailable) {
		t.Fatalf("exit %d, esperaba 4\n%s", exit, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--allow-network") {
		t.Errorf("el error no menciona --allow-network: %s", stderr.String())
	}
	if strings.Contains(stderr.String(), "network-fetch") {
		t.Error("se enumeró una descarga sin autorización: el cliente no debe construirse")
	}
}

// T040/FR-014 (C3): múltiples instalaciones → exit 5 con listado en stderr.
func TestMultipleRootsExplicitFailure(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.root, "multi")
	if err := lab.WriteTree(target, "1.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := lab.WriteTree(filepath.Join(target, "blog"), "1.0.0"); err != nil {
		t.Fatal(err)
	}
	exit, stdout, stderr := h.run(t, "scan", target)
	if exit != int(ExitMultipleRoots) {
		t.Fatalf("exit %d, esperaba 5\n%s", exit, stderr)
	}
	if len(stdout) != 0 {
		t.Fatal("no debe emitirse informe con múltiples raíces")
	}
	if !strings.Contains(stderr, "raiz-detectada") || !strings.Contains(stderr, "blog") {
		t.Fatalf("el listado de raíces falta en stderr: %s", stderr)
	}
}

// T031 (FR-045): supresión declarativa con motivo, reflejada en el informe.
func TestSuppressions(t *testing.T) {
	h := newHarness(t)
	r, _, _, _ := h.scanCase(t, "core-replaced-file")
	target := filepath.Join(h.root, "case-"+r.Case)

	excl := filepath.Join(h.root, "excl.yaml")
	writeFile(t, excl, `- rule: J0W-CORE-001
  path: "libraries/src/*"
  reason: "override aprobado por el desarrollador el 2026-07-01"
`)
	exit, doc, stderr := h.run(t, "scan", target, "--exclusions", excl)
	if exit != 0 {
		t.Fatalf("con el hallazgo suprimido el exit debe ser 0, es %d\n%s\n%s", exit, stderr, doc)
	}
	if !strings.Contains(string(doc), `"suppressions_applied"`) || !strings.Contains(string(doc), "override aprobado") {
		t.Fatal("la supresión no queda reflejada en el informe")
	}

	// Sin motivo → rechazo del archivo entero.
	writeFile(t, excl, `- rule: J0W-CORE-001
  path: "*"
  reason: ""
`)
	exit, _, stderr = h.run(t, "scan", target, "--exclusions", excl)
	if exit != int(ExitUsageError) {
		t.Fatalf("exclusión sin motivo debe rechazarse (exit 2), es %d\n%s", exit, stderr)
	}
}
