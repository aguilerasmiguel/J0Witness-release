package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"j0witness/internal/lab"
)

// TestDiffAddedEntry cubre el camino feliz de `diff` en modo monitorización
// (feature 002, Task 4): dos scans consecutivos del MISMO objetivo, el
// segundo con un archivo nuevo, y `diff <objetivo> --format json` refleja
// exactamente ese archivo en entries.added — nada más (Principio IV:
// determinismo, sin deriva espuria entre árboles casi idénticos).
func TestDiffAddedEntry(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.root, "diff-added")
	if err := lab.WriteTree(target, "1.1.0"); err != nil {
		t.Fatal(err)
	}

	exit, _, stderr := h.run(t, "scan", target)
	if exit != int(ExitOKClean) {
		t.Fatalf("1er scan: exit=%d, esperaba %d; stderr=%s", exit, ExitOKClean, stderr)
	}

	// Muta: añade un archivo nuevo bajo un directorio NUEVO ("uploads/", que
	// no pertenece al manifest ni a los directorios de escritura conocidos —
	// corediff.IsWritablePath) antes del 2º scan. Ni la raíz (in_core_dir=true,
	// dispara J0W-CORE-004) ni images/ (writableDirs, se segregaría como
	// runtime_churn en el diff) sirven aquí: "uploads/" cae fuera de ambos, así
	// que el 2º scan sigue limpio (contenido de usuario fuera del core, sin
	// hallazgo) y el diff lo cuenta en entries.added, no en runtime_churn.
	if err := os.MkdirAll(filepath.Join(target, "uploads"), 0o755); err != nil {
		t.Fatal(err)
	}
	newFile := filepath.Join(target, "uploads", "extra-upload.txt")
	if err := os.WriteFile(newFile, []byte("contenido nuevo, benigno\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	exit, _, stderr = h.run(t, "scan", target)
	if exit != int(ExitOKClean) {
		t.Fatalf("2º scan: exit=%d, esperaba %d; stderr=%s", exit, ExitOKClean, stderr)
	}

	exit, out, stderr := h.run(t, "diff", target, "--format", "json")
	if exit != int(ExitOKClean) {
		t.Fatalf("diff: exit=%d, esperaba %d (OK_CLEAN, sin hallazgos nuevos); stderr=%s\nsalida=%s", exit, ExitOKClean, stderr, out)
	}

	var dr struct {
		Entries struct {
			Added []struct {
				Path string `json:"path"`
			} `json:"added"`
			Removed []json.RawMessage `json:"removed"`
			Changed []json.RawMessage `json:"changed"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(out, &dr); err != nil {
		t.Fatalf("diff --format json no parsea: %v\n%s", err, out)
	}
	if len(dr.Entries.Added) != 1 {
		t.Fatalf("entries.added tiene %d elementos, esperaba 1: %s", len(dr.Entries.Added), out)
	}
	if got := dr.Entries.Added[0].Path; got != "uploads/extra-upload.txt" {
		t.Fatalf("entries.added[0].path=%q, esperaba %q", got, "uploads/extra-upload.txt")
	}
	if len(dr.Entries.Removed) != 0 {
		t.Fatalf("entries.removed no vacío: %s", out)
	}
	if len(dr.Entries.Changed) != 0 {
		t.Fatalf("entries.changed no vacío (deriva espuria entre escaneos casi idénticos): %s", out)
	}
}

// TestRunsListsBothRuns cubre `runs <objetivo>`: tras dos scans del mismo
// objetivo, lista los 2 runs de análisis persistidos.
func TestRunsListsBothRuns(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.root, "runs-list")
	if err := lab.WriteTree(target, "1.1.0"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		exit, _, stderr := h.run(t, "scan", target)
		if exit != int(ExitOKClean) {
			t.Fatalf("scan #%d: exit=%d, esperaba %d; stderr=%s", i+1, exit, ExitOKClean, stderr)
		}
	}
	exit, out, stderr := h.run(t, "runs", target)
	if exit != int(ExitOKClean) {
		t.Fatalf("runs: exit=%d, esperaba %d; stderr=%s", exit, ExitOKClean, stderr)
	}
	lines := splitNonEmptyLines(string(out))
	if len(lines) != 2 {
		t.Fatalf("runs listó %d líneas, esperaba 2:\n%s", len(lines), out)
	}
}

func splitNonEmptyLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// TestDiffTargetMismatch cubre el modo IR (`--old`/`--new`): dos stores de
// objetivos DISTINTOS producen un error de guarda (drift.Compare), mapeado a
// USAGE_ERROR — nunca se compara deriva entre objetivos diferentes.
func TestDiffTargetMismatch(t *testing.T) {
	h := newHarness(t)
	targetA := filepath.Join(h.root, "ir-target-a")
	targetB := filepath.Join(h.root, "ir-target-b")
	if err := lab.WriteTree(targetA, "1.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := lab.WriteTree(targetB, "1.1.0"); err != nil {
		t.Fatal(err)
	}

	exit, _, stderr := h.run(t, "scan", targetA)
	if exit != int(ExitOKClean) {
		t.Fatalf("scan targetA: exit=%d, esperaba %d; stderr=%s", exit, ExitOKClean, stderr)
	}
	exit, _, stderr = h.run(t, "scan", targetB)
	if exit != int(ExitOKClean) {
		t.Fatalf("scan targetB: exit=%d, esperaba %d; stderr=%s", exit, ExitOKClean, stderr)
	}

	dbA := invDBPath(&App{Flags: GlobalFlags{Workdir: h.workdir}}, mustAbs(t, targetA))
	dbB := invDBPath(&App{Flags: GlobalFlags{Workdir: h.workdir}}, mustAbs(t, targetB))

	exit, out, stderr := h.run(t, "diff", "--old", dbA, "--new", dbB, "--format", "json")
	if exit != int(ExitUsageError) {
		t.Fatalf("diff --old/--new objetivos distintos: exit=%d, esperaba %d (USAGE_ERROR); stdout=%s stderr=%s", exit, ExitUsageError, out, stderr)
	}
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}
