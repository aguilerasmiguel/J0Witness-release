package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"j0witness/internal/corpus"
	"j0witness/internal/lab"
)

// harness prepara catálogo, caché con ambos baselines y directorios de estado
// para tests de integración de la CLI.
type harness struct {
	catalog  string
	workdir  string
	cacheDir string
	root     string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	h := &harness{
		workdir:  filepath.Join(root, "state"),
		cacheDir: filepath.Join(root, "cache"),
		root:     root,
	}
	cat, err := lab.WriteCatalog(root)
	if err != nil {
		t.Fatal(err)
	}
	h.catalog = cat
	for _, v := range lab.MiniVersions {
		pkg, err := lab.WritePackage(root, v)
		if err != nil {
			t.Fatal(err)
		}
		exit, _, stderr := h.run(t, "baseline", "add", pkg)
		if exit != 0 {
			t.Fatalf("baseline add %s: exit %d\n%s", v, exit, stderr)
		}
	}
	return h
}

// run ejecuta la CLI con las banderas de estado del harness.
func (h *harness) run(t *testing.T, args ...string) (int, []byte, string) {
	t.Helper()
	full := append(args,
		"--workdir", h.workdir,
		"--cache-dir", h.cacheDir,
		"--catalog", h.catalog,
		"--quiet",
	)
	var stdout, stderr bytes.Buffer
	exit := Main(full, &stdout, &stderr)
	return exit, stdout.Bytes(), stderr.String()
}

// scanCase materializa una receta del corpus y la escanea.
func (h *harness) scanCase(t *testing.T, recipeName string) (*corpus.Recipe, int, []byte, string) {
	t.Helper()
	r, err := corpus.Load(filepath.Join(recipesDir(t), recipeName+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(h.root, "case-"+r.Case)
	if err := r.Materialize(lab.MiniProvider{}, target); err != nil {
		t.Fatal(err)
	}
	h.cacheExtensionBaselines(t, r, target)
	args := append([]string{"scan", target}, r.ScanArgs...)
	exit, doc, stderr := h.run(t, args...)
	return r, exit, doc, stderr
}

// cacheExtensionBaselines es el gancho de `add_extension_baseline` (fase 2a,
// Task 6; firma de `add` generalizada en fase 2c, Task 4): Materialize
// (internal/corpus) solo escribe el árbol del caso y no conoce el store de
// estado de la CLI, así que el cacheo real del baseline vive aquí, en el
// harness. Tras materializar el caso en site, recorre sus mutations buscando
// `add_extension_baseline`; por cada una, construye el "paquete oficial"
// (lab.MiniProvider.ExtPackage, con override de versión si la mutation lo
// declara), lo escribe en un archivo temporal y ejecuta
// `extension add com_labext <site> <paquete>` a través de la CLI real — la
// MISMA ruta que un operador seguiría — que localiza com_labext YA instalado
// en site (readInstalledExtension) y abre openStateStore(app), es decir
// `<h.workdir>/state.sqlite`: el mismo store que `scan` abrirá para verificar
// extensiones. Así el caché queda poblado ANTES del escaneo, en el store
// correcto, sin que corpus.apply() necesite conocer el concepto de store.
//
// El paquete puede declarar una versión distinta a la instalada en site
// (recipe "versión no coincidente", ver ext-version-mismatch.yaml): `add` no
// lo rechaza, cachea bajo la versión que el PAQUETE declara (Principio VI: es
// el operador quien avala el paquete, no un gate automático).
//
// m.Kind generaliza esto a los 5 tipos verificables (fase 2c, Task 7): ""/
// "component" resuelve exactamente igual que antes (lab.LabExtName +
// MiniProvider.ExtPackage); cualquier otro kind resuelve el elemento y el
// paquete vía lab.MiniProvider.ElementKeyKind/ExtPackageKind. El resto del
// mecanismo (escribir el zip a un temporal y llamar `extension add` por la
// CLI real) es idéntico para todos los tipos: readInstalledExtension localiza
// el manifiesto instalado por su ElementKey (com_x, mod_x, grupo/elemento,
// nombre de plantilla o libraryname), así que un solo camino de harness sirve
// para todos sin necesitar --group/--client (los fixtures de laboratorio no
// tienen homónimos que desambiguar dentro de un mismo caso).
func (h *harness) cacheExtensionBaselines(t *testing.T, r *corpus.Recipe, site string) {
	t.Helper()
	for _, m := range r.Mutations {
		if m.Op != "add_extension_baseline" {
			continue
		}
		element := lab.MiniProvider{}.ElementKeyKind(m.Kind)
		pkg, err := lab.MiniProvider{}.ExtPackageKind(m.Kind, m.Version)
		if err != nil {
			t.Fatalf("caso %s: paquete de baseline: %v", r.Case, err)
		}
		pkgPath := filepath.Join(t.TempDir(), "ext-baseline.zip")
		if err := os.WriteFile(pkgPath, pkg, 0o644); err != nil {
			t.Fatalf("caso %s: escribiendo paquete de baseline: %v", r.Case, err)
		}
		exit, _, stderr := h.run(t, "extension", "add", element, site, pkgPath)
		if exit != 0 {
			t.Fatalf("caso %s: extension add %s: exit %d\n%s", r.Case, element, exit, stderr)
		}
	}
}

// scanCaseArgs es scanCase con banderas extra para `scan` (p.ej. --db <dump>):
// usado por los tests de correlación con BD (feature 011, capa L7), que
// necesitan aportar un dump sin tocar la receta del corpus.
func (h *harness) scanCaseArgs(t *testing.T, recipeName string, extra ...string) (*corpus.Recipe, int, []byte, string) {
	t.Helper()
	r, err := corpus.Load(filepath.Join(recipesDir(t), recipeName+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(h.root, "case-"+r.Case)
	if err := r.Materialize(lab.MiniProvider{}, target); err != nil {
		t.Fatal(err)
	}
	h.cacheExtensionBaselines(t, r, target)
	args := append([]string{"scan", target}, r.ScanArgs...)
	args = append(args, extra...)
	exit, doc, stderr := h.run(t, args...)
	return r, exit, doc, stderr
}

// report ejecuta `j0witness report` sobre el workdir del harness (re-render
// desde el inventario persistido, sin re-recorrer) con las banderas extra
// dadas (p.ej. --format json). Devuelve solo el documento: los tests que la
// usan solo necesitan comprobar contenido, no exit/stderr.
func (h *harness) report(t *testing.T, extra ...string) []byte {
	t.Helper()
	args := append([]string{"report", h.workdir}, extra...)
	_, doc, _ := h.run(t, args...)
	return doc
}

func recipesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "..", "..", "testdata", "corpus")
}

// parsedReport extrae lo necesario para las aserciones.
type parsedReport struct {
	Findings []struct {
		ID       string `json:"id"`
		RuleID   string `json:"rule_id"`
		Subject  string `json:"subject"`
		Severity string `json:"severity"`
	} `json:"findings"`
	Summary struct {
		ExitCode int `json:"exit_code"`
	} `json:"summary"`
}

func parseReport(t *testing.T, doc []byte) parsedReport {
	t.Helper()
	var p parsedReport
	if err := json.Unmarshal(doc, &p); err != nil {
		t.Fatalf("informe no parsea: %v\n%s", err, doc)
	}
	return p
}

var sevRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// assertExpectations valida exit code, hallazgos esperados y prohibidos.
func assertExpectations(t *testing.T, r *corpus.Recipe, exit int, doc []byte, stderr string) {
	t.Helper()
	if exit != r.Expect.ExitCode {
		t.Fatalf("caso %s: exit %d, esperaba %d\nstderr: %s\ninforme: %s", r.Case, exit, r.Expect.ExitCode, stderr, doc)
	}
	p := parseReport(t, doc)
	for _, want := range r.Expect.Findings {
		if !hasFinding(p, want.RuleID, want.Subject, want.MinSeverity) {
			t.Errorf("caso %s: falta hallazgo %s %s (>=%s)\ninforme: %s", r.Case, want.RuleID, want.Subject, want.MinSeverity, doc)
			continue
		}
		if want.MaxSeverity != "" && exceedsMax(p, want.RuleID, want.Subject, want.MaxSeverity) {
			t.Errorf("caso %s: hallazgo %s %s supera la cota %s (degradación esperada, Principio VI)\ninforme: %s", r.Case, want.RuleID, want.Subject, want.MaxSeverity, doc)
		}
	}
	for _, ban := range r.Expect.NotFindings {
		if hasFinding(p, ban.RuleID, ban.Subject, "") {
			t.Errorf("caso %s: hallazgo prohibido %s %s presente (falso positivo, Principio VI)", r.Case, ban.RuleID, ban.Subject)
		}
	}
}

func hasFinding(p parsedReport, rule, subject, minSev string) bool {
	for _, f := range p.Findings {
		if f.RuleID != rule {
			continue
		}
		if subject != "" && f.Subject != subject {
			continue
		}
		if minSev != "" && sevRank[f.Severity] < sevRank[minSev] {
			continue
		}
		return true
	}
	return false
}

// exceedsMax informa de si existe un hallazgo (rule, subject) cuya severidad
// supera maxSev: sirve para afirmar que una degradación ocurrió.
func exceedsMax(p parsedReport, rule, subject, maxSev string) bool {
	for _, f := range p.Findings {
		if f.RuleID != rule {
			continue
		}
		if subject != "" && f.Subject != subject {
			continue
		}
		if sevRank[f.Severity] > sevRank[maxSev] {
			return true
		}
	}
	return false
}
