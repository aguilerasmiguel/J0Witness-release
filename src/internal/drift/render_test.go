package drift

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"j0witness/internal/finding"
	"j0witness/internal/inventory"
)

// fixture construye un DriftReport de ejemplo vía Compare sobre dos
// Snapshots sintéticos — evita duplicar a mano la lógica de ordenación que
// Compare ya garantiza.
func fixture(t *testing.T) DriftReport {
	t.Helper()
	old := Snapshot{
		Ref: RunRef{RunID: 1, Target: "/var/www/site", FinishedAt: "2026-01-01T00:00:00Z", ToolVersion: "0.1.0"},
		Entries: []inventory.Entry{
			ent("a.php", "AAA"),
			ent("b.php", "BBB"),
		},
		Findings: []finding.Finding{
			fnd("J0W-1", "CODE-001", "b.php", finding.High),
		},
	}
	neu := Snapshot{
		Ref: RunRef{RunID: 2, Target: "/var/www/site", FinishedAt: "2026-02-01T00:00:00Z", ToolVersion: "0.1.0"},
		Entries: []inventory.Entry{
			ent("a.php", "AAA"),
			ent("c.php", "CCC"),
		},
		Findings: []finding.Finding{
			fnd("J0W-2", "CODE-002", "c.php", finding.Critical),
		},
	}
	d, err := Compare(old, neu)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	return d
}

func TestRenderJSONDeterministic(t *testing.T) {
	d := fixture(t)

	a, err := d.RenderJSON()
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	b, err := d.RenderJSON()
	if err != nil {
		t.Fatalf("RenderJSON (2ª vez): %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("RenderJSON no es determinista:\n--- a ---\n%s\n--- b ---\n%s", a, b)
	}

	var m map[string]any
	if err := json.Unmarshal(a, &m); err != nil {
		t.Fatalf("RenderJSON no parsea como JSON: %v", err)
	}
	for _, key := range []string{"old", "new", "entries", "findings", "summary"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("RenderJSON: falta la clave %q en %v", key, m)
		}
	}
	if sv, _ := m["schema_version"].(string); sv != "1.0.0" {
		t.Fatalf("schema_version = %q, quiere 1.0.0", sv)
	}
}

func TestRenderJSONSetsSchemaVersionIfEmpty(t *testing.T) {
	d := fixture(t)
	d.SchemaVersion = ""
	out, err := d.RenderJSON()
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("no parsea: %v", err)
	}
	if sv, _ := m["schema_version"].(string); sv != "1.0.0" {
		t.Fatalf("schema_version = %q, quiere 1.0.0 tras dejarlo vacío", sv)
	}
}

func TestRenderText(t *testing.T) {
	d := fixture(t)
	out, err := d.RenderText()
	if err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	s := string(out)

	for _, want := range []string{
		"Añadidos (1)",
		"Eliminados (1)",
		"Modificados (0)",
		"Movidos (0)",
		"Metadatos (0)",
		"Churn de runtime: 0",
		"Hallazgos nuevos (1)",
		"Hallazgos resueltos (1)",
		"Persistentes: 0",
		"Salvedades",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("RenderText: falta %q en:\n%s", want, s)
		}
	}

	// paths de la deriva de ejemplo
	if !strings.Contains(s, "c.php") {
		t.Fatalf("RenderText: falta el path añadido c.php en:\n%s", s)
	}
	if !strings.Contains(s, "b.php") {
		t.Fatalf("RenderText: falta el path eliminado b.php en:\n%s", s)
	}
	// hallazgo nuevo con [sev] rule subject
	if !strings.Contains(s, "[critical] CODE-002 c.php") {
		t.Fatalf("RenderText: falta la línea de hallazgo nuevo en:\n%s", s)
	}
	// cabecera con run ids y targets
	if !strings.Contains(s, "/var/www/site") {
		t.Fatalf("RenderText: falta el target en la cabecera:\n%s", s)
	}
}

func TestRenderTextNoRuntimeChurnCaveats(t *testing.T) {
	// Sin salvedades: la sección debe seguir apareciendo (vacía) sin fallar.
	d := fixture(t)
	d.Caveats = nil
	out, err := d.RenderText()
	if err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	if !strings.Contains(string(out), "Salvedades") {
		t.Fatalf("RenderText: falta la sección Salvedades incluso vacía")
	}
}

func TestExitCode(t *testing.T) {
	d := fixture(t)
	if d.ExitCode() != 1 {
		t.Fatalf("ExitCode() = %d, quiere 1 (hay hallazgos nuevos)", d.ExitCode())
	}

	d.Findings.New = nil
	if d.ExitCode() != 0 {
		t.Fatalf("ExitCode() = %d, quiere 0 (sin hallazgos nuevos)", d.ExitCode())
	}
}
