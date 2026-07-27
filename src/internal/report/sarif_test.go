package report

import (
	"encoding/json"
	"strings"
	"testing"

	"j0witness/internal/finding"
	"j0witness/internal/i18n"
	"j0witness/internal/observe"
)

func TestRenderSARIFDeterministic(t *testing.T) {
	_, doc, err := Build(textFixtureInput(i18n.ES))
	if err != nil {
		t.Fatal(err)
	}
	a, err := RenderSARIF(doc)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RenderSARIF(doc)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("RenderSARIF no determinista")
	}
}

func TestRenderSARIFShape(t *testing.T) {
	_, doc, err := Build(textFixtureInput(i18n.ES))
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderSARIF(doc)
	if err != nil {
		t.Fatal(err)
	}
	var log map[string]any
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatalf("SARIF no parsea: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Fatalf("version = %v", log["version"])
	}
	if _, ok := log["$schema"]; !ok {
		t.Fatal("falta $schema")
	}
	runs, ok := log["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %v", log["runs"])
	}
	run := runs[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "J0Witness" {
		t.Fatalf("driver.name = %v", driver["name"])
	}
	if _, ok := driver["rules"].([]any); !ok {
		t.Fatal("faltan rules")
	}
	results := run["results"].([]any)
	if len(results) == 0 {
		t.Fatal("sin results")
	}
	r0 := results[0].(map[string]any)
	for _, k := range []string{"ruleId", "level", "message", "locations", "partialFingerprints"} {
		if _, ok := r0[k]; !ok {
			t.Errorf("result sin %q", k)
		}
	}
	if r0["message"].(map[string]any)["text"] == "" {
		t.Error("message.text vacío")
	}
	// el fixture es CORE-001 high → level error
	if r0["level"] != "error" {
		t.Errorf("level = %v (esperado error para high)", r0["level"])
	}
}

func TestRenderSARIFLevelMapping(t *testing.T) {
	cases := map[string]string{"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
	for sev, want := range cases {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%q) = %q, want %q", sev, got, want)
		}
	}
}

// TestRenderSARIFCodeLine: un finding J0W-CODE con evidence.line produce
// locations[0].physicalLocation.region.startLine.
func TestRenderSARIFCodeLine(t *testing.T) {
	in := textFixtureInput(i18n.ES)
	in.Findings = []finding.Finding{{
		ID: "abc123", RuleID: "J0W-CODE-003", Subject: "components/com_x/evil.php",
		Severity: finding.High, BaseSeverity: finding.High, Confidence: observe.High,
		Observed: "preg_replace con /e", ComparedTo: "técnica de backdoor clásica",
		Rationale: "el modificador /e ejecuta como PHP", Evidence: map[string]any{"line": 42},
	}}
	_, doc, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderSARIF(doc)
	if err != nil {
		t.Fatal(err)
	}
	var log map[string]any
	json.Unmarshal(out, &log)
	res := log["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	loc := res["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	region, ok := loc["region"].(map[string]any)
	if !ok {
		t.Fatal("falta region para finding CODE con line")
	}
	if region["startLine"].(float64) != 42 {
		t.Errorf("startLine = %v", region["startLine"])
	}
}

// TestRenderSARIFEnglishNoSpanish: con language en, el SARIF no lleva conectores
// ni prosa en español introducidos por el renderizador (message une prosa ya
// traducida con puntuación neutra; alternativa va a properties).
func TestRenderSARIFEnglishNoSpanish(t *testing.T) {
	_, doc, err := Build(textFixtureInput(i18n.EN))
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderSARIF(doc)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, bad := range []string{"Hipótesis", "hipótesis alternativa", "distribución", "archivo del core"} {
		if strings.Contains(s, bad) {
			t.Errorf("SARIF en inglés contiene español: %q", bad)
		}
	}
}
