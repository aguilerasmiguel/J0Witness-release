package cli

import (
	"encoding/json"
	"testing"
)

// T035 (US2): manipulación de versión declarada e instalaciones mixtas.
func TestScanVersionCases(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{"version-tampered", "mixed-versions"} {
		t.Run(name, func(t *testing.T) {
			r, exit, doc, stderr := h.scanCase(t, name)
			assertExpectations(t, r, exit, doc, stderr)
		})
	}
}

// US2 escenario 3: la versión real se infiere por evidencia y se usa como
// baseline, ignorando la declarada.
func TestTamperedVersionUsesInferredBaseline(t *testing.T) {
	h := newHarness(t)
	_, _, doc, _ := h.scanCase(t, "version-tampered")
	var rep struct {
		Provenance struct {
			Baseline struct {
				Version string `json:"version"`
			} `json:"baseline"`
		} `json:"provenance"`
		VersionInf struct {
			Inferred *string `json:"inferred"`
			Declared *string `json:"declared"`
		} `json:"version_inference"`
	}
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Provenance.Baseline.Version != "1.0.0" {
		t.Fatalf("el baseline debe ser la versión inferida (1.0.0), es %s", rep.Provenance.Baseline.Version)
	}
	if rep.VersionInf.Inferred == nil || *rep.VersionInf.Inferred != "1.0.0" {
		t.Fatalf("inferida: %v", rep.VersionInf.Inferred)
	}
	if rep.VersionInf.Declared == nil || *rep.VersionInf.Declared != "1.1.0" {
		t.Fatalf("declarada: %v", rep.VersionInf.Declared)
	}
}
