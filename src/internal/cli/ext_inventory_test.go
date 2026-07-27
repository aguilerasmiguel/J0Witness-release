package cli

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"j0witness/internal/lab"
)

// T125 (SC-104): sin extensiones de terceros, el informe es idéntico al de la
// 001 salvo schema_version (1.13.0), extensions:[] y attribution en cero. Nada
// de regresión.
func TestNoRegressionWithoutExtensions(t *testing.T) {
	h := newHarness(t)
	r, exit, doc, stderr := h.scanCase(t, "clean-minicms")
	assertExpectations(t, r, exit, doc, stderr)

	var rep struct {
		SchemaVersion string        `json:"schema_version"`
		Extensions    []interface{} `json:"extensions"`
		Coverage      struct {
			Attribution struct {
				FilesAttributed      int  `json:"files_attributed"`
				ThirdPartyExtensions int  `json:"third_party_extensions"`
				IntegrityVerified    bool `json:"integrity_verified"`
			} `json:"attribution"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.SchemaVersion != "1.13.0" {
		t.Fatalf("schema_version: %s", rep.SchemaVersion)
	}
	if len(rep.Extensions) != 0 {
		t.Fatalf("un sitio sin extensiones de terceros debe tener extensions vacío: %v", rep.Extensions)
	}
	if rep.Coverage.Attribution.FilesAttributed != 0 || rep.Coverage.Attribution.ThirdPartyExtensions != 0 {
		t.Fatalf("atribución debe estar en cero: %+v", rep.Coverage.Attribution)
	}
}

// T125: determinismo — dos escaneos con extensión → informes byte-idénticos
// salvo run.
func TestExtDeterminism(t *testing.T) {
	h := newHarness(t)
	r, _, doc1, _ := h.scanCase(t, "ext-legit")
	target := filepath.Join(h.root, "case-"+r.Case)
	_, doc2, _ := h.run(t, "scan", target)
	m1, m2 := stripRun(t, doc1), stripRun(t, doc2)
	if !reflect.DeepEqual(m1, m2) {
		t.Fatalf("informes con extensión difieren fuera de run:\n1:%s\n2:%s", doc1, doc2)
	}
}

// T121 (SC-103): inventario con varias extensiones, orden estable por
// manifest_path.
func TestMultipleExtensionsInventory(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.root, "multiext")
	if err := lab.WriteTree(target, "1.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := lab.InstallLabExt(target); err != nil {
		t.Fatal(err)
	}
	// Segunda extensión: un módulo sintético con su manifiesto.
	writeFile(t, filepath.Join(target, "modules/mod_labmod/mod_labmod.xml"),
		`<extension type="module"><name>mod_labmod</name><version>1.0</version><author>Lab</author><files><filename>mod_labmod.php</filename></files></extension>`)
	writeFile(t, filepath.Join(target, "modules/mod_labmod/mod_labmod.php"), "<?php // mod")

	exit, doc, stderr := h.run(t, "scan", target)
	if exit > 1 {
		t.Fatalf("scan multiext falló: %d\n%s", exit, stderr)
	}
	var rep struct {
		Extensions []struct {
			Name         string `json:"name"`
			ManifestPath string `json:"manifest_path"`
		} `json:"extensions"`
		Coverage struct {
			ExtensionVerification *struct {
				ExtensionsVerifiable   int `json:"extensions_verifiable"`
				ExtensionsVerified     int `json:"extensions_verified"`
				ExtensionsUnverifiable int `json:"extensions_unverifiable"`
				FilesModified          int `json:"files_modified"`
			} `json:"extension_verification"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Extensions) != 2 {
		t.Fatalf("esperaba 2 extensiones, hay %d: %+v", len(rep.Extensions), rep.Extensions)
	}
	// Orden estable por manifest_path.
	if rep.Extensions[0].ManifestPath > rep.Extensions[1].ManifestPath {
		t.Fatalf("inventario no ordenado por manifest_path: %+v", rep.Extensions)
	}
	// Fase 2c: extmap.VerifyExtensions ya verifica los 5 tipos con clave de
	// elemento estable (incluido module), así que las 2 extensiones (1
	// componente + 1 módulo, sin baseline cacheado para ninguno) cuentan como
	// verificables y ninguna se pudo verificar.
	ev := rep.Coverage.ExtensionVerification
	if ev == nil {
		t.Fatal("esperaba coverage.extension_verification")
	}
	if ev.ExtensionsVerifiable != 2 {
		t.Fatalf("extensions_verifiable = %d, quiere 2 (componente + módulo): %+v", ev.ExtensionsVerifiable, ev)
	}
	if ev.ExtensionsUnverifiable != 2 {
		t.Fatalf("extensions_unverifiable = %d, quiere 2 (ninguna con baseline cacheado): %+v", ev.ExtensionsUnverifiable, ev)
	}
	if ev.ExtensionsVerified != 0 {
		t.Fatalf("extensions_verified = %d, quiere 0 (sin baseline cacheado): %+v", ev.ExtensionsVerified, ev)
	}
}

// La red declara los ejecutables atribuidos sin verificarlos (schema 1.3.0).
func TestUnverifiedExecutablesDisclosed(t *testing.T) {
	h := newHarness(t)
	_, _, doc, _ := h.scanCase(t, "ext-exec-atribuido")
	var rep struct {
		Coverage struct {
			Attribution struct {
				Unverified *struct {
					Count int `json:"count"`
					Files []struct {
						Path      string `json:"path"`
						Extension string `json:"extension"`
					} `json:"files"`
				} `json:"unverified_executables"`
			} `json:"attribution"`
		} `json:"coverage"`
		Summary struct {
			Unverified int `json:"unverified_executables"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatal(err)
	}
	u := rep.Coverage.Attribution.Unverified
	if u == nil || u.Count == 0 {
		t.Fatalf("la red no declaró ningún ejecutable atribuido: %s", doc)
	}
	found := false
	for _, f := range u.Files {
		if f.Path == "components/com_labext/router.php" {
			found = true
		}
	}
	if !found {
		t.Fatalf("router.php no aparece en unverified_executables: %s", doc)
	}
	if rep.Summary.Unverified != u.Count {
		t.Fatalf("summary=%d no coincide con el bloque=%d", rep.Summary.Unverified, u.Count)
	}
}
