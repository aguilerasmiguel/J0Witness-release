package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// componentManifestXML es el manifiesto mínimo que buildComponentPackage
// escribe TANTO en el paquete oficial como (idéntico) en el árbol instalado,
// para que `extension add` pueda localizar el componente ya instalado
// (readInstalledExtension) antes de cachear su baseline.
func componentManifestXML(element, version string) string {
	return `<?xml version="1.0"?>
<extension type="component">
	<name>Lab Ext</name>
	<version>` + version + `</version>
	<files folder="site"><filename>router.php</filename></files>
	<administration><files folder="admin"><filename>` + element + `.php</filename></files></administration>
</extension>`
}

// buildComponentPackage arma un paquete de componente sintético mínimo (como
// en internal/extbaseline/simulate_test.go) y lo escribe en disco, devolviendo
// su ruta. Sirve para ejercitar `extension add` de punta a punta sin depender
// de un paquete real.
func buildComponentPackage(t *testing.T, dir, element, version string) string {
	t.Helper()
	files := map[string]string{
		element + ".xml":            componentManifestXML(element, version),
		"site/router.php":           "<?php // router\n",
		"admin/" + element + ".php": "<?php // admin\n",
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, element+"_"+version+".zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// installComponentTree escribe, bajo root, el árbol instalado mínimo que
// readInstalledExtension necesita para localizar element: el manifiesto en
// administrator/components/<element>/<element>.xml (idéntico al que trae el
// paquete de buildComponentPackage) más los archivos que declara, para que
// SimulateExtension/scan también encuentren un árbol coherente si lo escanean.
func installComponentTree(t *testing.T, root, element, version string) string {
	t.Helper()
	files := map[string]string{
		"administrator/components/" + element + "/" + element + ".xml": componentManifestXML(element, version),
		"components/" + element + "/router.php":                        "<?php // router\n",
		"administrator/components/" + element + "/" + element + ".php": "<?php // admin\n",
	}
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestExtensionAddAndList (Task 3, fase 2a): `extension add` cachea el
// baseline de un componente desde su paquete oficial, y `extension list` lo
// refleja en el listado JSON de stdout.
func TestExtensionAddAndList(t *testing.T) {
	h := newHarness(t)
	pkg := buildComponentPackage(t, h.root, "com_labext", "2.3.1")
	site := installComponentTree(t, filepath.Join(h.root, "add-list-site"), "com_labext", "2.3.1")

	exit, doc, stderr := h.run(t, "extension", "add", "com_labext", site, pkg)
	if exit != 0 {
		t.Fatalf("extension add: exit %d\n%s", exit, stderr)
	}
	var added struct {
		Added   string `json:"added"`
		Version string `json:"version"`
		Files   int    `json:"files"`
	}
	if err := json.Unmarshal(doc, &added); err != nil {
		t.Fatalf("extension add: salida no parsea: %v\n%s", err, doc)
	}
	if added.Added != "com_labext" || added.Version != "2.3.1" || added.Files == 0 {
		t.Fatalf("extension add: salida inesperada: %+v", added)
	}

	exit, doc, stderr = h.run(t, "extension", "list")
	if exit != 0 {
		t.Fatalf("extension list: exit %d\n%s", exit, stderr)
	}
	var listed struct {
		ExtensionBaselines []struct {
			Element string `json:"element"`
			Version string `json:"version"`
			Source  string `json:"source"`
		} `json:"extension_baselines"`
	}
	if err := json.Unmarshal(doc, &listed); err != nil {
		t.Fatalf("extension list: salida no parsea: %v\n%s", err, doc)
	}
	found := false
	for _, row := range listed.ExtensionBaselines {
		if row.Element == "com_labext" && row.Version == "2.3.1" {
			if row.Source != "package" {
				t.Errorf("extension list: source=%q, esperaba 'package'", row.Source)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("extension list: falta com_labext 2.3.1 en %+v", listed.ExtensionBaselines)
	}

	// Comprueba directamente contra el store que el manifiesto quedó
	// persistido con sus archivos (roundtrip Add → store).
	store, err := openStateStore(&App{Flags: GlobalFlags{Workdir: h.workdir}})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id, pkgSHA, source, err := store.FindExtensionBaseline("com_labext", "2.3.1")
	if err != nil {
		t.Fatalf("FindExtensionBaseline: %v", err)
	}
	if source != "package" || pkgSHA == "" {
		t.Fatalf("FindExtensionBaseline: source=%q pkgSHA=%q", source, pkgSHA)
	}
	files, err := store.ExtensionBaselineFiles(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("ExtensionBaselineFiles: manifiesto vacío")
	}
}
