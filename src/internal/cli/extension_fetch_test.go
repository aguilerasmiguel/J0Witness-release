package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"j0witness/internal/lab"
)

// buildZipBytes arma en memoria el zip de un paquete a partir de sus
// entradas, en orden determinista de nombre (Principio IV).
func buildZipBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range names {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(files[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// withUpdateServerBlock inserta un <updateservers><server>updateURL</server>
// </updateservers> justo antes de </extension> en un manifiesto XML, sin
// tocar el resto de su contenido.
func withUpdateServerBlock(t *testing.T, manifestXML, updateURL string) string {
	t.Helper()
	block := fmt.Sprintf("\t<updateservers>\n\t\t<server type=\"extension\" priority=\"1\" name=\"Lab Update Site\">%s</server>\n\t</updateservers>\n</extension>", updateURL)
	out := strings.Replace(manifestXML, "</extension>", block, 1)
	if out == manifestXML {
		t.Fatal("no se pudo insertar <updateservers> en el manifiesto")
	}
	return out
}

// readZipEntry extrae el contenido de una entrada de un paquete zip en memoria.
func readZipEntry(t *testing.T, pkg []byte, name string) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		t.Fatalf("abriendo paquete: %v", err)
	}
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("abriendo %s del paquete: %v", name, err)
		}
		defer rc.Close()
		b, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("leyendo %s del paquete: %v", name, err)
		}
		return b
	}
	t.Fatalf("el paquete no contiene %s", name)
	return nil
}

// replaceZipEntry reconstruye un paquete zip sustituyendo el contenido de una
// entrada, dejando el resto byte a byte igual.
func replaceZipEntry(t *testing.T, pkg []byte, name string, newContent []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		t.Fatalf("abriendo paquete: %v", err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		w, err := zw.Create(f.Name)
		if err != nil {
			t.Fatalf("recreando %s: %v", f.Name, err)
		}
		if f.Name == name {
			if _, err := w.Write(newContent); err != nil {
				t.Fatalf("escribiendo %s: %v", f.Name, err)
			}
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("abriendo %s: %v", f.Name, err)
		}
		if _, err := io.Copy(w, rc); err != nil {
			rc.Close()
			t.Fatalf("copiando %s: %v", f.Name, err)
		}
		rc.Close()
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("cerrando zip: %v", err)
	}
	return buf.Bytes()
}

// installLabExtWithUpdateServer instala com_labext (lab.InstallLabExt, la
// misma fixture que usa el corpus de fase 2a) y le añade un
// <updateservers><server>updateURL</server></updateservers> al manifiesto ya
// escrito. Sirve para el camino de la guarda --allow-network, donde Fetch
// jamás llega a ejecutarse y por tanto no hace falta que el paquete oficial
// coincida byte a byte con el manifiesto instalado. Devuelve la ruta del sitio.
func installLabExtWithUpdateServer(t *testing.T, root, updateURL string) string {
	t.Helper()
	if err := lab.WriteTree(root, "1.1.0"); err != nil {
		t.Fatalf("WriteTree: %v", err)
	}
	if err := lab.InstallLabExt(root); err != nil {
		t.Fatalf("InstallLabExt: %v", err)
	}
	manifestPath := filepath.Join(root, lab.LabExtManifestPath())
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("leyendo manifiesto instalado: %v", err)
	}
	withUpdate := withUpdateServerBlock(t, string(raw), updateURL)
	if err := os.WriteFile(manifestPath, []byte(withUpdate), 0o644); err != nil {
		t.Fatalf("reescribiendo manifiesto: %v", err)
	}
	return root
}

// buildLabExtWithUpdateServer instala com_labext y devuelve, además de la
// ruta del sitio, el paquete oficial "reeditado" para declarar el MISMO
// updateservers que el manifiesto instalado. Ambos manifiestos (el instalado
// y el que trae el paquete servido por /pkg.zip) deben ser byte a byte
// idénticos: SimulateComponent compara el manifiesto instalado como CUALQUIER
// otro archivo atribuido, así que si solo se editara el instalado, el hash no
// coincidiría con el del baseline y saldría un J0W-EXT-008 espurio sobre el
// propio manifiesto — un falso positivo del arnés de test, no del código bajo
// prueba.
func buildLabExtWithUpdateServer(t *testing.T, root, updateURL string) (site string, pkgWithUpdateServer []byte) {
	t.Helper()
	if err := lab.WriteTree(root, "1.1.0"); err != nil {
		t.Fatalf("WriteTree: %v", err)
	}

	orig := lab.LabExtPackage()
	manifestName := "com_labext.xml"
	manifestContent := readZipEntry(t, orig, manifestName)
	modifiedManifest := withUpdateServerBlock(t, string(manifestContent), updateURL)
	pkgWithUpdateServer = replaceZipEntry(t, orig, manifestName, []byte(modifiedManifest))

	if err := lab.InstallLabExt(root); err != nil {
		t.Fatalf("InstallLabExt: %v", err)
	}
	manifestPath := filepath.Join(root, lab.LabExtManifestPath())
	if err := os.WriteFile(manifestPath, []byte(modifiedManifest), 0o644); err != nil {
		t.Fatalf("reescribiendo manifiesto instalado: %v", err)
	}
	return root, pkgWithUpdateServer
}

// TestExtensionFetchGuardWithoutAllowNetwork (Task 3, fixes): el subcomando
// `extension fetch` debe rechazar SIN tocar la red cuando --allow-network no
// se pasó, enumerando en el mensaje la URL que se habría obtenido y
// sugiriendo el camino offline (`extension add`). La URL declarada ni
// siquiera necesita resolver de verdad: el guard corta antes de cualquier
// intento de conexión.
func TestExtensionFetchGuardWithoutAllowNetwork(t *testing.T) {
	h := newHarness(t)
	site := installLabExtWithUpdateServer(t, filepath.Join(h.root, "guard-site"), "http://example.invalid/update.xml")

	exit, _, stderr := h.run(t, "extension", "fetch", "com_labext", site)
	if exit == 0 {
		t.Fatalf("sin --allow-network debió fallar; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "http://example.invalid/update.xml") {
		t.Fatalf("el mensaje de rechazo debe enumerar la URL: %s", stderr)
	}
	if !strings.Contains(stderr, "extension add") {
		t.Fatalf("el mensaje de rechazo debe sugerir `extension add`: %s", stderr)
	}

	// Nada quedó cacheado: la guarda actuó ANTES de abrir el store o tocar la red.
	exit, doc, stderr := h.run(t, "extension", "list")
	if exit != 0 {
		t.Fatalf("extension list: exit %d\n%s", exit, stderr)
	}
	var listed struct {
		ExtensionBaselines []struct {
			Element string `json:"element"`
		} `json:"extension_baselines"`
	}
	if err := json.Unmarshal(doc, &listed); err != nil {
		t.Fatalf("extension list no parsea: %v\n%s", err, doc)
	}
	if len(listed.ExtensionBaselines) != 0 {
		t.Fatalf("no debía haber baselines cacheados tras el rechazo: %+v", listed.ExtensionBaselines)
	}
}

// TestExtensionFetchFullFlowThenScan (Task 3, fixes): flujo completo con un
// update server real en loopback. `extension fetch --allow-network` cachea el
// baseline oficial de com_labext (source "updateserver"); un `scan` posterior
// del mismo sitio debe marcar com_labext verified:true con
// verification_source "updateserver" y cero J0W-EXT-008 (nada trojanizado: el
// paquete servido y el árbol instalado declaran el mismo manifiesto).
func TestExtensionFetchFullFlowThenScan(t *testing.T) {
	h := newHarness(t)
	var pkg []byte
	var updateXML string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/update.xml":
			fmt.Fprint(w, updateXML)
		case "/pkg.zip":
			w.Write(pkg)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// El manifiesto (instalado y del paquete) se escribe DESPUÉS de levantar
	// el servidor: solo así se conoce el puerto loopback real que le toca
	// declarar en <updateservers>.
	site, pkgWithUpdateServer := buildLabExtWithUpdateServer(t, filepath.Join(h.root, "full-flow-site"), srv.URL+"/update.xml")
	pkg = pkgWithUpdateServer
	updateXML = fmt.Sprintf(`<?xml version="1.0"?><updates><update>`+
		`<element>com_labext</element><version>2.3.1</version>`+
		`<downloads><downloadurl type="full" format="zip">%s/pkg.zip</downloadurl></downloads>`+
		`</update></updates>`, srv.URL)

	exit, _, stderr := h.run(t, "--allow-network", "extension", "fetch", "com_labext", site)
	if exit != 0 {
		t.Fatalf("extension fetch --allow-network: exit %d\n%s", exit, stderr)
	}
	if !strings.Contains(stderr, "network-fetch") {
		t.Fatalf("no enumeró la red antes de tocarla: %s", stderr)
	}

	exit, doc, stderr := h.run(t, "extension", "list")
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
		t.Fatalf("extension list no parsea: %v\n%s", err, doc)
	}
	found := false
	for _, row := range listed.ExtensionBaselines {
		if row.Element == "com_labext" && row.Version == "2.3.1" {
			found = true
			if row.Source != "updateserver" {
				t.Errorf("extension list: source=%q, esperaba 'updateserver'", row.Source)
			}
		}
	}
	if !found {
		t.Fatalf("extension list: falta com_labext 2.3.1 en %+v", listed.ExtensionBaselines)
	}

	// Escanea el mismo sitio: com_labext debe verificar contra el baseline
	// recién obtenido por red.
	exit, doc, stderr = h.run(t, "scan", site)
	if exit != 0 {
		t.Fatalf("scan: exit %d\n%s", exit, stderr)
	}
	var rep struct {
		Findings []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
		Extensions []struct {
			Name               string  `json:"name"`
			Verified           bool    `json:"verified"`
			VerificationSource *string `json:"verification_source"`
		} `json:"extensions"`
	}
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatalf("informe no parsea: %v\n%s", err, doc)
	}
	extFound := false
	for _, e := range rep.Extensions {
		if e.Name != "com_labext" {
			continue
		}
		extFound = true
		if !e.Verified {
			t.Error("com_labext: verified debe ser true tras cachear el baseline vía update server")
		}
		if e.VerificationSource == nil || *e.VerificationSource != "updateserver" {
			got := "<nil>"
			if e.VerificationSource != nil {
				got = *e.VerificationSource
			}
			t.Errorf("com_labext: verification_source=%q, esperaba 'updateserver'", got)
		}
	}
	if !extFound {
		t.Fatalf("com_labext no aparece en coverage.extensions: %+v", rep.Extensions)
	}
	for _, f := range rep.Findings {
		if f.RuleID == "J0W-EXT-008" {
			t.Errorf("J0W-EXT-008 espurio tras verificar contra el baseline vía update server: %+v", f)
		}
	}
}

// TestExtensionFetchPluginFullFlowThenScan (fase 2c, Task 4): el mismo flujo
// que TestExtensionFetchFullFlowThenScan pero para un tipo NO componente — un
// plugin (system/foo) — para probar que `extension fetch`/`add` generalizan
// más allá de administrator/components/: localizan el manifiesto instalado
// en plugins/<group>/<elem>/ (readInstalledExtension), cachean su baseline
// bajo la clave "system/foo" (manifest.ExtensionKey de un plugin) y un `scan`
// posterior lo verifica igual que a un componente. No depende de T7
// (lab.InstallLabPlg no existe aún): el plugin se construye inline aquí, con
// el mismo manifiesto BYTE A BYTE en el árbol instalado y en el paquete
// servido (mismo motivo que buildLabExtWithUpdateServer: SimulateExtension
// atribuye el propio manifiesto como cualquier otro archivo, así que si
// difirieran, saldría un J0W-EXT-008 espurio del arnés, no del código bajo
// prueba).
func TestExtensionFetchPluginFullFlowThenScan(t *testing.T) {
	h := newHarness(t)
	var pkg []byte
	var updateXML string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/update.xml":
			fmt.Fprint(w, updateXML)
		case "/pkg.zip":
			w.Write(pkg)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// El árbol necesita un core Joomla real (para L2/inferencia de versión,
	// como en el resto de tests de scan de este archivo), más el plugin
	// añadido a mano encima.
	site := filepath.Join(h.root, "plugin-full-flow-site")
	if err := lab.WriteTree(site, "1.1.0"); err != nil {
		t.Fatalf("WriteTree: %v", err)
	}

	baseManifest := `<?xml version="1.0"?>
<extension type="plugin" group="system">
	<name>System Foo</name>
	<author>Lab Author</author>
	<version>1.0.0</version>
	<files>
		<filename>foo.php</filename>
	</files>
</extension>`
	// El manifiesto (instalado y del paquete) se escribe DESPUÉS de levantar
	// el servidor: solo así se conoce el puerto loopback real que le toca
	// declarar en <updateservers>.
	manifestWithUpdate := withUpdateServerBlock(t, baseManifest, srv.URL+"/update.xml")
	phpContent := "<?php\n// system plugin foo\n"

	pluginDir := filepath.Join(site, "plugins", "system", "foo")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "foo.xml"), []byte(manifestWithUpdate), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "foo.php"), []byte(phpContent), 0o644); err != nil {
		t.Fatal(err)
	}

	pkg = buildZipBytes(t, map[string]string{
		"foo.xml": manifestWithUpdate,
		"foo.php": phpContent,
	})
	updateXML = fmt.Sprintf(`<?xml version="1.0"?><updates><update>`+
		`<element>system/foo</element><version>1.0.0</version>`+
		`<downloads><downloadurl type="full" format="zip">%s/pkg.zip</downloadurl></downloads>`+
		`</update></updates>`, srv.URL)

	// element viene en forma "grupo/elemento": readInstalledExtension lo
	// reconoce como plugin sin necesidad de --group.
	exit, _, stderr := h.run(t, "--allow-network", "extension", "fetch", "system/foo", site)
	if exit != 0 {
		t.Fatalf("extension fetch --allow-network (plugin): exit %d\n%s", exit, stderr)
	}
	if !strings.Contains(stderr, "network-fetch") {
		t.Fatalf("no enumeró la red antes de tocarla: %s", stderr)
	}

	exit, doc, stderr := h.run(t, "extension", "list")
	if exit != 0 {
		t.Fatalf("extension list: exit %d\n%s", exit, stderr)
	}
	var listed struct {
		ExtensionBaselines []struct {
			Element string `json:"element"`
			Version string `json:"version"`
			Source  string `json:"source"`
			Type    string `json:"type"`
		} `json:"extension_baselines"`
	}
	if err := json.Unmarshal(doc, &listed); err != nil {
		t.Fatalf("extension list no parsea: %v\n%s", err, doc)
	}
	found := false
	for _, row := range listed.ExtensionBaselines {
		if row.Element == "system/foo" && row.Version == "1.0.0" {
			found = true
			if row.Source != "updateserver" {
				t.Errorf("extension list: source=%q, esperaba 'updateserver'", row.Source)
			}
			// extensionTypeOf solo mira la clave ("system/foo"), que por
			// construcción es ambigua entre plugin (grupo/elemento) y
			// librería namespaced (<libraryname> con "/") — no puede
			// distinguirlas sin consultar el árbol instalado, así que la
			// etiqueta honesta es "plugin-or-library" (fix round 2, MINOR 2),
			// no "plugin" (que sería una afirmación falsa para una librería
			// namespaced con la misma clave).
			if row.Type != "plugin-or-library" {
				t.Errorf("extension list: type=%q, esperaba 'plugin-or-library'", row.Type)
			}
		}
	}
	if !found {
		t.Fatalf("extension list: falta system/foo 1.0.0 en %+v", listed.ExtensionBaselines)
	}

	// Escanea el mismo sitio: el plugin debe verificar contra el baseline
	// recién obtenido por red, igual que un componente.
	exit, doc, stderr = h.run(t, "scan", site)
	if exit != 0 {
		t.Fatalf("scan: exit %d\n%s", exit, stderr)
	}
	var rep struct {
		Findings []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
		Extensions []struct {
			Type               string  `json:"type"`
			ManifestPath       string  `json:"manifest_path"`
			Verified           bool    `json:"verified"`
			VerificationSource *string `json:"verification_source"`
		} `json:"extensions"`
	}
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatalf("informe no parsea: %v\n%s", err, doc)
	}
	extFound := false
	for _, e := range rep.Extensions {
		if e.ManifestPath != "plugins/system/foo/foo.xml" {
			continue
		}
		extFound = true
		if e.Type != "plugin" {
			t.Errorf("system/foo: type=%q, esperaba 'plugin'", e.Type)
		}
		if !e.Verified {
			t.Error("system/foo: verified debe ser true tras cachear el baseline vía update server")
		}
		if e.VerificationSource == nil || *e.VerificationSource != "updateserver" {
			got := "<nil>"
			if e.VerificationSource != nil {
				got = *e.VerificationSource
			}
			t.Errorf("system/foo: verification_source=%q, esperaba 'updateserver'", got)
		}
	}
	if !extFound {
		t.Fatalf("system/foo no aparece en coverage.extensions: %+v", rep.Extensions)
	}
	for _, f := range rep.Findings {
		if f.RuleID == "J0W-EXT-008" {
			t.Errorf("J0W-EXT-008 espurio tras verificar contra el baseline vía update server (plugin): %+v", f)
		}
	}
}
