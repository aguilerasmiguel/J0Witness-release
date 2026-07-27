package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"j0witness/internal/manifest"
)

// writeInstalledFile crea rel bajo root (con sus directorios intermedios) con
// content. (No reutiliza writeFile de hostile_test.go: firma distinta —
// aquella toma una ruta absoluta ya unida, esta toma root+rel.)
func writeInstalledFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestReadInstalledExtensionNamespacedLibrary (fix round 1, CRITICAL 1): un
// elemento con forma "a/b" que NO tiene --group debe poder resolver a una
// LIBRERÍA namespaced (eshiol/J2xml, vendor/synthlib: ambas son fixtures
// reales de este repo — ver internal/lab/d2ext.go, internal/manifest
// discover_test.go/layout_test.go/parse_test.go), no solo a un plugin
// grupo/elemento. Antes del fix, `isPlugin := group != "" || strings.Contains
// (element, "/")` secuestraba CUALQUIER "/" hacia la rama de plugin antes de
// que la búsqueda de librería llegara siquiera a intentarse.
func TestReadInstalledExtensionNamespacedLibrary(t *testing.T) {
	root := t.TempDir()
	libManifest := `<?xml version="1.0" encoding="UTF-8"?>
<extension type="library" method="upgrade">
	<name>J2XML</name>
	<libraryname>eshiol/J2xml</libraryname>
	<version>3.2.1</version>
	<files>
		<filename>Exporter.php</filename>
		<folder>Table</folder>
	</files>
</extension>
`
	writeInstalledFile(t, root, "administrator/manifests/libraries/eshiol/J2xml.xml", libManifest)
	writeInstalledFile(t, root, "libraries/eshiol/J2xml/Exporter.php", "<?php\n// exporter\n")
	writeInstalledFile(t, root, "libraries/eshiol/J2xml/Table/Category.php", "<?php\n// category\n")

	target, version, _, err := readInstalledExtension(root, "eshiol/J2xml", "", "")
	if err != nil {
		t.Fatalf("readInstalledExtension: %v", err)
	}
	if target.Type != manifest.Library {
		t.Fatalf("Type=%q, esperaba library", target.Type)
	}
	if target.ElementKey != "eshiol/J2xml" {
		t.Fatalf("ElementKey=%q, esperaba eshiol/J2xml", target.ElementKey)
	}
	if target.FilesRoot != "libraries/eshiol/J2xml" {
		t.Fatalf("FilesRoot=%q, esperaba libraries/eshiol/J2xml", target.FilesRoot)
	}
	if version != "3.2.1" {
		t.Fatalf("version=%q, esperaba 3.2.1", version)
	}
}

// TestReadInstalledExtensionNamespacedLibraryVendor cubre el otro fixture ya
// presente en el repo (internal/lab/d2ext.go): vendor/synthlib, en un árbol
// más anidado (administrator/manifests/libraries/vendor/synthlib.xml) para
// probar que el recorrido recursivo no se detiene en el primer nivel.
func TestReadInstalledExtensionNamespacedLibraryVendor(t *testing.T) {
	root := t.TempDir()
	libManifest := `<?xml version="1.0" encoding="UTF-8"?>
<extension type="library" method="upgrade">
	<name>Synthetic Library</name>
	<libraryname>vendor/synthlib</libraryname>
	<version>1.0.0</version>
	<files>
		<filename>Lib.php</filename>
	</files>
</extension>
`
	writeInstalledFile(t, root, "administrator/manifests/libraries/vendor/synthlib.xml", libManifest)
	writeInstalledFile(t, root, "libraries/vendor/synthlib/Lib.php", "<?php\n// synthlib entry\n")

	target, version, _, err := readInstalledExtension(root, "vendor/synthlib", "", "")
	if err != nil {
		t.Fatalf("readInstalledExtension: %v", err)
	}
	if target.Type != manifest.Library || target.ElementKey != "vendor/synthlib" {
		t.Fatalf("target inesperado: %+v", target)
	}
	if version != "1.0.0" {
		t.Fatalf("version=%q", version)
	}
}

// TestReadInstalledExtensionSlashAmbiguousPluginAndLibrary: si el elemento
// "a/b" calza TANTO un plugin instalado en plugins/a/b/ COMO una librería
// namespaced con el mismo texto, es una ambigüedad genuina (identidades
// distintas: "a/b" plugin vs "a/b" library) y debe fallar enumerando, no
// elegir una al azar.
func TestReadInstalledExtensionSlashAmbiguousPluginAndLibrary(t *testing.T) {
	root := t.TempDir()
	pluginManifest := `<?xml version="1.0"?>
<extension type="plugin" group="sys"><name>tool</name><version>1.0</version><files><filename>tool.php</filename></files></extension>`
	writeInstalledFile(t, root, "plugins/sys/tool/tool.xml", pluginManifest)
	writeInstalledFile(t, root, "plugins/sys/tool/tool.php", "<?php\n")

	libManifest := `<?xml version="1.0"?>
<extension type="library"><name>Tool Lib</name><libraryname>sys/tool</libraryname><version>1.0</version><files><filename>Lib.php</filename></files></extension>`
	writeInstalledFile(t, root, "administrator/manifests/libraries/sys/tool.xml", libManifest)
	writeInstalledFile(t, root, "libraries/sys/tool/Lib.php", "<?php\n")

	_, _, _, err := readInstalledExtension(root, "sys/tool", "", "")
	if err == nil {
		t.Fatal("esperaba error de ambigüedad (plugin y librería calzan el mismo texto)")
	}
	if !strings.Contains(err.Error(), "--group") && !strings.Contains(err.Error(), "--client") {
		t.Fatalf("el error de ambigüedad debe sugerir --group/--client: %v", err)
	}

	// --group desambigua a favor del plugin.
	target, _, _, err := readInstalledExtension(root, "sys/tool", "sys", "")
	if err != nil {
		t.Fatalf("con --group, no debía haber ambigüedad: %v", err)
	}
	if target.Type != manifest.Plugin {
		t.Fatalf("con --group, esperaba plugin, salió %q", target.Type)
	}
}

// TestReadInstalledExtensionClientSymmetric (fix round 1, IMPORTANT 3): un
// módulo instalado TANTO en site como en administrator es ambiguo sin
// --client; --client site y --client admin deben, simétricamente, restringir
// la búsqueda a un solo lado (antes del fix, solo "admin" narrowed; "site" no
// hacía nada y la ambigüedad no tenía forma de resolverse a favor del lado
// site).
func TestReadInstalledExtensionClientSymmetric(t *testing.T) {
	root := t.TempDir()
	siteManifest := `<?xml version="1.0"?>
<extension type="module"><name>Mod X (site)</name><version>1.0</version><files><filename>mod_x.php</filename></files></extension>`
	adminManifest := `<?xml version="1.0"?>
<extension type="module"><name>Mod X (admin)</name><version>2.0</version><files><filename>mod_x.php</filename></files></extension>`
	writeInstalledFile(t, root, "modules/mod_x/mod_x.xml", siteManifest)
	writeInstalledFile(t, root, "modules/mod_x/mod_x.php", "<?php\n")
	writeInstalledFile(t, root, "administrator/modules/mod_x/mod_x.xml", adminManifest)
	writeInstalledFile(t, root, "administrator/modules/mod_x/mod_x.php", "<?php\n")

	// Sin --client: ambiguo (dos identidades: mod_x vs mod_x@administrator).
	if _, _, _, err := readInstalledExtension(root, "mod_x", "", ""); err == nil {
		t.Fatal("esperaba ambigüedad sin --client")
	}

	// --client site: solo el lado site.
	target, version, _, err := readInstalledExtension(root, "mod_x", "", "site")
	if err != nil {
		t.Fatalf("--client site: %v", err)
	}
	if target.ElementKey != "mod_x" || version != "1.0" {
		t.Fatalf("--client site: target=%+v version=%q, esperaba mod_x/1.0", target, version)
	}

	// --client admin: solo el lado admin.
	target, version, _, err = readInstalledExtension(root, "mod_x", "", "admin")
	if err != nil {
		t.Fatalf("--client admin: %v", err)
	}
	if target.ElementKey != "mod_x@administrator" || version != "2.0" {
		t.Fatalf("--client admin: target=%+v version=%q, esperaba mod_x@administrator/2.0", target, version)
	}
}

// TestReadInstalledExtensionAdminSuffixRoundTrips (fix round 2, IMPORTANT 1):
// `extension list` imprime la clave canónica de un módulo/plantilla admin CON
// el sufijo "@administrator" (manifest.ExtensionKey). Antes del fix,
// readInstalledExtension construía sus directorios candidatos a partir del
// element crudo, así que alimentar de vuelta esa misma clave impresa
// ("mod_x@administrator") producía una ruta que nunca existe
// ("administrator/modules/mod_x@administrator/") y fallaba con "no
// encontrado" — un operador no podía copiar/pegar la clave de `list` en
// `add`/`fetch`. El fix despoja el sufijo y fuerza client="admin" sea cual
// sea el --client recibido (aquí "", NO "admin": la prueba pasa client=""
// precisamente para demostrar que el sufijo por sí solo, sin --client admin,
// ya dirige la búsqueda al lado admin).
func TestReadInstalledExtensionAdminSuffixRoundTrips(t *testing.T) {
	root := t.TempDir()
	adminManifest := `<?xml version="1.0"?>
<extension type="module"><name>Mod X (admin)</name><version>2.0</version><files><filename>mod_x.php</filename></files></extension>`
	writeInstalledFile(t, root, "administrator/modules/mod_x/mod_x.xml", adminManifest)
	writeInstalledFile(t, root, "administrator/modules/mod_x/mod_x.php", "<?php\n")

	// La clave EXACTA que `extension list` imprimiría para este módulo admin,
	// con client="" (no "admin"): el sufijo por sí solo debe bastar.
	target, version, _, err := readInstalledExtension(root, "mod_x@administrator", "", "")
	if err != nil {
		t.Fatalf("readInstalledExtension(mod_x@administrator): %v", err)
	}
	if target.ElementKey != "mod_x@administrator" {
		t.Fatalf("ElementKey=%q, esperaba mod_x@administrator", target.ElementKey)
	}
	if target.FilesRoot != "administrator/modules/mod_x" {
		t.Fatalf("FilesRoot=%q, esperaba administrator/modules/mod_x", target.FilesRoot)
	}
	if version != "2.0" {
		t.Fatalf("version=%q, esperaba 2.0", version)
	}

	// El camino sin sufijo + --client admin (equivalente explícito de
	// operador) debe seguir funcionando exactamente igual: el fix no lo debe
	// romper ni volverlo redundante.
	target, version, _, err = readInstalledExtension(root, "mod_x", "", "admin")
	if err != nil {
		t.Fatalf("readInstalledExtension(mod_x, --client admin): %v", err)
	}
	if target.ElementKey != "mod_x@administrator" || version != "2.0" {
		t.Fatalf("--client admin: target=%+v version=%q, esperaba mod_x@administrator/2.0", target, version)
	}
}
