package lab

import (
	"os"
	"path/filepath"
	"strings"
)

// LabPlgGroup/LabPlgElement identifican plg_system_labplg: el plugin
// sintético de laboratorio EN LAYOUT PLANO (fase 2c, Task 7). A diferencia de
// com_labext (folder-prefixed: `<files folder="site">`), un plugin real de
// Joomla casi siempre declara su manifiesto sin `folder=`: los `<filename>`/
// `<folder>` son relativos a la raíz del propio paquete (ver
// extbaseline.SimulateExtension, camino "plano"). Este fixture ejercita
// exactamente ese camino con un fixture reutilizable, tanto en tests de
// round-trip como en recetas de corpus.
const (
	LabPlgGroup   = "system"
	LabPlgElement = "labplg"
)

// labPlgManifest: manifiesto de plugin PLANO. src/ es una carpeta declarada
// (recursiva, todo ejecutable) y tmpl/ trae tanto una vista PHP como un
// activo CSS inerte — necesario para distinguir troyano (ejecutable) de
// modificación inerte en las recetas de corpus (D5).
const labPlgManifest = `<?xml version="1.0" encoding="UTF-8"?>
<extension type="plugin" group="system" method="upgrade">
	<name>plg_system_labplg</name>
	<author>Lab Author</author>
	<creationDate>2026-01</creationDate>
	<version>1.4.0</version>
	<description>Plugin sintético de laboratorio (layout plano)</description>
	<files>
		<filename>labplg.php</filename>
		<folder>src</folder>
		<folder>tmpl</folder>
	</files>
</extension>
`

// labPlgFiles son los archivos instalados de plg_system_labplg, en sus
// ubicaciones reales (todos bajo plugins/system/labplg/, layout plano: no hay
// prefijo site/admin/media que mapear).
func labPlgFiles() map[string]string {
	return map[string]string{
		"plugins/system/labplg/labplg.php":       "<?php\n// labplg entry\nfunction labplg_boot() {}\n",
		"plugins/system/labplg/src/Handler.php":  "<?php\nnamespace Lab\\Plugin\\Labplg;\nclass Handler {}\n",
		"plugins/system/labplg/tmpl/default.php": "<?php\n// labplg admin field view\n",
		"plugins/system/labplg/tmpl/field.css":   "/* labplg field styling */\n.labplg-field { color: #000; }\n",
	}
}

// LabPlgManifestPath devuelve la ruta del manifiesto del plugin de
// laboratorio.
func LabPlgManifestPath() string {
	return "plugins/system/labplg/labplg.xml"
}

// LabPlgElementKey es la clave estable (manifest.ExtensionKey para Plugin:
// grupo/elemento).
func LabPlgElementKey() string {
	return LabPlgGroup + "/" + LabPlgElement
}

// InstallLabPlg escribe el plugin sintético legítimo dentro de un árbol ya
// existente. No toca el core.
func InstallLabPlg(root string) error {
	files := labPlgFiles()
	files[LabPlgManifestPath()] = labPlgManifest
	for rel, content := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// LabPlgPackage construye, de forma determinista, el zip PLANO del "paquete
// oficial" sintético de plg_system_labplg: manifiesto + labplg.php + src/…
// + tmpl/… en la RAÍZ del paquete, sin ningún prefijo site/admin/media (a
// diferencia de LabExtPackage/buildLabExtPackage, que invierte un mapeo con
// folder=). `extbaseline.SimulateExtension` sobre este paquete, contra el
// InstallTarget del plugin, produce EXACTAMENTE el conjunto ruta
// instalada→sha256 que InstallLabPlg escribe.
func LabPlgPackage() []byte {
	return buildLabPlgPackage(labPlgManifest)
}

// LabPlgPackageWithVersion construye el mismo paquete que LabPlgPackage pero
// declarando otra versión en el manifiesto (recipe de "versión no
// coincidente").
func LabPlgPackageWithVersion(version string) []byte {
	m := strings.Replace(labPlgManifest, "<version>1.4.0</version>", "<version>"+version+"</version>", 1)
	if m == labPlgManifest && version != "1.4.0" {
		panic("LabPlgPackageWithVersion: no se pudo sustituir la versión en el manifiesto de laboratorio")
	}
	return buildLabPlgPackage(m)
}

// buildLabPlgPackage arma el zip PLANO a partir del manifiesto dado (permite
// variar solo la versión declarada) y de labPlgFiles(): cada ruta instalada
// (plugins/system/labplg/<rel>) vuelve a <rel> en la raíz del paquete.
func buildLabPlgPackage(manifestXML string) []byte {
	const prefix = "plugins/system/labplg/"
	entries := map[string]string{
		"labplg.xml": manifestXML,
	}
	for installed, content := range labPlgFiles() {
		rel := strings.TrimPrefix(installed, prefix)
		if rel == installed {
			panic("buildLabPlgPackage: ruta instalada sin el prefijo esperado: " + installed)
		}
		entries[rel] = content
	}
	return zipDeterministic(entries)
}
