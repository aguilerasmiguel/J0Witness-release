package lab

import (
	"os"
	"path/filepath"
	"strings"
)

// LabLibName identifica la librería sintética de laboratorio (fase 2c, Task
// 7): raíz derivada de <libraryname> (no de <name> de display), manifiesto en
// un subdirectorio de administrator/manifests/libraries/ (D2: la raíz real y
// el directorio del manifiesto NO coinciden, a diferencia de componente/
// módulo/plugin/plantilla).
//
// Es un fixture DISTINTO del de d2ext.go (vendor/synthlib, usado por la
// regresión D2 "ext-d2-library-language"): un elemento propio
// (labvendor/lablib) evita acoplar el matrix de estados de verificación de
// Task 7 con esa receta de regresión ya existente.
const LabLibName = "labvendor/lablib"

const labLibManifestPath = "administrator/manifests/libraries/labvendor/lablib.xml"

const labLibManifest = `<?xml version="1.0" encoding="UTF-8"?>
<extension type="library" method="upgrade">
	<name>Lab Library</name>
	<libraryname>labvendor/lablib</libraryname>
	<author>Lab Author</author>
	<creationDate>2026-01</creationDate>
	<version>4.1.0</version>
	<description>Librería sintética de laboratorio</description>
	<files folder="lib">
		<filename>Lib.php</filename>
		<folder>Support</folder>
	</files>
</extension>
`

// labLibFiles son los archivos instalados de la librería, en sus ubicaciones
// reales (libraries/labvendor/lablib/…). Support/notice.txt es un activo
// inerte no ejecutable, necesario para distinguir troyano de modificación
// inerte en las recetas de corpus (D5).
func labLibFiles() map[string]string {
	return map[string]string{
		"libraries/labvendor/lablib/Lib.php":            "<?php\nnamespace LabVendor\\Lablib;\nclass Lib {}\n",
		"libraries/labvendor/lablib/Support/Helper.php": "<?php\nnamespace LabVendor\\Lablib\\Support;\nclass Helper {}\n",
		"libraries/labvendor/lablib/Support/notice.txt": "Lab Library — synthetic fixture.\n",
	}
}

// LabLibManifestPath devuelve la ruta del manifiesto instalado de la
// librería de laboratorio.
func LabLibManifestPath() string { return labLibManifestPath }

// LabLibElementKey es la clave estable (manifest.ExtensionKey para Library:
// <libraryname>).
func LabLibElementKey() string { return LabLibName }

// InstallLabLib escribe la librería sintética legítima dentro de un árbol ya
// existente. No toca el core.
func InstallLabLib(root string) error {
	files := labLibFiles()
	files[labLibManifestPath] = labLibManifest
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

// LabLibPackage construye, de forma determinista, el zip del "paquete
// oficial" sintético de la librería: manifiesto en la raíz + lib/Lib.php +
// lib/Support/… (folder="lib", invirtiendo el mapeo declarado→instalado, como
// LabExtPackage hace para el componente).
func LabLibPackage() []byte { return buildLabLibPackage(labLibManifest) }

// LabLibPackageWithVersion construye el mismo paquete pero con otra versión
// declarada (recipe de "versión no coincidente").
func LabLibPackageWithVersion(version string) []byte {
	m := strings.Replace(labLibManifest, "<version>4.1.0</version>", "<version>"+version+"</version>", 1)
	if m == labLibManifest && version != "4.1.0" {
		panic("LabLibPackageWithVersion: no se pudo sustituir la versión en el manifiesto de laboratorio")
	}
	return buildLabLibPackage(m)
}

// buildLabLibPackage invierte labLibFiles() (raíz libraries/labvendor/lablib/)
// hacia lib/… en el paquete, y coloca el manifiesto en la raíz del paquete
// con el mismo nombre de archivo que el instalado (lablib.xml, ver
// LabLibManifestPath: administrator/manifests/libraries/labvendor/lablib.xml).
func buildLabLibPackage(manifestXML string) []byte {
	const installedPrefix = "libraries/labvendor/lablib/"
	entries := map[string]string{
		"lablib.xml": manifestXML,
	}
	for installed, content := range labLibFiles() {
		rel := strings.TrimPrefix(installed, installedPrefix)
		if rel == installed {
			panic("buildLabLibPackage: ruta instalada sin el prefijo esperado: " + installed)
		}
		entries["lib/"+rel] = content
	}
	return zipDeterministic(entries)
}
