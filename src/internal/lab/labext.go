package lab

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LabExtName es el componente sintético de terceros usado por el corpus de la
// feature 002. Estructura joomla-forme real: manifiesto en la raíz de
// administración, archivos repartidos entre sitio, administración y medios,
// carpetas declaradas (`<folder>`) y archivos declarados (`<filename>`).
const LabExtName = "com_labext"

// labExtManifest es el manifiesto moderno del componente. Declara:
//   - site: carpeta src/ (recursiva) y archivo router.php
//   - admin: carpeta src/ (recursiva) y archivos labext.php, config.xml
//   - media: carpeta js/ (recursiva)
const labExtManifest = `<?xml version="1.0" encoding="UTF-8"?>
<extension type="component" method="upgrade">
	<name>com_labext</name>
	<author>Lab Author</author>
	<creationDate>2026-01</creationDate>
	<version>2.3.1</version>
	<description>Extensión sintética de laboratorio</description>
	<files folder="site">
		<filename>router.php</filename>
		<folder>src</folder>
	</files>
	<media destination="com_labext" folder="media">
		<folder>js</folder>
	</media>
	<administration>
		<files folder="admin">
			<filename>labext.php</filename>
			<filename>config.xml</filename>
			<folder>src</folder>
		</files>
	</administration>
</extension>
`

// labExtFiles es el conjunto de archivos que la extensión declara e instala,
// en sus ubicaciones reales (tras el mapeo declarado→instalado de Joomla).
func labExtFiles() map[string]string {
	return map[string]string{
		// site → components/com_labext/
		"components/com_labext/router.php":         "<?php\n// com_labext site router\nfunction labext_route($p) { return $p; }\n",
		"components/com_labext/src/Controller.php": "<?php\nnamespace Lab\\Component\\Labext;\nclass Controller {}\n",
		"components/com_labext/src/Model.php":      "<?php\nnamespace Lab\\Component\\Labext;\nclass Model {}\n",
		// media → media/com_labext/
		"media/com_labext/js/app.js": "// com_labext front\nconsole.log('labext');\n",
		// admin → administrator/components/com_labext/
		"administrator/components/com_labext/labext.php":         "<?php\n// com_labext admin entry\n",
		"administrator/components/com_labext/config.xml":         "<?xml version=\"1.0\"?>\n<config/>\n",
		"administrator/components/com_labext/src/Dispatcher.php": "<?php\nnamespace Lab\\Component\\Labext\\Administrator;\nclass Dispatcher {}\n",
	}
}

// ManifestPath devuelve la ruta del manifiesto del componente de laboratorio.
func LabExtManifestPath() string {
	return "administrator/components/com_labext/com_labext.xml"
}

// InstallLabExt escribe la extensión sintética legítima dentro de un árbol ya
// existente (típicamente una instalación minicms). No toca el core.
func InstallLabExt(root string) error {
	files := labExtFiles()
	files[LabExtManifestPath()] = labExtManifest
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

// LabExtDeclaredPaths son las rutas que el manifiesto declara suyas, ya
// mapeadas a ubicaciones instaladas. Sirve de oráculo para los tests del mapeo.
func LabExtDeclaredPaths() []string {
	return []string{
		"components/com_labext/router.php",
		"components/com_labext/src/Controller.php",
		"components/com_labext/src/Model.php",
		"media/com_labext/js/app.js",
		"administrator/components/com_labext/labext.php",
		"administrator/components/com_labext/config.xml",
		"administrator/components/com_labext/src/Dispatcher.php",
	}
}

// LabExtRoots son las raíces de instalación que ocupa (FR-113).
func LabExtRoots() []string {
	return []string{
		"administrator/components/com_labext",
		"components/com_labext",
		"media/com_labext",
	}
}

// LabExtPackage construye, de forma determinista, el zip del "paquete
// oficial" sintético de com_labext (fase 2a: corpus de verificación de
// extensiones). Se construye INVIRTIENDO el mapeo instalado→origen a partir
// de la MISMA fuente de verdad que InstallLabExt usa (labExtFiles): cada ruta
// instalada vuelve a su ruta de origen dentro del paquete (site/, admin/,
// media/), con el MISMO contenido. Así, `extbaseline.SimulateComponent`
// sobre este paquete produce EXACTAMENTE el conjunto ruta instalada→sha256
// que `InstallLabExt` escribe en el árbol: una instalación limpia de
// com_labext verifica sin falsos J0W-EXT-008.
func LabExtPackage() []byte {
	return buildLabExtPackage(labExtManifest)
}

// LabExtPackageWithVersion construye el mismo paquete que LabExtPackage pero
// declarando otra versión en el manifiesto. Sirve al recipe de corpus
// "versión no coincidente": cachear un baseline bajo una versión distinta a
// la instalada hace que el lookup de VerifyExtensions (element, versión
// instalada) no encuentre baseline, y por tanto no se compare nada
// (Principio VI) — ni J0W-EXT-008 ni J0W-EXT-009.
func LabExtPackageWithVersion(version string) []byte {
	m := strings.Replace(labExtManifest, "<version>2.3.1</version>", "<version>"+version+"</version>", 1)
	if m == labExtManifest && version != "2.3.1" {
		panic("LabExtPackageWithVersion: no se pudo sustituir la versión en el manifiesto de laboratorio")
	}
	return buildLabExtPackage(m)
}

// buildLabExtPackage arma el zip del paquete a partir del manifiesto dado
// (permite variar solo la versión declarada) y de labExtFiles(), invirtiendo
// el mapeo declarado→instalado de com_labext:
//   - components/com_labext/<rel>               → site/<rel>
//   - administrator/components/com_labext/<rel> → admin/<rel>
//   - media/com_labext/<rel>                     → media/<rel>
//   - manifiesto                                 → com_labext.xml (raíz)
//
// El nombre del manifiesto en el zip coincide con el nombre real instalado
// (com_labext.xml, ver LabExtManifestPath) para que
// `administrator/components/<element>/<manName>` case con la ruta que
// InstallLabExt realmente escribe.
func buildLabExtPackage(manifestXML string) []byte {
	entries := map[string]string{
		"com_labext.xml": manifestXML,
	}
	for installed, content := range labExtFiles() {
		switch {
		case strings.HasPrefix(installed, "components/com_labext/"):
			rel := strings.TrimPrefix(installed, "components/com_labext/")
			entries["site/"+rel] = content
		case strings.HasPrefix(installed, "administrator/components/com_labext/"):
			rel := strings.TrimPrefix(installed, "administrator/components/com_labext/")
			entries["admin/"+rel] = content
		case strings.HasPrefix(installed, "media/com_labext/"):
			rel := strings.TrimPrefix(installed, "media/com_labext/")
			entries["media/"+rel] = content
		default:
			panic("buildLabExtPackage: ruta instalada de labExtFiles sin mapeo inverso conocido: " + installed)
		}
	}
	return zipDeterministic(entries)
}

// zipDeterministic construye un zip en memoria con las entradas dadas, en
// orden de nombre estable (Principio IV: nunca se itera un map para producir
// salida directamente).
func zipDeterministic(files map[string]string) []byte {
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
			panic(err) // escritura en memoria: solo puede fallar por bug
		}
		if _, err := fw.Write([]byte(files[name])); err != nil {
			panic(err)
		}
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
