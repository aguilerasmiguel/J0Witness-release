package lab

import (
	"os"
	"path/filepath"
)

// DispExtDir es el DIRECTORIO instalado del segundo componente sintético, cuyo
// `<name>` de display ("Fancy Component") difiere a propósito del directorio.
// Reproduce el patrón real (p.ej. SP Page Builder → com_sppagebuilder) que
// motivó D1: la raíz de un componente debe derivar del directorio del
// manifiesto, no del nombre de display.
const DispExtDir = "com_dispname"

// dispExtManifest declara sus secciones site/admin/media como cualquier
// componente real; su `<name>` es un rótulo humano, no el elemento instalado.
const dispExtManifest = `<?xml version="1.0" encoding="UTF-8"?>
<extension type="component" method="upgrade">
	<name>Fancy Component</name>
	<author>Lab Author</author>
	<creationDate>2026-01</creationDate>
	<version>4.5.6</version>
	<description>Extensión sintética con nombre de display distinto del directorio</description>
	<files folder="site">
		<filename>router.php</filename>
		<folder>src</folder>
	</files>
	<media folder="media">
		<folder>js</folder>
	</media>
	<administration>
		<files folder="admin">
			<filename>dispname.php</filename>
			<folder>src</folder>
		</files>
	</administration>
</extension>
`

// dispExtFiles son los archivos instalados en sus ubicaciones reales, todas
// bajo el DIRECTORIO com_dispname (no bajo el nombre de display).
func dispExtFiles() map[string]string {
	return map[string]string{
		"components/com_dispname/router.php":                  "<?php\n// com_dispname site router\nfunction disp_route($p) { return $p; }\n",
		"components/com_dispname/src/Controller.php":          "<?php\nnamespace Lab\\Component\\Dispname;\nclass Controller {}\n",
		"media/com_dispname/js/app.js":                        "// com_dispname front\nconsole.log('dispname');\n",
		"administrator/components/com_dispname/dispname.php":  "<?php\n// com_dispname admin entry\n",
		"administrator/components/com_dispname/src/Model.php": "<?php\nnamespace Lab\\Component\\Dispname\\Administrator;\nclass Model {}\n",
	}
}

// DispExtManifestPath es la ruta del manifiesto (nombre del archivo distinto
// del directorio, como en instalaciones reales).
func DispExtManifestPath() string {
	return "administrator/components/com_dispname/dispname.xml"
}

// InstallDispExt escribe el componente de nombre-de-display dentro de un árbol
// existente. No toca el core.
func InstallDispExt(root string) error {
	files := dispExtFiles()
	files[DispExtManifestPath()] = dispExtManifest
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
