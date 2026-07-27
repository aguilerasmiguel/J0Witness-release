package lab

import (
	"os"
	"path/filepath"
)

// D2 fixtures: reproducen los tres patrones reales que D2 corrige, todos dentro
// de directorios del core (donde un archivo ajeno sería J0W-CORE-004):
//   - una librería cuya raíz se deriva de <libraryname> (no de <name>) y cuyo
//     manifiesto vive en un subdirectorio de manifests/libraries,
//   - un paquete de idioma de terceros que posee todo su directorio,
//   - un componente que vuelca una traducción en la carpeta de idioma
//     compartida que el pack también posee (exacto gana a carpeta).

const d2LibManifestPath = "administrator/manifests/libraries/vendor/synthlib.xml"

const d2LibManifest = `<?xml version="1.0" encoding="UTF-8"?>
<extension type="library" method="upgrade">
	<name>Synthetic Library</name>
	<libraryname>vendor/synthlib</libraryname>
	<version>1.0.0</version>
	<files>
		<filename>Lib.php</filename>
		<folder>Sub</folder>
	</files>
</extension>
`

const d2LangManifestPath = "administrator/language/es-XX/install.xml"

const d2LangManifest = `<?xml version="1.0" encoding="UTF-8"?>
<extension client="administrator" type="language" method="upgrade">
	<name>Synthetic (es-XX)</name>
	<tag>es-XX</tag>
	<version>1.0.0</version>
	<files>
		<folder>/</folder>
		<filename file="meta">install.xml</filename>
	</files>
</extension>
`

const d2ComManifestPath = "administrator/components/com_d2demo/d2demo.xml"

// d2ComManifest: <name> de display distinto del directorio (D1) y una
// traducción declarada por <languages> en la carpeta de idioma compartida (D2).
const d2ComManifest = `<?xml version="1.0" encoding="UTF-8"?>
<extension type="component" method="upgrade">
	<name>D2 Demo</name>
	<version>1.0.0</version>
	<administration>
		<files folder="admin"><filename>d2demo.php</filename></files>
		<languages folder="language/admin">
			<language tag="es-XX">es-XX/es-XX.com_d2demo.ini</language>
		</languages>
	</administration>
</extension>
`

// d2Files son todos los archivos instalados (manifiestos + contenido).
func d2Files() map[string]string {
	return map[string]string{
		// Librería: raíz derivada de <libraryname> = libraries/vendor/synthlib.
		d2LibManifestPath:                        d2LibManifest,
		"libraries/vendor/synthlib/Lib.php":      "<?php\n// synthlib entry\n",
		"libraries/vendor/synthlib/Sub/Help.php": "<?php\n// synthlib helper\n",
		// Pack de idioma: posee todo administrator/language/es-XX/.
		d2LangManifestPath: d2LangManifest,
		"administrator/language/es-XX/es-XX.synthpack.ini": "; synthetic pack strings\nKEY=\"valor\"\n",
		// Componente con traducción compartida en la carpeta del pack.
		d2ComManifestPath: d2ComManifest,
		"administrator/components/com_d2demo/d2demo.php":    "<?php\n// com_d2demo admin\n",
		"administrator/language/es-XX/es-XX.com_d2demo.ini": "; com_d2demo strings\nTITLE=\"Demo\"\n",
	}
}

// InstallD2Fixtures escribe las fixtures de D2 dentro de un árbol existente.
func InstallD2Fixtures(root string) error {
	for rel, content := range d2Files() {
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
