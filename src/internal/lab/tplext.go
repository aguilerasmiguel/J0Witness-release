package lab

import (
	"os"
	"path/filepath"
	"strings"
)

// LabTplName identifica la plantilla sintética de laboratorio (fase 2c, Task
// 7): layout PLANO, manifiesto templateDetails.xml (nombre de archivo fijo:
// única forma que manifest.DiscoverCandidates reconoce para plantillas), en
// templates/labtpl/.
const LabTplName = "labtpl"

const labTplManifest = `<?xml version="1.0" encoding="UTF-8"?>
<extension type="template" client="site" method="upgrade">
	<name>labtpl</name>
	<author>Lab Author</author>
	<creationDate>2026-01</creationDate>
	<version>3.0.0</version>
	<description>Plantilla sintética de laboratorio (layout plano)</description>
	<files>
		<filename>index.php</filename>
		<folder>html</folder>
		<folder>css</folder>
	</files>
</extension>
`

// labTplFiles son los archivos instalados de la plantilla, relativos a su
// raíz (templates/labtpl/). index.php y html/com_content/article.php son
// overrides ejecutables; css/template.css es un activo inerte.
func labTplFiles() map[string]string {
	return map[string]string{
		"templates/labtpl/index.php":                    "<?php\n// labtpl entry\n",
		"templates/labtpl/html/com_content/article.php": "<?php\n// labtpl override: com_content article\n",
		"templates/labtpl/css/template.css":             "/* labtpl styling */\nbody { font-family: sans-serif; }\n",
	}
}

// LabTplManifestPath devuelve la ruta del manifiesto instalado.
func LabTplManifestPath() string { return "templates/labtpl/templateDetails.xml" }

// LabTplElementKey es la clave estable (manifest.ExtensionKey para Template:
// el nombre, sin sufijo @administrator).
func LabTplElementKey() string { return LabTplName }

// InstallLabTpl escribe la plantilla sintética legítima dentro de un árbol ya
// existente. No toca el core.
func InstallLabTpl(root string) error {
	files := labTplFiles()
	files[LabTplManifestPath()] = labTplManifest
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

// LabTplPackage construye, de forma determinista, el zip PLANO del "paquete
// oficial" sintético de labtpl: manifiesto + index.php + html/… + css/… en la
// raíz del paquete (sin prefijos).
func LabTplPackage() []byte { return buildLabTplPackage(labTplManifest) }

// LabTplPackageWithVersion construye el mismo paquete pero con otra versión
// declarada (recipe de "versión no coincidente").
func LabTplPackageWithVersion(version string) []byte {
	m := strings.Replace(labTplManifest, "<version>3.0.0</version>", "<version>"+version+"</version>", 1)
	if m == labTplManifest && version != "3.0.0" {
		panic("LabTplPackageWithVersion: no se pudo sustituir la versión en el manifiesto de laboratorio")
	}
	return buildLabTplPackage(m)
}

func buildLabTplPackage(manifestXML string) []byte {
	const prefix = "templates/labtpl/"
	entries := map[string]string{
		"templateDetails.xml": manifestXML,
	}
	for installed, content := range labTplFiles() {
		rel := strings.TrimPrefix(installed, prefix)
		if rel == installed {
			panic("buildLabTplPackage: ruta instalada sin el prefijo esperado: " + installed)
		}
		entries[rel] = content
	}
	return zipDeterministic(entries)
}
