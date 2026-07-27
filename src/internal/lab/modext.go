package lab

import (
	"os"
	"path/filepath"
	"strings"
)

// LabModElement identifica mod_labmod: el módulo sintético de laboratorio en
// layout PLANO (fase 2c, Task 7). Se instala en dos variantes con el MISMO
// contenido relativo (labModRelFiles) pero raíces distintas:
//   - site:  modules/mod_labmod/
//   - admin: administrator/modules/mod_labmod/
//
// La raíz de instalación de un módulo se deriva del DIRECTORIO del manifiesto
// (sectionRootsFor, caso Module), no de un atributo `client=` del propio
// manifiesto — así que el mismo texto de manifiesto sirve para ambas
// variantes; solo cambia dónde se escribe.
const LabModElement = "mod_labmod"

const labModManifest = `<?xml version="1.0" encoding="UTF-8"?>
<extension type="module" client="site" method="upgrade">
	<name>mod_labmod</name>
	<author>Lab Author</author>
	<creationDate>2026-01</creationDate>
	<version>1.2.0</version>
	<description>Módulo sintético de laboratorio (layout plano)</description>
	<files>
		<filename>mod_labmod.php</filename>
		<folder>tmpl</folder>
	</files>
</extension>
`

// labModRelFiles son los archivos del módulo, relativos a SU PROPIA raíz de
// instalación (sin prefijo): el mismo conjunto sirve para la variante site y
// la variante admin, montado bajo raíces distintas.
func labModRelFiles() map[string]string {
	return map[string]string{
		"mod_labmod.php":   "<?php\n// mod_labmod entry\nfunction mod_labmod_render() {}\n",
		"tmpl/default.php": "<?php\n// mod_labmod tmpl\n",
		"tmpl/default.css": "/* mod_labmod styling */\n.mod-labmod { display: block; }\n",
	}
}

// LabModManifestPath / LabModAdminManifestPath devuelven la ruta del
// manifiesto instalado para cada variante.
func LabModManifestPath() string      { return "modules/mod_labmod/mod_labmod.xml" }
func LabModAdminManifestPath() string { return "administrator/modules/mod_labmod/mod_labmod.xml" }

// LabModElementKey es la clave estable de la variante site (manifest.
// ExtensionKey para Module sin sufijo @administrator).
func LabModElementKey() string { return LabModElement }

// installLabModAt escribe la variante del módulo cuya raíz de instalación es
// installRoot (p.ej. "modules/mod_labmod" o "administrator/modules/mod_labmod").
func installLabModAt(root, installRoot string) error {
	files := map[string]string{
		installRoot + "/mod_labmod.xml": labModManifest,
	}
	for rel, content := range labModRelFiles() {
		files[installRoot+"/"+rel] = content
	}
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

// InstallLabMod escribe la variante SITE de mod_labmod (modules/mod_labmod/).
func InstallLabMod(root string) error { return installLabModAt(root, "modules/mod_labmod") }

// InstallLabModAdmin escribe la variante ADMIN de mod_labmod
// (administrator/modules/mod_labmod/): mismo contenido relativo, raíz
// distinta. Sirve al round-trip de la variante admin (fase 2c, Task 7); no se
// wirea a una receta de corpus (el matrix de recetas usa la variante site).
func InstallLabModAdmin(root string) error {
	return installLabModAt(root, "administrator/modules/mod_labmod")
}

// LabModPackage construye, de forma determinista, el zip PLANO del "paquete
// oficial" sintético de mod_labmod: manifiesto + mod_labmod.php + tmpl/… en
// la raíz del paquete. El MISMO paquete simula correctamente ambas variantes
// de instalación (site y admin): SimulateExtension usa las raíces del
// InstallTarget, no el paquete, para decidir dónde caen los archivos.
func LabModPackage() []byte { return buildLabModPackage(labModManifest) }

// LabModPackageWithVersion construye el mismo paquete pero con otra versión
// declarada (recipe de "versión no coincidente").
func LabModPackageWithVersion(version string) []byte {
	m := strings.Replace(labModManifest, "<version>1.2.0</version>", "<version>"+version+"</version>", 1)
	if m == labModManifest && version != "1.2.0" {
		panic("LabModPackageWithVersion: no se pudo sustituir la versión en el manifiesto de laboratorio")
	}
	return buildLabModPackage(m)
}

func buildLabModPackage(manifestXML string) []byte {
	entries := map[string]string{
		"mod_labmod.xml": manifestXML,
	}
	for rel, content := range labModRelFiles() {
		entries[rel] = content
	}
	return zipDeterministic(entries)
}
