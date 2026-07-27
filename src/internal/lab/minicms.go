// Package lab contiene la infraestructura de laboratorio: la
// mini-distribución sintética (minicms) para tests herméticos y helpers para
// construir catálogos y paquetes de prueba. Nunca se compila en el binario de
// producción (solo lo importan tests y tools).
package lab

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MiniVersions son las versiones publicadas de la mini-distribución.
var MiniVersions = []string{"1.0.0", "1.1.0"}

// MiniFiles devuelve el contenido de la distribución minicms para una
// versión. Estructura deliberadamente joomla-forme: version.php declarado,
// archivos testigo dispersos y un obsoleto que 1.1.0 dejó de distribuir.
func MiniFiles(version string) map[string]string {
	files := map[string]string{
		"index.php":                                "<?php\ndefine('_MEXEC', 1);\nrequire __DIR__.'/libraries/src/App.php';\necho app_run();\n",
		"administrator/index.php":                  "<?php\ndefine('_MEXEC', 1);\necho 'admin';\n",
		"libraries/src/Version.php":                "<?php\nclass Version {\n    const MAJOR_VERSION = " + major(version) + ";\n    const MINOR_VERSION = " + minor(version) + ";\n    const PATCH_VERSION = " + patch(version) + ";\n}\n",
		"administrator/manifests/files/joomla.xml": "<?xml version=\"1.0\"?>\n<extension><version>" + version + "</version></extension>\n",
		// Testigos: difieren entre versiones y están dispersos por el árbol (R7).
		"libraries/src/App.php":                    "<?php\nfunction app_run() { return 'minicms core v" + version + "'; }\n// build " + version + "\n",
		"libraries/src/Router.php":                 "<?php\nfunction route($p) { return trim($p, '/'); }\n// rev " + version + "\n",
		"media/js/app.js":                          "// minicms front v" + version + "\nconsole.log('app');\n",
		"media/css/app.css":                        "/* minicms v" + version + " */ body { margin: 0; }\n",
		"language/en-GB/en-GB.ini":                 "APP_TITLE=\"MiniCMS " + version + "\"\n",
		"administrator/components/com_app/app.php": "<?php\n// admin component, dist " + version + "\nfunction admin_app() { return 1; }\n",
		"includes/defines.php":                     "<?php\ndefine('MPATH_BASE', __DIR__);\n// snapshot " + version + "\n",
		// Marcador del esqueleto admin estándar (fase 2c, task 5): junto con
		// administrator/components/ y administrator/manifests/ (arriba) hace que
		// minicms sea un layout reconocible por layout.DetectAdmin, para que los
		// negativos del corpus no disparen J0W-LAYOUT-001 (línea base sin FP).
		"administrator/includes/defines.php": "<?php\ndefine('MADMIN_BASE', __DIR__);\n// snapshot " + version + "\n",
		// "images/" ES un directorio de la distribución real de Joomla (lleva un
		// index.html "silencio" para impedir el listado); WriteTree además
		// siembra images/banner.png como contenido de USUARIO en ese mismo
		// directorio (línea ~106, sin tocar). Sin esta entrada, "images" no
		// existiría en el manifiesto y coverage.foreign_roots[].distribution_dir
		// no podría distinguir "dir de Joomla con contenido de usuario" de
		// "raíz genuinamente ajena" (feature 012, Task 3 — refinamiento
		// post-shipping validado en sitio real).
		"images/index.html": "<!-- Silence is golden. -->\n",
		"htaccess.txt":      "# dist htaccess\nOptions -Indexes\n",
		"robots.txt.dist":   "User-agent: *\nDisallow: /administrator/\n",
		// Binario del core (imagen GIF, firma real): presente en la distribución;
		// permite probar la degradación D5 de un archivo inerte modificado (CORE-001).
		"libraries/logo.gif": "GIF89a" + string(bytes.Repeat([]byte{0x01}, 64)),
	}
	// D5c: dos subárboles del baseline con >= collapseThreshold (8) archivos
	// cada uno, para que una receta de corpus pueda borrar el subárbol ENTERO
	// y ejercitar el colapso de CollapseMissingSubtrees (internal/corediff).
	// Presentes en AMBAS versiones (no dependen de `version`) para que estén
	// tanto en el árbol instalado (WriteTree) como en el paquete oficial
	// (PackageZip → manifiesto): borrarlos del árbol los deja "ausentes del
	// baseline". media/vendor/lib/ (8 .js/.css, bajo media/ → clase
	// "inert_asset") ejercita el colapso degradado a low; vendor/pkg/ (8
	// .php → clase "executable", IsExecutable tiene precedencia sobre el
	// prefijo de directorio) ejercita el colapso que se queda en medium.
	//
	// media/vendor/notes.txt y vendor/notes.txt son hermanos que NINGUNA
	// receta borra: mantienen media/vendor/ y vendor/ respectivamente
	// PARCIALMENTE presentes, para que CollapseMissingSubtrees ancle la raíz
	// maximal ausente-por-completo exactamente en .../lib y .../pkg (si
	// media/vendor/ y vendor/ estuvieran también ausentes-por-completo, el
	// colapso subiría un nivel más, como en el diseño de media/vendor/
	// completo — aquí queremos anclar el subject en el subdirectorio, no en
	// el padre).
	files["media/vendor/notes.txt"] = "# vendored assets, not part of minicms core\n"
	files["vendor/notes.txt"] = "vendored packages, not part of minicms core\n"
	for _, f := range []string{"core.js", "core.min.js", "plugin.js", "util.js"} {
		files["media/vendor/lib/"+f] = "// minicms vendor asset: " + f + "\n"
	}
	for _, f := range []string{"theme.css", "theme.min.css", "reset.css", "print.css"} {
		files["media/vendor/lib/"+f] = "/* minicms vendor asset: " + f + " */\n"
	}
	for _, f := range []string{"Autoload", "Cache", "Client", "Config", "Dispatcher", "Event", "Factory", "Registry"} {
		files["vendor/pkg/"+f+".php"] = "<?php\n// minicms vendor package module: " + f + "\nfunction vendor_pkg_" + f + "() { return true; }\n"
	}
	if version == "1.0.0" {
		// Archivo que 1.1.0 elimina: entra en la lista de obsoletos.
		files["libraries/legacy.php"] = "<?php\n// legacy helper, removed in 1.1.0\nfunction legacy() { return 0; }\n"
		files["libraries/old-icon.gif"] = "GIF89a" + string(bytes.Repeat([]byte{0x02}, 48))
	}
	return files
}

func major(v string) string { return strings.Split(v, ".")[0] }
func minor(v string) string { return strings.Split(v, ".")[1] }
func patch(v string) string { return strings.Split(v, ".")[2] }

// WriteTree materializa una instalación minicms en dir.
func WriteTree(dir, version string) error {
	for rel, content := range MiniFiles(version) {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			return err
		}
	}
	// Contenido de usuario habitual: no pertenece a la distribución pero es
	// benigno (los negativos del corpus no deben dispararse con él).
	user := filepath.Join(dir, "images", "banner.png")
	if err := os.MkdirAll(filepath.Dir(user), 0o755); err != nil {
		return err
	}
	// PNG mínimo válido (magic bytes reales para no disparar type_mismatch).
	png := append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, bytes.Repeat([]byte{0}, 64)...)
	if err := os.WriteFile(user, png, 0o644); err != nil {
		return err
	}
	cfg := "<?php\nclass JConfig {\n\tpublic $sitename = 'Lab';\n\tpublic $password = 'SENTINEL_DB_PASSWORD_XYZZY';\n\tpublic $secret = 'SENTINEL_SECRET_PLUGH';\n\tpublic $user = 'labuser';\n\tpublic $db = 'labdb';\n\tpublic $host = 'localhost';\n}\n"
	return os.WriteFile(filepath.Join(dir, "configuration.php"), []byte(cfg), 0o644)
}

// Sentinels son los valores centinela sembrados en configuration.php; los
// tests T021 verifican que jamás aparecen en informe ni inventario (FR-047).
var Sentinels = []string{"SENTINEL_DB_PASSWORD_XYZZY", "SENTINEL_SECRET_PLUGH"}

// PackageZip construye en memoria el paquete oficial de una versión y
// devuelve (contenido, sha256hex). Orden de entradas determinista.
func PackageZip(version string) ([]byte, string, error) {
	files := MiniFiles(version)
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, p := range paths {
		fw, err := w.Create(p)
		if err != nil {
			return nil, "", err
		}
		if _, err := fw.Write([]byte(files[p])); err != nil {
			return nil, "", err
		}
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:]), nil
}

// FileSHA es el sha256 hex del contenido de un archivo de la distribución.
func FileSHA(version, rel string) string {
	content, ok := MiniFiles(version)[rel]
	if !ok {
		return ""
	}
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// WitnessPaths es el conjunto testigo de minicms (disperso, discriminante).
var WitnessPaths = []string{
	"libraries/src/App.php",
	"libraries/src/Router.php",
	"media/js/app.js",
	"media/css/app.css",
	"language/en-GB/en-GB.ini",
	"administrator/components/com_app/app.php",
	"includes/defines.php",
}

// CatalogJSON construye el catálogo de prueba para minicms en el formato del
// paquete baseline, con paquetes, testigos y obsoletos.
func CatalogJSON() ([]byte, error) {
	type witness struct {
		Path     string            `json:"path"`
		Branches []string          `json:"branches"`
		Hashes   map[string]string `json:"hashes"`
	}
	type knownFile struct {
		Path   string   `json:"path"`
		Hashes []string `json:"hashes"`
	}
	type release struct {
		Version       string `json:"version"`
		PackageSHA256 string `json:"package_sha256"`
	}
	var releases []release
	for _, v := range MiniVersions {
		_, sha, err := PackageZip(v)
		if err != nil {
			return nil, err
		}
		releases = append(releases, release{Version: v, PackageSHA256: sha})
	}
	witnesses := make([]witness, 0, len(WitnessPaths))
	for _, p := range WitnessPaths {
		h := map[string]string{}
		for _, v := range MiniVersions {
			if s := FileSHA(v, p); s != "" {
				h[v] = s
			}
		}
		// Todas las versiones de minicms son de la rama 1: el acotado por rama
		// se ejercita igual, con un único conjunto.
		witnesses = append(witnesses, witness{Path: p, Branches: []string{"1"}, Hashes: h})
	}
	// known_files: toda ruta que alguna versión distribuyó, con sus hashes (R6
	// enmendado). libraries/legacy.php entra solo: 1.0.0 lo distribuye y 1.1.0
	// no, así que al escanear 1.1.0 queda fuera del baseline y es obsoleto.
	byPath := map[string]map[string]bool{}
	for _, v := range MiniVersions {
		for p := range MiniFiles(v) {
			if byPath[p] == nil {
				byPath[p] = map[string]bool{}
			}
			byPath[p][FileSHA(v, p)] = true
		}
	}
	paths := make([]string, 0, len(byPath))
	for p := range byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	knownFiles := make([]knownFile, 0, len(paths))
	for _, p := range paths {
		hs := make([]string, 0, len(byPath[p]))
		for h := range byPath[p] {
			hs = append(hs, h)
		}
		sort.Strings(hs)
		knownFiles = append(knownFiles, knownFile{Path: p, Hashes: hs})
	}
	catalog := map[string]any{
		"catalog_version": "lab-1",
		"cms":             "joomla",
		"releases":        releases,
		"witnesses":       witnesses,
		"known_files":     knownFiles,
	}
	return jsonMarshal(catalog)
}

func jsonMarshal(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// WriteCatalog escribe el catálogo de prueba a un archivo y devuelve su ruta.
func WriteCatalog(dir string) (string, error) {
	data, err := CatalogJSON()
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return "", err
	}
	return p, nil
}

// WritePackage escribe el paquete zip de una versión y devuelve su ruta.
func WritePackage(dir, version string) (string, error) {
	data, _, err := PackageZip(version)
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, fmt.Sprintf("MiniCMS_%s.zip", version))
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return "", err
	}
	return p, nil
}
