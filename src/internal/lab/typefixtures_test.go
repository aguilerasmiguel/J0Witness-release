package lab

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"j0witness/internal/extbaseline"
	"j0witness/internal/manifest"
)

// assertPackageMatchesInstall es el oráculo común de las pruebas de
// round-trip de fase 2c (Task 7, module/plugin/template/library): tras
// instalar UNA fixture (y solo esa) en un árbol temporal vacío, compara
// SimulateExtension(target, pkg) contra el sha256 REAL de cada archivo que la
// instalación escribió, recorriendo el árbol entero — no una lista fijada a
// mano (labext_test.go sí la fija, porque labExtFiles() ya es esa fuente de
// verdad para el componente; aquí se recorre el disco para no duplicarla por
// cada tipo). Si la simulación produce una ruta de más o de menos, o un hash
// distinto, el test falla: es exactamente el requisito de Task 2
// (SimulateExtension(target, LabXPackage()) == InstallLabX(tree)).
func assertPackageMatchesInstall(t *testing.T, dir, manifestRelPath string, pkg []byte, wantVersion string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, manifestRelPath))
	if err != nil {
		t.Fatalf("leyendo manifiesto instalado %s: %v", manifestRelPath, err)
	}
	m, err := manifest.Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parseando manifiesto instalado: %v", err)
	}
	target := m.ResolveInstall(manifestRelPath)

	version, files, pkgSHA, err := extbaseline.SimulateExtension(target, pkg)
	if err != nil {
		t.Fatalf("SimulateExtension: %v", err)
	}
	if version != wantVersion {
		t.Fatalf("version=%q, esperaba %q", version, wantVersion)
	}
	if pkgSHA == "" {
		t.Fatal("pkgSHA vacío")
	}
	sumPkg := sha256.Sum256(pkg)
	if pkgSHA != hex.EncodeToString(sumPkg[:]) {
		t.Fatalf("pkgSHA no coincide con sha256(pkgRaw): %s", pkgSHA)
	}

	want := map[string]string{} // ruta instalada (relativa a dir) -> sha256 real
	walkErr := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		want[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if walkErr != nil {
		t.Fatalf("recorriendo el árbol instalado: %v", walkErr)
	}

	if len(files) != len(want) {
		t.Fatalf("simulación produjo %d rutas, el árbol instalado tiene %d\nsimuladas: %v\ninstaladas: %v",
			len(files), len(want), sortedKeysOf(files), sortedKeysOf(want))
	}
	for path, wantHash := range want {
		gotHash, ok := files[path]
		if !ok {
			t.Fatalf("falta en la simulación la ruta instalada %s (el árbol SÍ la tiene)", path)
		}
		if gotHash != wantHash {
			t.Fatalf("ruta %s: hash simulado=%s, hash real=%s (contenido distinto)", path, gotHash, wantHash)
		}
	}
}

// --- plugin (layout plano) ---

func TestLabPlgPackageMatchesInstall(t *testing.T) {
	dir := t.TempDir()
	if err := InstallLabPlg(dir); err != nil {
		t.Fatal(err)
	}
	assertPackageMatchesInstall(t, dir, LabPlgManifestPath(), LabPlgPackage(), "1.4.0")
}

func TestLabPlgPackageWithVersionDiffers(t *testing.T) {
	target := manifest.InstallTarget{
		Type: manifest.Plugin, ElementKey: LabPlgElementKey(),
		FilesRoot: "plugins/system/labplg", ManifestDir: "plugins/system/labplg",
		MediaBase: "media", MediaFallback: LabPlgElementKey(),
	}
	version, files, _, err := extbaseline.SimulateExtension(target, LabPlgPackageWithVersion("9.9.9"))
	if err != nil {
		t.Fatalf("SimulateExtension: %v", err)
	}
	if version != "9.9.9" {
		t.Fatalf("version=%q, esperaba 9.9.9", version)
	}

	_, baseFiles, _, err := extbaseline.SimulateExtension(target, LabPlgPackage())
	if err != nil {
		t.Fatalf("SimulateExtension (paquete base): %v", err)
	}
	if len(files) != len(baseFiles) {
		t.Fatalf("el paquete con versión sustituida no conserva el mismo conjunto de rutas: %v vs %v", sortedKeysOf(files), sortedKeysOf(baseFiles))
	}
}

// --- módulo (layout plano, variantes site y admin) ---

func TestLabModPackageMatchesInstallSite(t *testing.T) {
	dir := t.TempDir()
	if err := InstallLabMod(dir); err != nil {
		t.Fatal(err)
	}
	assertPackageMatchesInstall(t, dir, LabModManifestPath(), LabModPackage(), "1.2.0")
}

// TestLabModPackageMatchesInstallAdmin: la variante admin instala el MISMO
// contenido bajo administrator/modules/mod_labmod/ — el mismo LabModPackage()
// simula correctamente ambas variantes porque el mapeo depende de las raíces
// del InstallTarget (derivadas del directorio del manifiesto), no del
// paquete (ver comentario de LabModPackage).
func TestLabModPackageMatchesInstallAdmin(t *testing.T) {
	dir := t.TempDir()
	if err := InstallLabModAdmin(dir); err != nil {
		t.Fatal(err)
	}
	assertPackageMatchesInstall(t, dir, LabModAdminManifestPath(), LabModPackage(), "1.2.0")
}

func TestLabModPackageWithVersionDiffers(t *testing.T) {
	target := manifest.InstallTarget{
		Type: manifest.Module, ElementKey: LabModElementKey(),
		FilesRoot: "modules/mod_labmod", ManifestDir: "modules/mod_labmod",
		MediaBase: "media", MediaFallback: LabModElementKey(),
	}
	version, files, _, err := extbaseline.SimulateExtension(target, LabModPackageWithVersion("9.9.9"))
	if err != nil {
		t.Fatalf("SimulateExtension: %v", err)
	}
	if version != "9.9.9" {
		t.Fatalf("version=%q, esperaba 9.9.9", version)
	}

	_, baseFiles, _, err := extbaseline.SimulateExtension(target, LabModPackage())
	if err != nil {
		t.Fatalf("SimulateExtension (paquete base): %v", err)
	}
	if len(files) != len(baseFiles) {
		t.Fatalf("el paquete con versión sustituida no conserva el mismo conjunto de rutas: %v vs %v", sortedKeysOf(files), sortedKeysOf(baseFiles))
	}
}

// --- plantilla (layout plano) ---

func TestLabTplPackageMatchesInstall(t *testing.T) {
	dir := t.TempDir()
	if err := InstallLabTpl(dir); err != nil {
		t.Fatal(err)
	}
	assertPackageMatchesInstall(t, dir, LabTplManifestPath(), LabTplPackage(), "3.0.0")
}

func TestLabTplPackageWithVersionDiffers(t *testing.T) {
	target := manifest.InstallTarget{
		Type: manifest.Template, ElementKey: LabTplElementKey(),
		FilesRoot: "templates/labtpl", ManifestDir: "templates/labtpl",
		MediaBase: "media", MediaFallback: LabTplElementKey(),
	}
	version, files, _, err := extbaseline.SimulateExtension(target, LabTplPackageWithVersion("9.9.9"))
	if err != nil {
		t.Fatalf("SimulateExtension: %v", err)
	}
	if version != "9.9.9" {
		t.Fatalf("version=%q, esperaba 9.9.9", version)
	}

	_, baseFiles, _, err := extbaseline.SimulateExtension(target, LabTplPackage())
	if err != nil {
		t.Fatalf("SimulateExtension (paquete base): %v", err)
	}
	if len(files) != len(baseFiles) {
		t.Fatalf("el paquete con versión sustituida no conserva el mismo conjunto de rutas: %v vs %v", sortedKeysOf(files), sortedKeysOf(baseFiles))
	}
}

// --- librería (raíz por <libraryname>, manifiesto en subdirectorio) ---

func TestLabLibPackageMatchesInstall(t *testing.T) {
	dir := t.TempDir()
	if err := InstallLabLib(dir); err != nil {
		t.Fatal(err)
	}
	assertPackageMatchesInstall(t, dir, LabLibManifestPath(), LabLibPackage(), "4.1.0")
}

func TestLabLibPackageWithVersionDiffers(t *testing.T) {
	target := manifest.InstallTarget{
		Type: manifest.Library, ElementKey: LabLibElementKey(),
		FilesRoot: "libraries/labvendor/lablib", ManifestDir: "administrator/manifests/libraries/labvendor",
		MediaBase: "media", MediaFallback: LabLibElementKey(),
	}
	version, files, _, err := extbaseline.SimulateExtension(target, LabLibPackageWithVersion("9.9.9"))
	if err != nil {
		t.Fatalf("SimulateExtension: %v", err)
	}
	if version != "9.9.9" {
		t.Fatalf("version=%q, esperaba 9.9.9", version)
	}

	_, baseFiles, _, err := extbaseline.SimulateExtension(target, LabLibPackage())
	if err != nil {
		t.Fatalf("SimulateExtension (paquete base): %v", err)
	}
	if len(files) != len(baseFiles) {
		t.Fatalf("el paquete con versión sustituida no conserva el mismo conjunto de rutas: %v vs %v", sortedKeysOf(files), sortedKeysOf(baseFiles))
	}
}
