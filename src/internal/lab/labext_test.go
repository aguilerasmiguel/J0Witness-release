package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"j0witness/internal/extbaseline"
)

// TestLabExtPackageMatchesInstall es el requisito crítico de corrección del
// corpus de verificación de extensiones (fase 2a, Task 6): si LabExtPackage
// no simula EXACTAMENTE lo que InstallLabExt escribe, el recipe "verificado"
// emitiría J0W-EXT-008 falsos. Compara el conjunto ruta instalada→sha256 que
// devuelve extbaseline.SimulateComponent sobre LabExtPackage() contra el
// hash real de cada archivo que labExtFiles()+el manifiesto declaran (la
// MISMA fuente de verdad que usa InstallLabExt).
func TestLabExtPackageMatchesInstall(t *testing.T) {
	pkg := LabExtPackage()
	version, files, pkgSHA, err := extbaseline.SimulateComponent(LabExtName, pkg)
	if err != nil {
		t.Fatalf("SimulateComponent: %v", err)
	}
	if version != "2.3.1" {
		t.Fatalf("version=%q, esperaba 2.3.1 (la del manifiesto de laboratorio)", version)
	}
	if pkgSHA == "" {
		t.Fatal("pkgSHA vacío")
	}

	want := labExtFiles()
	want[LabExtManifestPath()] = labExtManifest

	if len(files) != len(want) {
		t.Fatalf("simulación produjo %d rutas, InstallLabExt escribe %d\nsimuladas: %v\nesperadas: %v",
			len(files), len(want), sortedKeysOf(files), sortedKeysOf(want))
	}
	for path, content := range want {
		wantSum := sha256.Sum256([]byte(content))
		wantHash := hex.EncodeToString(wantSum[:])
		gotHash, ok := files[path]
		if !ok {
			t.Fatalf("falta en la simulación la ruta instalada %s (InstallLabExt SÍ la escribe)", path)
		}
		if gotHash != wantHash {
			t.Fatalf("ruta %s: hash simulado=%s, hash real=%s (contenido distinto)", path, gotHash, wantHash)
		}
	}
}

// TestLabExtPackageWithVersionDiffers confirma que el paquete con versión
// sustituida declara esa otra versión mientras conserva los mismos archivos
// (mismo mapeo, solo cambia <version>).
func TestLabExtPackageWithVersionDiffers(t *testing.T) {
	pkg := LabExtPackageWithVersion("9.9.9")
	version, files, _, err := extbaseline.SimulateComponent(LabExtName, pkg)
	if err != nil {
		t.Fatalf("SimulateComponent: %v", err)
	}
	if version != "9.9.9" {
		t.Fatalf("version=%q, esperaba 9.9.9", version)
	}
	want := labExtFiles()
	want[LabExtManifestPath()] = labExtManifest
	if len(files) != len(want) {
		t.Fatalf("el paquete con versión sustituida no conserva el mismo conjunto de rutas: %v", sortedKeysOf(files))
	}
}

func sortedKeysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
