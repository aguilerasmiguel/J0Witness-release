package baseline

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"j0witness/internal/inventory"
)

// helper: build a stored manifest map + its canonical manSHA from entries.
func manOf(entries []inventory.Entry) (map[string]ManifestEntry, string) {
	m := map[string]ManifestEntry{}
	for _, e := range entries {
		m[string(e.RelPath)] = ManifestEntry{SHA256: e.SHA256, Size: e.Size}
	}
	return m, manifestSHA(entries)
}

func TestVerifyPackageIdentityMismatch(t *testing.T) {
	rel := Release{Version: "1.0", PackageSHA256: "CATALOG_SHA"}
	_, err := Verify(rel, "cms-1.0", "OTHER_SHA", "manX", nil, t.TempDir(), "1.0")
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("pkgSHA distinto al catálogo debe dar ErrUntrusted, got %v", err)
	}
}

func TestVerifyPartialWhenPackageNotCached(t *testing.T) {
	entries := []inventory.Entry{{RelPath: []byte("a.php"), SHA256: "h1", Size: 1}, {RelPath: []byte("b.php"), SHA256: "h2", Size: 2}}
	man, manSHA := manOf(entries)
	rel := Release{Version: "1.0", PackageSHA256: "PKG"}
	v, err := Verify(rel, "cms-1.0", "PKG", manSHA, man, t.TempDir(), "1.0") // cacheDir vacío → no cacheado
	if err != nil {
		t.Fatalf("no debe fallar (identidad OK, sin paquete): %v", err)
	}
	if v.Assurance != "partial" || v.ManifestSource != "stored-self-consistent" {
		t.Errorf("assurance = %+v, want partial/stored-self-consistent", v)
	}
}

func TestVerifyPartialDetectsTamperedManifestRows(t *testing.T) {
	entries := []inventory.Entry{{RelPath: []byte("a.php"), SHA256: "h1", Size: 1}}
	man, manSHA := manOf(entries)
	man["a.php"] = ManifestEntry{SHA256: "TAMPERED", Size: 1} // fila alterada, manSHA sin recomputar
	rel := Release{Version: "1.0", PackageSHA256: "PKG"}
	_, err := Verify(rel, "cms-1.0", "PKG", manSHA, man, t.TempDir(), "1.0")
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("manifiesto alterado (sin paquete) debe dar ErrUntrusted por auto-consistencia, got %v", err)
	}
}

// writeTestZip escribe un zip minimalista con los archivos dados en
// <cacheDir>/packages/<version>.zip (la ruta que espera OpenContent) y
// devuelve el sha256 hex del paquete resultante.
func writeTestZip(t *testing.T, cacheDir, version string, files map[string]string) string {
	t.Helper()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, n := range names {
		fw, err := w.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(files[n])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if err := os.MkdirAll(filepath.Join(cacheDir, "packages"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "packages", version+".zip"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// manifestOfContentMap deriva el manifiesto almacenado (map[string]ManifestEntry)
// y su manSHA canónico a partir de las mismas rutas→contenido usadas para
// construir el zip cacheado, tal como Add lo haría a partir del zip real.
func manifestOfContentMap(files map[string]string) (map[string]ManifestEntry, string) {
	entries := make([]inventory.Entry, 0, len(files))
	man := map[string]ManifestEntry{}
	for n, c := range files {
		sum := sha256.Sum256([]byte(c))
		sha := hex.EncodeToString(sum[:])
		entries = append(entries, inventory.Entry{RelPath: []byte(n), SHA256: sha, Size: int64(len(c))})
		man[n] = ManifestEntry{SHA256: sha, Size: int64(len(c))}
	}
	return man, manifestSHA(entries)
}

func TestVerifyVerifiedWithCachedPackage(t *testing.T) {
	files := map[string]string{"a.php": "uno", "b.php": "dos"}
	cacheDir := t.TempDir()
	pkgSHA := writeTestZip(t, cacheDir, "1.0", files)
	man, manSHA := manifestOfContentMap(files)
	rel := Release{Version: "1.0", PackageSHA256: pkgSHA}

	v, err := Verify(rel, "cms-1.0", pkgSHA, manSHA, man, cacheDir, "1.0")
	if err != nil {
		t.Fatalf("paquete cacheado íntegro no debe fallar: %v", err)
	}
	if v.Assurance != "verified" || v.ManifestSource != "rederived-from-verified-package" {
		t.Errorf("assurance = %+v, want verified/rederived-from-verified-package", v)
	}
	if v.PackageSHA256 != pkgSHA || v.CatalogVersion != "cms-1.0" {
		t.Errorf("metadata de Verification incompleta: %+v", v)
	}
}

func TestVerifyUntrustedWhenCachedPackageCorrupted(t *testing.T) {
	files := map[string]string{"a.php": "uno"}
	cacheDir := t.TempDir()
	pkgSHA := writeTestZip(t, cacheDir, "1.0", files)
	man, manSHA := manifestOfContentMap(files)
	rel := Release{Version: "1.0", PackageSHA256: pkgSHA}

	// Corrompe el zip cacheado en disco tras haber fijado pkgSHA en el catálogo.
	corrupted := filepath.Join(cacheDir, "packages", "1.0.zip")
	if err := os.WriteFile(corrupted, []byte("PK\x03\x04no-es-el-zip-original"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Verify(rel, "cms-1.0", pkgSHA, manSHA, man, cacheDir, "1.0")
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("paquete cacheado manipulado debe dar ErrUntrusted (vía ErrPackageMismatch), got %v", err)
	}
	if !errors.Is(err, ErrPackageMismatch) {
		t.Errorf("el error debe seguir envolviendo ErrPackageMismatch, got %v", err)
	}
}

func TestVerifyUntrustedWhenStoredManifestSHAWrong(t *testing.T) {
	files := map[string]string{"a.php": "uno"}
	cacheDir := t.TempDir()
	pkgSHA := writeTestZip(t, cacheDir, "1.0", files)
	man, _ := manifestOfContentMap(files)
	rel := Release{Version: "1.0", PackageSHA256: pkgSHA}

	_, err := Verify(rel, "cms-1.0", pkgSHA, "MANSHA_INCORRECTO", man, cacheDir, "1.0")
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("manSHA almacenado distinto del re-derivado debe dar ErrUntrusted, got %v", err)
	}
}
