package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"j0witness/internal/inventory"
	"j0witness/internal/lab"
)

func labCatalog(t *testing.T) *Catalog {
	t.Helper()
	p, err := lab.WriteCatalog(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cat, err := LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

// T023: verificación contra catálogo, derivación de manifiesto, persistencia.
func TestAddVerifiedPackage(t *testing.T) {
	cat := labCatalog(t)
	store, err := inventory.Open(filepath.Join(t.TempDir(), "inv.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	pkg, err := lab.WritePackage(t.TempDir(), "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	version, manifestSHA, err := Add(cat, store, pkg, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if version != "1.0.0" || manifestSHA == "" {
		t.Fatalf("version=%s manifest=%s", version, manifestSHA)
	}
	man, err := Manifest(store, "joomla", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if man["index.php"].SHA256 != lab.FileSHA("1.0.0", "index.php") {
		t.Fatal("manifiesto no coincide con la distribución")
	}
	if _, ok := man["libraries/legacy.php"]; !ok {
		t.Fatal("falta el archivo que 1.1.0 declara obsoleto")
	}
}

// T023: rechazo de paquete cuyo hash no figura en el catálogo.
func TestAddRejectsUnknownPackage(t *testing.T) {
	cat := labCatalog(t)
	store, _ := inventory.Open(filepath.Join(t.TempDir(), "inv.sqlite"))
	defer store.Close()

	fake := filepath.Join(t.TempDir(), "malicioso.zip")
	if err := os.WriteFile(fake, []byte("PK\x03\x04no-es-el-paquete-oficial"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Add(cat, store, fake, t.TempDir()); err == nil {
		t.Fatal("un paquete desconocido debe rechazarse")
	}
}
