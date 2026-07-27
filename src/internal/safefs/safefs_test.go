package safefs

import (
	"os"
	"path/filepath"
	"testing"
)

// T005: la API de safefs no expone escritura y abre en solo lectura con
// degradación silenciosa de O_NOATIME.
func TestOpenIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(target, []byte("evidencia"), 0o644); err != nil {
		t.Fatal(err)
	}
	fsys, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := fsys.Open("a.txt")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	// Escribir sobre el descriptor debe fallar: está abierto O_RDONLY.
	if _, err := f.Write([]byte("x")); err == nil {
		t.Fatal("el descriptor admite escritura; debe ser solo lectura")
	}
	buf := make([]byte, 9)
	if _, err := f.Read(buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf) != "evidencia" {
		t.Fatalf("leído %q", buf)
	}
}

// T005: O_NOATIME sin privilegio degrada sin error (archivo de otro uid no es
// reproducible en test sin root; verificamos que la ruta de degradación
// funciona forzando el flag).
func TestNoatimeDegradation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fsys, _ := New(dir)
	fsys.noatimeFailed = true // simula EPERM previo
	f, err := fsys.Open("b.txt")
	if err != nil {
		t.Fatalf("Open degradado: %v", err)
	}
	f.Close()
}

func TestRawStatExposesInode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fsys, _ := New(dir)
	info, err := fsys.Lstat("c.txt")
	if err != nil {
		t.Fatal(err)
	}
	st, ok := RawStat(info)
	if !ok || st.Ino == 0 {
		t.Fatal("RawStat no expone inode")
	}
}
