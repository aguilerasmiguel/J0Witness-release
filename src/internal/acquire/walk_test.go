package acquire

import (
	"os"
	"path/filepath"
	"testing"

	"j0witness/internal/safefs"
)

func newFS(t *testing.T, dir string) *safefs.FS {
	t.Helper()
	fsys, err := safefs.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return fsys
}

// T012: recorrido determinista, symlinks no seguidos, ciclos por inode.
func TestWalkDeterministicOrder(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"b/x.php", "a/y.php", "c.php"} {
		full := filepath.Join(dir, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte("x"), 0o644)
	}
	items1 := Walk(newFS(t, dir))
	items2 := Walk(newFS(t, dir))
	if len(items1) != len(items2) {
		t.Fatal("longitudes distintas")
	}
	for i := range items1 {
		if items1[i].RelPath != items2[i].RelPath {
			t.Fatalf("orden inestable en %d: %s vs %s", i, items1[i].RelPath, items2[i].RelPath)
		}
	}
	// Por niveles y lexicográfico dentro de cada nivel: la garantía que
	// importa es la estabilidad (el informe ordena por rel_path en SQL).
	want := []string{"a", "b", "c.php", "a/y.php", "b/x.php"}
	got := paths(items1)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("orden inesperado: %v", got)
		}
	}
}

func paths(items []Item) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.RelPath
	}
	return out
}

func TestWalkSymlinksNotFollowed(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secreto.txt"), []byte("x"), 0o644)
	dir := filepath.Join(root, "site")
	os.MkdirAll(dir, 0o755)
	os.Symlink(outside, filepath.Join(dir, "fuera"))
	os.Symlink(dir, filepath.Join(dir, "bucle")) // symlink a sí mismo (ciclo)

	items := Walk(newFS(t, dir))
	var fuera, bucle *Item
	for i := range items {
		switch items[i].RelPath {
		case "fuera":
			fuera = &items[i]
		case "bucle":
			bucle = &items[i]
		}
	}
	if fuera == nil || fuera.Type != "symlink" || !fuera.SymlinkOut {
		t.Fatalf("symlink fuera del árbol no detectado: %+v", fuera)
	}
	if bucle == nil || bucle.Type != "symlink" {
		t.Fatal("symlink circular no registrado como symlink")
	}
	// No debe haber entradas bajo fuera/ ni bucle/: no se siguen.
	for _, it := range items {
		if len(it.RelPath) > 6 && (it.RelPath[:6] == "fuera/" || it.RelPath[:6] == "bucle/") {
			t.Fatalf("symlink seguido: %s", it.RelPath)
		}
	}
}

func TestWalkHardlinkDup(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.bin")
	os.WriteFile(a, []byte("contenido"), 0o644)
	if err := os.Link(a, filepath.Join(dir, "b.bin")); err != nil {
		t.Skipf("hardlinks no soportados: %v", err)
	}
	items := Walk(newFS(t, dir))
	dups := 0
	for _, it := range items {
		if it.HardlinkDup {
			dups++
		}
	}
	if dups != 1 {
		t.Fatalf("esperaba 1 duplicado por inode, hay %d", dups)
	}
}

// FR-052: profundidad extrema sin desbordar (walker iterativo).
func TestWalkDeepTree(t *testing.T) {
	dir := t.TempDir()
	p := dir
	for i := 0; i < 200; i++ {
		p = filepath.Join(p, "d")
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(p, "hoja.txt"), []byte("x"), 0o644)
	items := Walk(newFS(t, dir))
	if len(items) != 201 {
		t.Fatalf("esperaba 201 entradas, hay %d", len(items))
	}
}
