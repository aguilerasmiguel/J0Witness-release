package corpus

import (
	"os"
	"path/filepath"
	"testing"
)

// stubProvider es un BaseProvider mínimo para probar apply() sin depender de
// ninguna distribución base real (minicms/Joomla). WriteBase es un no-op
// (apply() no la invoca; solo Materialize lo hace) y FileContent siempre
// falla la búsqueda, salvo que un caso concreto necesite lo contrario.
type stubProvider struct{}

func (stubProvider) WriteBase(dir, version string) error { return nil }

func (stubProvider) FileContent(version, rel string) ([]byte, bool) { return nil, false }

// panicOnFileContent es un BaseProvider cuyo FileContent entra en pánico si
// se invoca: lo usamos para demostrar que requireWithinCase rechaza una ruta
// fuera del caso ANTES de que overlay_version llegue a tocar el provider.
type panicOnFileContent struct{}

func (panicOnFileContent) WriteBase(dir, version string) error { return nil }

func (panicOnFileContent) FileContent(version, rel string) ([]byte, bool) {
	panic("FileContent no debería alcanzarse: el guard de path-traversal debe disparar antes")
}

func TestApplyRejectsPathTraversal_AddFile(t *testing.T) {
	dir := t.TempDir()
	err := apply(stubProvider{}, dir, Mutation{Op: "add_file", Path: "../escape.txt", Content: "x"})
	if err == nil {
		t.Fatal("se esperaba error por path fuera del caso, se obtuvo nil")
	}
}

func TestApplyRejectsPathTraversal_DeepTree(t *testing.T) {
	dir := t.TempDir()
	err := apply(stubProvider{}, dir, Mutation{Op: "deep_tree", At: "../escape", Depth: 2})
	if err == nil {
		t.Fatal("se esperaba error por at fuera del caso, se obtuvo nil")
	}
}

func TestApplyRejectsPathTraversal_OverlayVersion(t *testing.T) {
	dir := t.TempDir()
	// panicOnFileContent demuestra que el guard dispara ANTES de tocar el
	// provider: si el guard no disparara primero, este test fallaría por
	// pánico en vez de por el error esperado.
	err := apply(panicOnFileContent{}, dir, Mutation{Op: "overlay_version", Paths: []string{"../escape"}, Version: "1.0.0"})
	if err == nil {
		t.Fatal("se esperaba error por path fuera del caso, se obtuvo nil")
	}
}

func TestApplyRejectsPathTraversal_RenameDirTarget(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "administrator"), 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	err := apply(stubProvider{}, dir, Mutation{Op: "rename_dir", Path: "administrator", Target: "../escape"})
	if err == nil {
		t.Fatal("se esperaba error por target fuera del caso, se obtuvo nil")
	}
}

func TestApplySymlinkTargetStaysFree(t *testing.T) {
	dir := t.TempDir()
	err := apply(stubProvider{}, dir, Mutation{Op: "symlink", Path: "link", Target: "/etc/passwd"})
	if err != nil {
		t.Fatalf("symlink con target fuera del árbol no debe rechazarse: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(dir, "link"))
	if err != nil {
		t.Fatalf("el symlink debería existir: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("se esperaba que link fuera un symlink")
	}
}

func TestApplyAddFileWithinCaseSucceeds(t *testing.T) {
	dir := t.TempDir()
	err := apply(stubProvider{}, dir, Mutation{Op: "add_file", Path: "sub/ok.txt", Content: "ok"})
	if err != nil {
		t.Fatalf("add_file dentro del caso no debería fallar: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sub/ok.txt")); err != nil {
		t.Fatalf("el archivo debería existir: %v", err)
	}
}
