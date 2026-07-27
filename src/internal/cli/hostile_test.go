package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"j0witness/internal/lab"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// T053 (FR-052): árboles hostiles — profundidad extrema, nombres adversarios,
// symlinks circulares y entradas ilegibles — sin cuelgue, sin desborde y sin
// romper la salida.
func TestHostileTree(t *testing.T) {
	h := newHarness(t)
	target := filepath.Join(h.root, "hostil")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	// Instalación válida de base para que el escaneo llegue a completarse.
	if err := writeMinicmsInto(target); err != nil {
		t.Fatal(err)
	}
	// Profundidad extrema.
	deep := filepath.Join(target, "tmp")
	for i := 0; i < 300; i++ {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(deep, "hoja.txt"), "x")
	// Nombres adversarios.
	writeFile(t, filepath.Join(target, "logs", "con\nsalto.log"), "x")
	if err := os.WriteFile(filepath.Join(target, "logs", string([]byte{0xff, 0xfe})+".bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Symlink circular y symlink fuera del árbol.
	if err := os.Symlink(target, filepath.Join(target, "bucle")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(target, "fuera")); err != nil {
		t.Fatal(err)
	}
	// Entrada ilegible.
	secret := filepath.Join(target, "cache", "secreto.dat")
	writeFile(t, secret, "x")
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(secret, 0o644) //nolint:errcheck

	done := make(chan struct{})
	var exit int
	var doc []byte
	go func() {
		defer close(done)
		exit, doc, _ = h.run(t, "scan", target)
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("el escaneo de un árbol hostil se colgó (FR-052)")
	}
	if exit > 1 {
		t.Fatalf("el árbol hostil rompió el escaneo: exit %d", exit)
	}
	p := parseReport(t, doc) // la salida sigue siendo JSON válido
	_ = p
	if os.Getuid() != 0 {
		// FR-007: la entrada ilegible aparece en la cobertura, nunca silencio.
		if !contains(string(doc), "read_denied") {
			t.Fatal("entrada ilegible sin declarar en coverage.not_analyzed")
		}
	}
}

func writeMinicmsInto(target string) error {
	return lab.WriteTree(target, "1.1.0")
}
