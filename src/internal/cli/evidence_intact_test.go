package cli

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"syscall"
	"testing"
)

// treeSnapshot captura los atributos de todo el árbol (Principio I).
func treeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	snap := map[string]string{}
	err := filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return nil // entradas ilegibles: su ausencia de cambio se verifica por el resto
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		snap[rel] = fmt.Sprintf("size=%d mode=%o mtime=%d.%d ctime=%d.%d uid=%d gid=%d nlink=%d",
			info.Size(), info.Mode(), st.Mtim.Sec, st.Mtim.Nsec, st.Ctim.Sec, st.Ctim.Nsec,
			st.Uid, st.Gid, st.Nlink)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// T042 (SC-006, escenario 9): tras un escaneo completo ningún mtime, ctime,
// contenido, permiso o entrada de directorio del árbol ha cambiado, y no
// existe ningún archivo nuevo dentro de él.
func TestEvidenceIntact(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{"clean-minicms", "core-injected-line"} {
		t.Run(name, func(t *testing.T) {
			// Materializa primero, snapshot después, escaneo, re-snapshot.
			r, _, _, _ := h.scanCase(t, name) // primer escaneo materializa el caso
			target := filepath.Join(h.root, "case-"+r.Case)

			before := treeSnapshot(t, target)
			if exit, _, stderr := h.run(t, "scan", target); exit > 1 {
				t.Fatalf("re-escaneo falló: %d\n%s", exit, stderr)
			}
			after := treeSnapshot(t, target)

			if len(before) != len(after) {
				t.Fatalf("el número de entradas cambió: %d → %d", len(before), len(after))
			}
			for rel, b := range before {
				a, ok := after[rel]
				if !ok {
					t.Errorf("entrada desaparecida: %s", rel)
					continue
				}
				if a != b {
					t.Errorf("atributos alterados en %s:\n  antes:   %s\n  después: %s", rel, b, a)
				}
			}
		})
	}
}
