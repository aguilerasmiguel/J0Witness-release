package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"j0witness/internal/lab"
)

// T021 (FR-047): los centinelas sembrados en configuration.php no aparecen ni
// en el informe ni en el inventario SQLite (ambas barreras verificadas).
func TestSentinelsNeverLeak(t *testing.T) {
	h := newHarness(t)
	_, _, doc, stderr := h.scanCase(t, "clean-minicms")

	for _, sentinel := range lab.Sentinels {
		if bytes.Contains(doc, []byte(sentinel)) {
			t.Fatalf("centinela %s presente en el informe (FR-047)", sentinel)
		}
		if bytes.Contains([]byte(stderr), []byte(sentinel)) {
			t.Fatalf("centinela %s presente en stderr", sentinel)
		}
	}

	// Barrera 1: tampoco en el almacén persistido.
	dbs, err := filepath.Glob(filepath.Join(h.workdir, "*.sqlite"))
	if err != nil || len(dbs) == 0 {
		t.Fatalf("sin almacenes en %s", h.workdir)
	}
	for _, db := range dbs {
		raw, err := os.ReadFile(db)
		if err != nil {
			t.Fatal(err)
		}
		for _, sentinel := range lab.Sentinels {
			if bytes.Contains(raw, []byte(sentinel)) {
				t.Fatalf("centinela %s presente en el inventario %s (FR-047 barrera 1)", sentinel, filepath.Base(db))
			}
		}
	}
}
