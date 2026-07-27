package acquire

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"j0witness/internal/inventory"
	"j0witness/internal/lab"
	"j0witness/internal/observe"
)

// T014: L0 de punta a punta sobre minicms — entradas y observaciones
// persistidas, resumen coherente.
func TestRunOnMinicms(t *testing.T) {
	target := t.TempDir()
	if err := lab.WriteTree(target, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	store, err := inventory.Open(filepath.Join(t.TempDir(), "inv.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runID, err := store.CreateRun("inventory", "test", "h", []byte(target), target, "{}", "webserver-user-no-root", 1)
	if err != nil {
		t.Fatal(err)
	}
	fsys := newFS(t, target)
	sum, err := Run(fsys, store, runID, Options{Jobs: 4, FuzzyThreshold: 10 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if sum.RegularFiles < 10 || sum.ReadErrors != 0 {
		t.Fatalf("resumen inesperado: %+v", sum)
	}
	entries, err := store.EntriesByRun(runID)
	if err != nil {
		t.Fatal(err)
	}
	var indexSHA string
	for _, e := range entries {
		if e.PathDisplay == "index.php" {
			indexSHA = e.SHA256
		}
	}
	if indexSHA != lab.FileSHA("1.0.0", "index.php") {
		t.Fatalf("sha de index.php no coincide con la distribución: %s", indexSHA)
	}
	obs, err := store.ObservationsByRun(runID)
	if err != nil {
		t.Fatal(err)
	}
	hashed := 0
	for _, o := range obs {
		if o.Type == observe.EntryHashed {
			hashed++
		}
	}
	if hashed != sum.RegularFiles {
		t.Fatalf("observaciones entry_hashed=%d, archivos=%d", hashed, sum.RegularFiles)
	}
}

// Fase 2d T2: con Options.Canonicalize, RelPath/PathDisplay de las Entry
// persistidas y el subject de las observaciones deben quedar en la forma
// canónica ("administrator/…"), nunca en la ruta real del árbol
// ("adm1ng/…"). Rutas fuera del layout remapeado (p.ej. components/) no
// deben tocarse.
func TestRunCanonicalizesPaths(t *testing.T) {
	target := t.TempDir()
	files := map[string]string{
		"adm1ng/index.php":       "<?php // admin\n",
		"components/com_x/a.php": "<?php // component\n",
	}
	for rel, content := range files {
		full := filepath.Join(target, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	store, err := inventory.Open(filepath.Join(t.TempDir(), "inv.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runID, err := store.CreateRun("inventory", "test", "h", []byte(target), target, "{}", "webserver-user-no-root", 1)
	if err != nil {
		t.Fatal(err)
	}

	// Canonicalizador de prueba: reescribe únicamente el prefijo "adm1ng"
	// (el directorio admin renombrado) a "administrator".
	canon := func(rel string) string {
		if rel == "adm1ng" {
			return "administrator"
		}
		if strings.HasPrefix(rel, "adm1ng/") {
			return "administrator/" + strings.TrimPrefix(rel, "adm1ng/")
		}
		return rel
	}

	fsys := newFS(t, target)
	if _, err := Run(fsys, store, runID, Options{Jobs: 4, FuzzyThreshold: 10 << 20, Canonicalize: canon}); err != nil {
		t.Fatal(err)
	}

	entries, err := store.EntriesByRun(runID)
	if err != nil {
		t.Fatal(err)
	}
	var sawAdmin, sawComponent bool
	for _, e := range entries {
		if e.PathDisplay == "adm1ng/index.php" || strings.Contains(string(e.RelPath), "adm1ng") {
			t.Fatalf("entrada con ruta real (no canonicalizada) persistida: %+v", e)
		}
		if e.PathDisplay == "administrator/index.php" {
			sawAdmin = true
			if string(e.RelPath) != "administrator/index.php" {
				t.Fatalf("RelPath no canónico: %q", e.RelPath)
			}
		}
		if e.PathDisplay == "components/com_x/a.php" {
			sawComponent = true
			if string(e.RelPath) != "components/com_x/a.php" {
				t.Fatalf("ruta fuera del remap alterada: %q", e.RelPath)
			}
		}
	}
	if !sawAdmin {
		t.Fatal("no se encontró administrator/index.php entre las entradas")
	}
	if !sawComponent {
		t.Fatal("no se encontró components/com_x/a.php entre las entradas")
	}

	obs, err := store.ObservationsByRun(runID)
	if err != nil {
		t.Fatal(err)
	}
	var sawHashedObs bool
	for _, o := range obs {
		if o.Type != observe.EntryHashed {
			continue
		}
		if o.SubjectDisplay == "administrator/index.php" {
			sawHashedObs = true
		}
		if strings.Contains(o.SubjectDisplay, "adm1ng") {
			t.Fatalf("observación entry_hashed con subject no canonicalizado: %q", o.SubjectDisplay)
		}
	}
	if !sawHashedObs {
		t.Fatal("no se encontró observación entry_hashed con subject canónico administrator/index.php")
	}
}

// Fase 2d T2 (fix round 1): WalkObservations también debe recibir subjects
// canonicalizados. Un symlink bajo "adm1ng/" apuntando fuera del árbol
// dispara symlink_out_of_tree en tiempo de walk (antes de hash): su
// SubjectDisplay debe ser "administrator/…", nunca "adm1ng/…", igual que la
// Entry persistida para ese mismo archivo (invariante de consistencia
// interna). Además, ninguna observación persistida —de ningún tipo— debe
// llevar un subject con el prefijo real "adm1ng/".
func TestRunCanonicalizesWalkObservationSubjects(t *testing.T) {
	target := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secreto.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	admDir := filepath.Join(target, "adm1ng")
	if err := os.MkdirAll(admDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(admDir, "index.php"), []byte("<?php\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(admDir, "fuera")); err != nil {
		t.Fatal(err)
	}

	store, err := inventory.Open(filepath.Join(t.TempDir(), "inv.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runID, err := store.CreateRun("inventory", "test", "h", []byte(target), target, "{}", "webserver-user-no-root", 1)
	if err != nil {
		t.Fatal(err)
	}

	canon := func(rel string) string {
		if rel == "adm1ng" {
			return "administrator"
		}
		if strings.HasPrefix(rel, "adm1ng/") {
			return "administrator/" + strings.TrimPrefix(rel, "adm1ng/")
		}
		return rel
	}

	fsys := newFS(t, target)
	if _, err := Run(fsys, store, runID, Options{Jobs: 4, FuzzyThreshold: 10 << 20, Canonicalize: canon}); err != nil {
		t.Fatal(err)
	}

	obs, err := store.ObservationsByRun(runID)
	if err != nil {
		t.Fatal(err)
	}

	var sawSymlinkOut bool
	for _, o := range obs {
		if strings.HasPrefix(o.SubjectDisplay, "adm1ng/") || o.SubjectDisplay == "adm1ng" {
			t.Fatalf("observación %q con subject NO canonicalizado: %q", o.Type, o.SubjectDisplay)
		}
		if o.Type == observe.SymlinkOutOfTree && o.SubjectDisplay == "administrator/fuera" {
			sawSymlinkOut = true
		}
	}
	if !sawSymlinkOut {
		t.Fatal("no se encontró observación symlink_out_of_tree con subject canónico administrator/fuera")
	}
}
