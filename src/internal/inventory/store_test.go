package inventory

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"j0witness/internal/observe"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "inv.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// T010: alta de run, entradas y observaciones con lectura en orden estable.
func TestStoreRoundTrip(t *testing.T) {
	s := openTestStore(t)
	runID, err := s.CreateRun("inventory", "test", "hash", []byte("/t"), "/t", "{}", "webserver-user-no-root", 1)
	if err != nil {
		t.Fatal(err)
	}
	entries := []Entry{
		{RelPath: []byte("z.php"), PathDisplay: "z.php", Type: "file", SHA256: "cc"},
		{RelPath: []byte("a.php"), PathDisplay: "a.php", Type: "file", SHA256: "aa"},
	}
	if err := s.InsertEntries(runID, entries); err != nil {
		t.Fatal(err)
	}
	got, err := s.EntriesByRun(runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].PathDisplay != "a.php" || got[1].PathDisplay != "z.php" {
		t.Fatalf("orden inestable: %+v", got)
	}

	o, _ := observe.New([]byte("a.php"), observe.FileModified, map[string]any{"k": 1}, observe.SrcCorediff, observe.High, 2)
	ids, err := s.InsertObservations(runID, []observe.Observation{o})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] == 0 {
		t.Fatalf("ids: %v", ids)
	}
	obs, err := s.ObservationsByRun(runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Type != observe.FileModified || obs[0].ID != ids[0] {
		t.Fatalf("obs: %+v", obs)
	}
}

// ListRuns devuelve los runs del kind dado, ordenados por inicio ascendente.
func TestStoreListRuns(t *testing.T) {
	s := openTestStore(t)
	id1, err := s.CreateRun("analyze", "test", "hash", []byte("/t"), "/t", "{}", "webserver-user-no-root", 1)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := s.CreateRun("analyze", "test", "hash", []byte("/t"), "/t", "{}", "webserver-user-no-root", 2)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := s.ListRuns("analyze")
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Fatalf("esperaba 2 runs, obtuve %d: %+v", len(runs), runs)
	}
	if runs[0].ID != id1 || runs[1].ID != id2 {
		t.Fatalf("orden inesperado: %+v", runs)
	}
	if runs[0].StartedAtNS != 1 || runs[1].StartedAtNS != 2 {
		t.Fatalf("StartedAtNS inesperado: %+v", runs)
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	s := openTestStore(t)
	files := []Entry{
		{RelPath: []byte("index.php"), PathDisplay: "index.php", SHA256: "aa", Size: 10},
	}
	id, err := s.SaveBaseline("joomla", "1.0.0", "pkg", "man", "local-add", 1, files)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.BaselineFiles(id)
	if err != nil || len(got) != 1 || got[0].SHA256 != "aa" {
		t.Fatalf("manifiesto: %v %+v", err, got)
	}
	fid, pkg, _, src, err := s.FindBaseline("joomla", "1.0.0")
	if err != nil || fid != id || pkg != "pkg" || src != "local-add" {
		t.Fatalf("FindBaseline: %v", err)
	}
}

func TestExtensionBaselineRoundtrip(t *testing.T) {
	s := openTestStore(t)
	files := []Entry{
		{RelPath: []byte("administrator/components/com_x/x.php"), PathDisplay: "administrator/components/com_x/x.php", SHA256: "aa", Size: 3},
		{RelPath: []byte("components/com_x/router.php"), PathDisplay: "components/com_x/router.php", SHA256: "bb", Size: 5},
	}
	id, err := s.SaveExtensionBaseline("com_x", "1.0.0", "pkgsha", "package", 1, files)
	if err != nil {
		t.Fatal(err)
	}
	gotID, pkg, src, err := s.FindExtensionBaseline("com_x", "1.0.0")
	if err != nil || gotID != id || pkg != "pkgsha" || src != "package" {
		t.Fatalf("find: %v %d %q %q", err, gotID, pkg, src)
	}
	bf, err := s.ExtensionBaselineFiles(id)
	if err != nil || len(bf) != 2 || bf[0].SHA256 != "aa" {
		t.Fatalf("files: %v %+v", err, bf)
	}
	// No encontrada → error claro.
	if _, _, _, err := s.FindExtensionBaseline("com_x", "9.9.9"); err == nil {
		t.Fatal("versión inexistente debe dar error")
	}
}

// Re-guardar el mismo (element, version) es una operación normal del operador
// (`extension add` repetido). El id debe permanecer estable y las filas de
// extension_baseline_files del guardado anterior no deben quedar huérfanas
// (regresión: INSERT OR REPLACE reasigna rowid → el DELETE por el id nuevo no
// borra las filas del id viejo).
func TestExtensionBaselineResaveNoOrphans(t *testing.T) {
	s := openTestStore(t)
	first := []Entry{
		{RelPath: []byte("a.php"), PathDisplay: "a.php", SHA256: "a1", Size: 1},
		{RelPath: []byte("b.php"), PathDisplay: "b.php", SHA256: "b1", Size: 2},
	}
	firstID, err := s.SaveExtensionBaseline("com_y", "1.0.0", "pkg1", "package", 1, first)
	if err != nil {
		t.Fatal(err)
	}

	second := []Entry{
		{RelPath: []byte("c.php"), PathDisplay: "c.php", SHA256: "c1", Size: 3},
		{RelPath: []byte("d.php"), PathDisplay: "d.php", SHA256: "d1", Size: 4},
		{RelPath: []byte("e.php"), PathDisplay: "e.php", SHA256: "e1", Size: 5},
	}
	secondID, err := s.SaveExtensionBaseline("com_y", "1.0.0", "pkg2", "package", 2, second)
	if err != nil {
		t.Fatal(err)
	}
	if secondID != firstID {
		t.Fatalf("el id debe permanecer estable en el re-guardado: primero=%d segundo=%d", firstID, secondID)
	}

	gotID, pkg, _, err := s.FindExtensionBaseline("com_y", "1.0.0")
	if err != nil || gotID != firstID || pkg != "pkg2" {
		t.Fatalf("find tras re-guardado: %v id=%d pkg=%q", err, gotID, pkg)
	}

	bf, err := s.ExtensionBaselineFiles(gotID)
	if err != nil || len(bf) != 3 {
		t.Fatalf("archivos tras re-guardado: %v %+v", err, bf)
	}

	// Comprobación directa contra filas huérfanas: el total de filas en
	// extension_baseline_files debe ser exactamente 3 (no 5), sin importar
	// bajo qué ext_baseline_id quedaran.
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM extension_baseline_files`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("filas huérfanas detectadas: total=%d, esperado=3", total)
	}
}

// T010 gate R8: 30k entradas + 30k observaciones en <5 s.
func TestStoreThroughputGate(t *testing.T) {
	if testing.Short() {
		t.Skip("gate de rendimiento omitido en -short")
	}
	s := openTestStore(t)
	runID, err := s.CreateRun("inventory", "test", "hash", []byte("/t"), "/t", "{}", "webserver-user-no-root", 1)
	if err != nil {
		t.Fatal(err)
	}
	const n = 30000
	entries := make([]Entry, n)
	obs := make([]observe.Observation, n)
	for i := range entries {
		p := fmt.Sprintf("dir/archivo-%06d.php", i)
		entries[i] = Entry{RelPath: []byte(p), PathDisplay: p, Type: "file", SHA256: "abc", Size: int64(i)}
		o, _ := observe.New([]byte(p), observe.EntryHashed, map[string]any{"sha256": "abc"}, observe.SrcAcquire, observe.High, int64(i))
		obs[i] = o
	}
	start := time.Now()
	if err := s.InsertEntries(runID, entries); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertObservations(runID, obs); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("gate R8 roto: %v > 5s", d)
	}
}
