package report

import (
	"testing"

	"j0witness/internal/observe"
)

func fu(subject string, inCore, forbidden, exec bool) observe.Observation {
	o, _ := observe.New([]byte(subject), observe.FileUnexpected, map[string]any{
		"in_core_dir": inCore, "in_forbidden_exec": forbidden, "executable": exec,
	}, observe.SrcCorediff, observe.High, 1)
	return o
}

func TestForeignRootsAggregates(t *testing.T) {
	obs := []observe.Observation{
		fu("app/main.php", false, false, true),
		fu("app/bundle.js", false, false, false),
		fu("vendor/index.js", false, false, false),
		fu("shell.php", false, false, true),                // archivo raíz suelto
		fu("components/com_x/evil.php", true, false, true), // in_core → CORE-004, excluido
		fu("cache/tmp.php", false, true, true),             // forbidden-exec → CORE-005, excluido
	}
	size := map[string]int64{"app/main.php": 1000, "app/bundle.js": 500, "vendor/index.js": 200, "shell.php": 50}
	got := ForeignRoots(obs, size, nil)
	// Esperado (orden: DistributionDir asc (todas false aquí, knownRoots=nil),
	// luego executables desc, luego root asc): app(2f,1e,1500b)? no:
	// app = main.php(exec)+bundle.js = 2 files, 1 exec, 1500 bytes
	// shell.php = 1 file, 1 exec, 50 bytes
	// vendor = 1 file, 0 exec, 200 bytes
	// orden por exec desc: map(1) y shell(1) empatan → root asc: "app","shell.php"; luego vendor(0)
	want := []ForeignRoot{
		{Root: "app", Files: 2, Executables: 1, Bytes: 1500},
		{Root: "shell.php", Files: 1, Executables: 1, Bytes: 50},
		{Root: "vendor", Files: 1, Executables: 0, Bytes: 200},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d roots, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("root %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestForeignRootsExcludesExtAndConfigOwned(t *testing.T) {
	// Un FileUnexpected explicado por una extensión (ext_owns_path sobre el mismo
	// subject) NO es "ajeno": no debe aparecer.
	owned, _ := observe.New([]byte("app/owned.php"), observe.ExtOwnsPath,
		map[string]any{"extension": "com_x"}, observe.SrcExtmap, observe.High, 1)
	obs := []observe.Observation{
		fu("app/owned.php", false, false, true),
		owned,
	}
	got := ForeignRoots(obs, map[string]int64{"app/owned.php": 100}, nil)
	if len(got) != 0 {
		t.Fatalf("un archivo explicado por extensión no debe contarse como ajeno: %+v", got)
	}
}

// TestForeignRootsForbiddenNonExecutableIsForeign cubre el fix del review
// (round 1): la exclusión de foreign.go debe ser un espejo LITERAL de
// finding.Derive, que solo enruta a J0W-CORE-005 cuando executable &&
// in_forbidden_exec (internal/finding/derive.go:295). Un in_forbidden_exec=true
// con executable=false NO produce CORE-005 — Derive lo deja caer al "return
// nil" de contenido ajeno (línea 319) — así que SÍ debe contarse en
// foreign_roots. El caso real de CORE-005 (executable && forbidden, p.ej.
// cache/tmp.php) sigue excluido.
func TestForeignRootsForbiddenNonExecutableIsForeign(t *testing.T) {
	obs := []observe.Observation{
		fu("uploads/data.txt", false, true, false), // forbidden pero NO ejecutable → ajeno, cuenta
		fu("cache/tmp.php", false, true, true),     // forbidden && executable → CORE-005 real, excluido
	}
	size := map[string]int64{"uploads/data.txt": 42, "cache/tmp.php": 999}
	got := ForeignRoots(obs, size, nil)
	want := []ForeignRoot{
		{Root: "uploads", Files: 1, Executables: 0, Bytes: 42},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d roots, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("root %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestForeignRootsEmpty(t *testing.T) {
	if got := ForeignRoots(nil, nil, nil); got != nil {
		t.Errorf("sin observaciones → nil (omitempty), got %+v", got)
	}
}

// TestForeignRootsDistributionDirLabelAndOrder cubre el etiquetado
// distribution_dir (refinamiento post-shipping de feature 012, validado en
// sitio real: el bloque mezclaba raíces genuinamente ajenas -- app/,
// vendor/ -- con dirs ESTÁNDAR de Joomla que solo contienen contenido de
// usuario -- images/, administrator/). knownRoots={"images":true} marca
// "images" como dir de la distribución; "app" (ausente del manifiesto) queda
// false. El orden debe surfacear las raíces genuinamente ajenas PRIMERO
// (DistributionDir asc), incluso si "images" tuviera más ejecutables — aquí
// se le da a "app" un ejecutable para que el desempate por executables no
// pueda, por sí solo, explicar el orden.
func TestForeignRootsDistributionDirLabelAndOrder(t *testing.T) {
	obs := []observe.Observation{
		fu("app/x.php", false, false, true),     // ajena, ejecutable
		fu("images/x.jpg", false, false, false), // dir de Joomla, contenido de usuario
	}
	size := map[string]int64{"app/x.php": 10, "images/x.jpg": 20}
	knownRoots := map[string]bool{"images": true}
	got := ForeignRoots(obs, size, knownRoots)
	if len(got) != 2 {
		t.Fatalf("got %d roots, want 2: %+v", len(got), got)
	}
	if got[0].Root != "app" || got[0].DistributionDir != false {
		t.Errorf("root 0 = %+v, want app con distribution_dir=false primero (ajena)", got[0])
	}
	if got[1].Root != "images" || got[1].DistributionDir != true {
		t.Errorf("root 1 = %+v, want images con distribution_dir=true", got[1])
	}
}
