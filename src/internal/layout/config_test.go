package layout

import "testing"

func TestCanonicalizeRealize(t *testing.T) {
	c := Config{AdminDir: "adm1ng", ApiDir: "myapi", Source: SourceOperator}
	cases := []struct{ real, canon string }{
		{"adm1ng/index.php", "administrator/index.php"},
		{"adm1ng/components/com_x/x.php", "administrator/components/com_x/x.php"},
		{"myapi/components/com_x/y.php", "api/components/com_x/y.php"},
		{"components/com_x/z.php", "components/com_x/z.php"}, // site-tree: intacto
		{"adm1ngtail/x", "adm1ngtail/x"},                     // no es prefijo de dir: intacto
	}
	for _, k := range cases {
		if got := c.Canonicalize(k.real); got != k.canon {
			t.Errorf("Canonicalize(%q)=%q want %q", k.real, got, k.canon)
		}
		if got := c.Realize(k.canon); got != k.real {
			t.Errorf("Realize(%q)=%q want %q", k.canon, got, k.real)
		}
	}
	// Sin remapeo: identidad.
	if (Config{}).Canonicalize("adm1ng/x") != "adm1ng/x" {
		t.Fatal("identidad esperada")
	}
	if (Config{}).Realize("administrator/x") != "administrator/x" {
		t.Fatal("identidad esperada")
	}
}

// TestCanonicalizeRealize_SingleDirConfigsAreNoOpForTheOther prueba que un
// Config que solo remapea AdminDir deja intacto cualquier rel con forma
// "api"/"myapi" (y viceversa): cada rama de rewritePrefix se aplica solo a
// su propio par (from,to), sin interferir con el otro directorio.
func TestCanonicalizeRealize_SingleDirConfigsAreNoOpForTheOther(t *testing.T) {
	adminOnly := Config{AdminDir: "adm1ng"}
	for _, rel := range []string{"api/x", "myapi/x"} {
		if got := adminOnly.Canonicalize(rel); got != rel {
			t.Errorf("adminOnly.Canonicalize(%q)=%q want %q (sin ApiDir, debe quedar intacto)", rel, got, rel)
		}
		if got := adminOnly.Realize(rel); got != rel {
			t.Errorf("adminOnly.Realize(%q)=%q want %q (sin ApiDir, debe quedar intacto)", rel, got, rel)
		}
	}

	apiOnly := Config{ApiDir: "myapi"}
	for _, rel := range []string{"administrator/x", "adm1ng/x"} {
		if got := apiOnly.Canonicalize(rel); got != rel {
			t.Errorf("apiOnly.Canonicalize(%q)=%q want %q (sin AdminDir, debe quedar intacto)", rel, got, rel)
		}
		if got := apiOnly.Realize(rel); got != rel {
			t.Errorf("apiOnly.Realize(%q)=%q want %q (sin AdminDir, debe quedar intacto)", rel, got, rel)
		}
	}
}

func TestResolve_OperatorFlagValid(t *testing.T) {
	fsys := mkTree(t,
		"adm1ng/components",
		"adm1ng/manifests",
		"adm1ng/includes",
	)
	cfg, err := Resolve(fsys, "adm1ng", "")
	if err != nil {
		t.Fatalf("no esperaba error, obtuve %v", err)
	}
	want := Config{AdminDir: "adm1ng", Source: SourceOperator}
	if cfg != want {
		t.Fatalf("Resolve=%+v want %+v", cfg, want)
	}
	if !cfg.RemapApplied() {
		t.Fatal("esperaba RemapApplied()==true")
	}
}

func TestResolve_OperatorFlagInvalid(t *testing.T) {
	fsys := mkTree(t,
		"components",
		"modules",
	)
	if _, err := Resolve(fsys, "noexiste", ""); err == nil {
		t.Fatal("esperaba error para --administrator-dir=noexiste")
	}
}

func TestResolve_AutoDetectConfident(t *testing.T) {
	fsys := mkTree(t,
		"adm1ng/components",
		"adm1ng/manifests",
		"adm1ng/includes",
	)
	cfg, err := Resolve(fsys, "", "")
	if err != nil {
		t.Fatalf("no esperaba error, obtuve %v", err)
	}
	want := Config{AdminDir: "adm1ng", Source: SourceAuto, AdminDirFound: "adm1ng"}
	if cfg != want {
		t.Fatalf("Resolve=%+v want %+v", cfg, want)
	}
}

func TestResolve_StandardTree(t *testing.T) {
	fsys := mkTree(t,
		"administrator/components",
		"administrator/manifests",
		"administrator/includes",
	)
	cfg, err := Resolve(fsys, "", "")
	if err != nil {
		t.Fatalf("no esperaba error, obtuve %v", err)
	}
	if cfg != (Config{}) {
		t.Fatalf("esperaba Config{} (sin remapeo), obtuve %+v", cfg)
	}
	if cfg.NonstandardUnresolved {
		t.Fatal("esperaba NonstandardUnresolved==false")
	}
}

func TestResolve_NoSkeletonAnywhereUnresolved(t *testing.T) {
	fsys := mkTree(t,
		"components",
		"modules",
	)
	cfg, err := Resolve(fsys, "", "")
	if err != nil {
		t.Fatalf("no esperaba error, obtuve %v", err)
	}
	if !cfg.NonstandardUnresolved {
		t.Fatalf("esperaba NonstandardUnresolved==true, obtuve %+v", cfg)
	}
}

func TestResolve_CollisionWithLiteralAdministrator(t *testing.T) {
	fsys := mkTree(t,
		"adm1ng/components",
		"adm1ng/manifests",
		"adm1ng/includes",
		"administrator/decoy", // señuelo: administrator/ literal también existe
	)
	if _, err := Resolve(fsys, "adm1ng", ""); err == nil {
		t.Fatal("esperaba error de colisión (adm1ng resuelto + administrator/ literal presente)")
	}
}

// TestResolve_CollisionWithLiteralAdministrator_AutoDetected prueba el mismo
// caso de colisión pero sin flag: administrator/ existe (no está ausente)
// pero carece del esqueleto, así que DetectAdmin lo descarta y encuentra
// adm1ng/ como candidato auto-detectado. Resolve debe fallar igual —
// Principio VI no distingue Source: nunca fusiona dos dirs reales en un
// único namespace canónico, sea la fuente el operador o la auto-detección.
func TestResolve_CollisionWithLiteralAdministrator_AutoDetected(t *testing.T) {
	fsys := mkTree(t,
		"adm1ng/components",
		"adm1ng/manifests",
		"adm1ng/includes",
		"administrator/decoy", // existe pero SIN esqueleto: DetectAdmin no lo confunde con estándar
	)
	if _, err := Resolve(fsys, "", ""); err == nil {
		t.Fatal("esperaba error de colisión (adm1ng auto-detectado + administrator/ literal sin esqueleto presente)")
	}
}

func TestResolve_ApiDirValid(t *testing.T) {
	fsys := mkTree(t,
		"administrator/components",
		"administrator/manifests",
		"administrator/includes",
		"myapi/components",
	)
	cfg, err := Resolve(fsys, "", "myapi")
	if err != nil {
		t.Fatalf("no esperaba error, obtuve %v", err)
	}
	if cfg.ApiDir != "myapi" {
		t.Fatalf("ApiDir=%q want %q", cfg.ApiDir, "myapi")
	}
}

func TestResolve_ApiDirInvalid(t *testing.T) {
	fsys := mkTree(t,
		"administrator/components",
		"administrator/manifests",
		"administrator/includes",
	)
	if _, err := Resolve(fsys, "", "noexiste"); err == nil {
		t.Fatal("esperaba error para --api-dir=noexiste")
	}
}

// TestResolve_ApiCollision es la contraparte, para api, de
// TestResolve_CollisionWithLiteralAdministrator: si --api-dir resuelve a un
// directorio distinto de "api" y además existe un api/ literal en el árbol,
// canonicalizar fusionaría dos directorios reales en un mismo namespace
// (colisión silenciosa o UNIQUE-constraint interno) — Resolve debe rechazarlo
// en voz alta (Principio VI/IV), igual que para admin.
func TestResolve_ApiCollision(t *testing.T) {
	fsys := mkTree(t,
		"administrator/components",
		"administrator/manifests",
		"administrator/includes",
		"myapi/components",
		"api/decoy", // señuelo: api/ literal también existe
	)
	if _, err := Resolve(fsys, "", "myapi"); err == nil {
		t.Fatal("esperaba error de colisión (myapi resuelto como api + api/ literal presente)")
	}
}

// TestResolve_ExplicitCanonicalAdminFlagIsNoOp cubre el hallazgo MINOR 2:
// --administrator-dir=administrator (el nombre canónico, explícito) sobre un
// árbol estándar no debe fijar AdminDir/Source — Canonicalize sería identidad
// de todos modos, así que fijarlos solo dispararía RemapApplied()==true
// espurio y rompería la guardia de byte-identidad para árboles estándar.
func TestResolve_ExplicitCanonicalAdminFlagIsNoOp(t *testing.T) {
	fsys := mkTree(t,
		"administrator/components",
		"administrator/manifests",
		"administrator/includes",
	)
	cfg, err := Resolve(fsys, "administrator", "")
	if err != nil {
		t.Fatalf("no esperaba error, obtuve %v", err)
	}
	if cfg.RemapApplied() {
		t.Fatalf("esperaba RemapApplied()==false para --administrator-dir=administrator explícito, obtuve %+v", cfg)
	}
	if cfg != (Config{}) {
		t.Fatalf("esperaba Config{} (sin remapeo), obtuve %+v", cfg)
	}
}

// TestResolve_ExplicitCanonicalApiFlagIsNoOp es la contraparte api de la
// prueba anterior: --api-dir=api explícito no debe fijar ApiDir.
func TestResolve_ExplicitCanonicalApiFlagIsNoOp(t *testing.T) {
	fsys := mkTree(t,
		"administrator/components",
		"administrator/manifests",
		"administrator/includes",
		"api/components",
	)
	cfg, err := Resolve(fsys, "", "api")
	if err != nil {
		t.Fatalf("no esperaba error, obtuve %v", err)
	}
	if cfg.RemapApplied() {
		t.Fatalf("esperaba RemapApplied()==false para --api-dir=api explícito, obtuve %+v", cfg)
	}
}

// TestResolve_ApiOnlySource cubre el hallazgo MINOR 3: un remapeo puramente
// de api (sin remapeo de admin) debe declarar Source==SourceOperator, porque
// ApiDir es solo-por-flag (no hay auto-detección de api) — el operador es
// siempre la fuente correcta. Sin este comportamiento, coverage.layout
// declararía remap_applied:true con remap_source vacío (Principio VII).
func TestResolve_ApiOnlySource(t *testing.T) {
	fsys := mkTree(t,
		"administrator/components",
		"administrator/manifests",
		"administrator/includes",
		"myapi/components",
	)
	cfg, err := Resolve(fsys, "", "myapi")
	if err != nil {
		t.Fatalf("no esperaba error, obtuve %v", err)
	}
	if cfg.Source != SourceOperator {
		t.Fatalf("Source=%q want %q (remapeo api-only debe declarar fuente operator)", cfg.Source, SourceOperator)
	}
}
