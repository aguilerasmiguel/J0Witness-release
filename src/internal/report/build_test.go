package report

import (
	"encoding/json"
	"strings"
	"testing"

	"j0witness/internal/finding"
	"j0witness/internal/i18n"
	"j0witness/internal/observe"
)

// TestCodeFlaggedPaths verifica el helper puro que agrega, por ruta, si algún
// hallazgo J0W-CODE-* la marcó (feature 003, capa L4).
func TestCodeFlaggedPaths(t *testing.T) {
	fs := []finding.Finding{
		{RuleID: "J0W-CODE-001", Subject: "a.php"},
		{RuleID: "J0W-CODE-002", Subject: "a.php"}, // misma ruta, dos reglas → una entrada
		{RuleID: "J0W-CORE-004", Subject: "b.php"}, // no es CODE → no cuenta
	}
	got := codeFlaggedPaths(fs)
	if len(got) != 1 || !got["a.php"] {
		t.Fatalf("codeFlaggedPaths = %v, quiere {a.php}", got)
	}
}

// TestSchemaVersion fija el contrato en 1.13.0 (baseline_verification,
// aditivo sobre 1.12.0).
func TestSchemaVersion(t *testing.T) {
	if SchemaVersion != "1.13.0" {
		t.Fatalf("esquema = %s, quiere 1.13.0", SchemaVersion)
	}
}

// TestBuildLanguage cubre la 1.8.0: BuildInput.Language se declara en
// Report.Language tal cual (Build no traduce nada, la prosa ya viene resuelta
// desde Derive); el cero-valor (sin --language, o un informe reconstruido sin
// el campo) se interpreta como "es" por defecto/retrocompatibilidad.
func TestBuildLanguage(t *testing.T) {
	rep, _, err := Build(BuildInput{FailOn: finding.MediumS, Language: i18n.EN})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Language != "en" {
		t.Fatalf("Language = %q, quiere en", rep.Language)
	}

	repDefault, _, err := Build(BuildInput{FailOn: finding.MediumS})
	if err != nil {
		t.Fatal(err)
	}
	if repDefault.Language != "es" {
		t.Fatalf("Language = %q, quiere es (por defecto, cero-valor)", repDefault.Language)
	}
}

// TestExtVerificationCoverage cubre la fase 2a de punta a punta desde Build:
// un ext_file_verified ejecutable NO aparece en unverified_executables (ya se
// comparó contra el paquete oficial), mientras que un ext_file_modified sigue
// produciendo J0W-EXT-008 y activa integrity_verified a nivel agregado.
func TestExtVerificationCoverage(t *testing.T) {
	mk := func(subject string, typ observe.Type, ev map[string]any) observe.Observation {
		o, _ := observe.New([]byte(subject), typ, ev, observe.SrcExtmap, observe.High, 1)
		return o
	}
	obs := []observe.Observation{
		mk("components/com_x/verified.php", observe.ExtOwnsPath, map[string]any{"extension": "com_x", "declaration": "file", "executable": true}),
		mk("components/com_x/verified.php", observe.ExtFileVerified, map[string]any{"extension": "com_x", "verification_source": "package", "executable": true}),
		mk("components/com_x/modified.php", observe.ExtOwnsPath, map[string]any{"extension": "com_x", "declaration": "file", "executable": true}),
		mk("components/com_x/modified.php", observe.ExtFileModified, map[string]any{"extension": "com_x", "verification_source": "package", "executable": true}),
	}
	finds := finding.Derive(obs, "1.1.0", map[string]bool{}, i18n.ES)
	exts := []Ext{{Type: "component", Name: "Lab", ManifestPath: "components/com_x/com_x.xml", Verified: true}}

	rep, _, err := Build(BuildInput{
		Observations: obs,
		Findings:     finds,
		Extensions:   exts,
		FailOn:       finding.MediumS,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.SchemaVersion != "1.13.0" {
		t.Fatalf("schema_version = %s, quiere 1.13.0", rep.SchemaVersion)
	}

	att := rep.Coverage.Attribution
	if att == nil || att.UnverifiedExecutables == nil {
		t.Fatalf("esperaba unverified_executables no nulo: %+v", att)
	}
	for _, f := range att.UnverifiedExecutables.Files {
		if f.Path == "components/com_x/verified.php" {
			t.Fatalf("verified.php no debe aparecer en unverified_executables: %+v", att.UnverifiedExecutables.Files)
		}
	}
	gotModified := false
	for _, f := range att.UnverifiedExecutables.Files {
		if f.Path == "components/com_x/modified.php" {
			gotModified = true
		}
	}
	if !gotModified {
		t.Fatalf("modified.php debe seguir en unverified_executables (fase 2a no verifica su hash): %+v", att.UnverifiedExecutables.Files)
	}
	if !att.IntegrityVerified {
		t.Fatal("integrity_verified debe ser true: hay al menos una extensión verificada")
	}

	gotEXT008 := false
	for _, f := range rep.Findings {
		if f.RuleID == "J0W-EXT-008" && f.Subject == "components/com_x/modified.php" {
			gotEXT008 = true
		}
	}
	if !gotEXT008 {
		t.Fatalf("esperaba J0W-EXT-008 sobre modified.php: %+v", rep.Findings)
	}

	ev := rep.Coverage.ExtensionVerification
	if ev == nil {
		t.Fatal("esperaba coverage.extension_verification")
	}
	if ev.ExtensionsVerifiable != 1 || ev.ExtensionsVerified != 1 || ev.ExtensionsUnverifiable != 0 || ev.FilesModified != 1 {
		t.Fatalf("extension_verification = %+v, quiere {verifiable:1 verified:1 unverifiable:0 modified:1}", ev)
	}
}

// TestExtVerificationCountsAllVerifiableTypes fija la generalización de fase
// 2c: extmap.VerifyExtensions ya verifica los 5 tipos con clave de elemento
// estable (component/module/plugin/template/library), así que
// extensions_verifiable debe contar los tres tipos verificables presentes
// (component + plugin + module), y extensions_verified solo el marcado
// Verified:true.
func TestExtVerificationCountsAllVerifiableTypes(t *testing.T) {
	exts := []Ext{
		{Type: "component", Name: "Lab", ManifestPath: "components/com_x/com_x.xml", Verified: true},
		{Type: "plugin", Name: "labplugin", ManifestPath: "plugins/system/labplugin/labplugin.xml", Verified: false},
		{Type: "module", Name: "mod_labmod", ManifestPath: "modules/mod_labmod/mod_labmod.xml", Verified: false},
	}
	rep, _, err := Build(BuildInput{Extensions: exts, FailOn: finding.MediumS})
	if err != nil {
		t.Fatal(err)
	}
	ev := rep.Coverage.ExtensionVerification
	if ev == nil {
		t.Fatal("esperaba coverage.extension_verification")
	}
	if ev.ExtensionsVerifiable != 3 {
		t.Fatalf("extensions_verifiable = %d, quiere 3 (component + plugin + module)", ev.ExtensionsVerifiable)
	}
	if ev.ExtensionsVerified != 1 {
		t.Fatalf("extensions_verified = %d, quiere 1", ev.ExtensionsVerified)
	}
	if ev.ExtensionsUnverifiable != 2 {
		t.Fatalf("extensions_unverifiable = %d, quiere 2 (verifiable - verified)", ev.ExtensionsUnverifiable)
	}
}

// TestCoverageExtensionsByType cubre la 1.7.0: coverage.extensions_by_type
// desglosa las extensiones de terceros por tipo de manifiesto (solo tipos
// presentes); el total ya lo da coverage.attribution.third_party_extensions.
func TestCoverageExtensionsByType(t *testing.T) {
	exts := []Ext{
		{Type: "component", Name: "Lab", ManifestPath: "components/com_x/com_x.xml", Verified: true},
		{Type: "component", Name: "Lab2", ManifestPath: "components/com_y/com_y.xml", Verified: true},
		{Type: "plugin", Name: "labplugin", ManifestPath: "plugins/system/labplugin/labplugin.xml", Verified: false},
		{Type: "module", Name: "mod_labmod", ManifestPath: "modules/mod_labmod/mod_labmod.xml", Verified: false},
	}
	rep, _, err := Build(BuildInput{Extensions: exts, FailOn: finding.MediumS})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"component": 2, "plugin": 1, "module": 1}
	if len(rep.Coverage.ExtensionsByType) != len(want) {
		t.Fatalf("extensions_by_type = %v, quiere %v", rep.Coverage.ExtensionsByType, want)
	}
	for typ, n := range want {
		if got := rep.Coverage.ExtensionsByType[typ]; got != n {
			t.Fatalf("extensions_by_type[%q] = %d, quiere %d", typ, got, n)
		}
	}
}

// TestCoverageExtensionsByTypeAbsentWhenNoExtensions cubre la 1.7.0: sin
// extensiones, ExtensionsByType debe quedar nil (omitempty, ausente del JSON).
func TestCoverageExtensionsByTypeAbsentWhenNoExtensions(t *testing.T) {
	rep, doc, err := Build(BuildInput{FailOn: finding.MediumS})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Coverage.ExtensionsByType != nil {
		t.Fatalf("Coverage.ExtensionsByType = %v, quiere nil (sin extensiones)", rep.Coverage.ExtensionsByType)
	}
	var raw struct {
		Coverage map[string]json.RawMessage `json:"coverage"`
	}
	if err := json.Unmarshal(doc, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw.Coverage["extensions_by_type"]; ok {
		t.Fatalf("el JSON no debe tener coverage.extensions_by_type sin extensiones: %s", doc)
	}
}

// TestCoverageLayoutStandard cubre la T6: un árbol estándar (LayoutStandard:
// true) no debe emitir coverage.layout — ni como struct Go (nil) ni como
// clave "layout" en el JSON marshalado (omitempty), para no ensuciar informes
// previos a la fase 2c.
func TestCoverageLayoutStandard(t *testing.T) {
	exts := []Ext{{Type: "component", Name: "Lab", ManifestPath: "components/com_x/com_x.xml", Verified: true}}
	rep, doc, err := Build(BuildInput{Extensions: exts, FailOn: finding.MediumS, LayoutStandard: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Coverage.Layout != nil {
		t.Fatalf("Coverage.Layout = %+v, quiere nil (árbol estándar)", rep.Coverage.Layout)
	}
	var raw struct {
		Coverage map[string]json.RawMessage `json:"coverage"`
	}
	if err := json.Unmarshal(doc, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw.Coverage["layout"]; ok {
		t.Fatalf("el JSON no debe tener coverage.layout en un árbol estándar: %s", doc)
	}
}

// TestCoverageLayoutNonstandard cubre la T6: un árbol no estándar
// (LayoutStandard: false, admin renombrado a "panel") debe emitir
// coverage.layout con Standard=false y el AdminDirFound declarado.
func TestCoverageLayoutNonstandard(t *testing.T) {
	rep, _, err := Build(BuildInput{FailOn: finding.MediumS, LayoutStandard: false, LayoutAdminDir: "panel"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Coverage.Layout == nil {
		t.Fatal("esperaba coverage.layout no nulo (árbol no estándar)")
	}
	if rep.Coverage.Layout.Standard {
		t.Fatal("Coverage.Layout.Standard debe ser false")
	}
	if rep.Coverage.Layout.AdminDirFound != "panel" {
		t.Fatalf("Coverage.Layout.AdminDirFound = %q, quiere \"panel\"", rep.Coverage.Layout.AdminDirFound)
	}
	if rep.Coverage.Layout.RemapApplied {
		t.Fatal("Coverage.Layout.RemapApplied debe ser false (no-resuelto, no remapeado)")
	}
	if rep.Coverage.Layout.AdminDir != "" || rep.Coverage.Layout.ApiDir != "" || rep.Coverage.Layout.RemapSource != "" {
		t.Fatalf("los campos de remapeo deben quedar vacíos cuando no hubo remapeo: %+v", rep.Coverage.Layout)
	}
}

// realizeInput arma un BuildInput con datos en todos los campos que
// realizePath/realizePaths tocan (fase 2d, T5): finding subject,
// not_analyzed/omissions, unverified_executables y extensions
// (manifest_path/roots). Se comparte entre TestRealizeIdentityByteIdentical
// (a) y TestRealizeAppliesToOperatorFacingPaths (b): el único eje que varía
// entre ambos tests es el campo Realize (y, en (b), los campos de remapeo).
func realizeInput(realize func(string) string) BuildInput {
	mk := func(subject string, typ observe.Type, ev map[string]any) observe.Observation {
		o, _ := observe.New([]byte(subject), typ, ev, observe.SrcAcquire, observe.High, 1)
		return o
	}
	obs := []observe.Observation{
		mk("administrator/cache/x.tmp", observe.ReadDenied, map[string]any{"reason": "permission"}),
		mk("administrator/uploads/y.dat", observe.FuzzyHashSkipped, map[string]any{"reason": "too_large"}),
		mk("components/com_x/exec.php", observe.ExtOwnsPath, map[string]any{"extension": "com_x", "declaration": "file", "executable": true}),
	}
	finds := []finding.Finding{
		{ID: "aaaaaaaaaaaaaaaa", RuleID: "J0W-CORE-004", Subject: "administrator/x.php", Severity: finding.Low, BaseSeverity: finding.Low, Confidence: observe.High, Evidence: map[string]any{}},
	}
	exts := []Ext{
		{Type: "component", Name: "Lab", ManifestPath: "administrator/components/com_x/com_x.xml", Roots: []string{"administrator/components/com_x", "components/com_x"}, Verified: true},
	}
	return BuildInput{
		Observations:   obs,
		Findings:       finds,
		Extensions:     exts,
		FailOn:         finding.MediumS,
		Realize:        realize,
		LayoutStandard: true, // caso base (a): árbol estándar, sin coverage.layout
	}
}

// TestRealizeIdentityByteIdentical cubre la guarda de regresión central de la
// fase 2d (T5): un árbol SIN remapeo (Realize identidad, LayoutStandard
// implícito por omisión de los campos de layout) produce una salida
// byte-idéntica tanto si Realize es nil como si es una función identidad
// explícita — realizeAll/realizePath no deben mutar nada cuando no hay
// remapeo que aplicar.
func TestRealizeIdentityByteIdentical(t *testing.T) {
	_, docNil, err := Build(realizeInput(nil))
	if err != nil {
		t.Fatal(err)
	}
	_, docIdentity, err := Build(realizeInput(func(p string) string { return p }))
	if err != nil {
		t.Fatal(err)
	}
	if string(docNil) != string(docIdentity) {
		t.Fatalf("Realize nil vs identidad explícita deben producir el mismo documento:\nnil:      %s\nidentidad: %s", docNil, docIdentity)
	}
}

// TestRealizeAppliesToOperatorFacingPaths cubre el caso (b) del brief: un
// Realize que invierte un remapeo conocido (administrator/ → adm1ng/, la
// dirección real de layout.Config.Realize) debe traducir las rutas de cara al
// operador — F.Subject, not_analyzed[].path, omissions[].path,
// unverified_executables[].files[].path, extensions[].manifest_path y
// extensions[].roots[] — a la ruta REAL, y coverage.layout debe declarar el
// remapeo (remap_applied:true, admin_dir:"adm1ng").
func TestRealizeAppliesToOperatorFacingPaths(t *testing.T) {
	realize := func(p string) string {
		if p == "administrator" {
			return "adm1ng"
		}
		if strings.HasPrefix(p, "administrator/") {
			return "adm1ng/" + p[len("administrator/"):]
		}
		return p
	}
	in := realizeInput(realize)
	in.LayoutStandard = false
	in.LayoutRemapApplied = true
	in.LayoutRemapAdminDir = "adm1ng"
	in.LayoutRemapSource = "operator"

	rep, _, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}

	var gotSubject string
	for _, f := range rep.Findings {
		if f.RuleID == "J0W-CORE-004" {
			gotSubject = f.Subject
		}
	}
	if gotSubject != "adm1ng/x.php" {
		t.Fatalf("F.Subject = %q, quiere adm1ng/x.php (realizado)", gotSubject)
	}

	if len(rep.Coverage.NotAnalyzed) != 1 || rep.Coverage.NotAnalyzed[0].Path != "adm1ng/cache/x.tmp" {
		t.Fatalf("Coverage.NotAnalyzed = %+v, quiere path=adm1ng/cache/x.tmp", rep.Coverage.NotAnalyzed)
	}
	if len(rep.Coverage.Omissions) != 1 || rep.Coverage.Omissions[0].Path != "adm1ng/uploads/y.dat" {
		t.Fatalf("Coverage.Omissions = %+v, quiere path=adm1ng/uploads/y.dat", rep.Coverage.Omissions)
	}

	att := rep.Coverage.Attribution
	if att == nil || att.UnverifiedExecutables == nil || len(att.UnverifiedExecutables.Files) != 1 {
		t.Fatalf("esperaba exactamente 1 unverified_executable: %+v", att)
	}
	if att.UnverifiedExecutables.Files[0].Path != "components/com_x/exec.php" {
		t.Fatalf("unverified_executables[0].Path = %q, quiere components/com_x/exec.php (fuera de administrator/, sin cambios)", att.UnverifiedExecutables.Files[0].Path)
	}

	if len(rep.Extensions) != 1 {
		t.Fatalf("esperaba 1 extensión: %+v", rep.Extensions)
	}
	ext := rep.Extensions[0]
	if ext.ManifestPath != "adm1ng/components/com_x/com_x.xml" {
		t.Fatalf("Ext.ManifestPath = %q, quiere adm1ng/components/com_x/com_x.xml", ext.ManifestPath)
	}
	if len(ext.Roots) != 2 || ext.Roots[0] != "adm1ng/components/com_x" || ext.Roots[1] != "components/com_x" {
		t.Fatalf("Ext.Roots = %v, quiere [adm1ng/components/com_x components/com_x]", ext.Roots)
	}

	if rep.Coverage.Layout == nil {
		t.Fatal("esperaba coverage.layout no nulo (remapeado)")
	}
	if !rep.Coverage.Layout.RemapApplied {
		t.Fatal("Coverage.Layout.RemapApplied debe ser true")
	}
	if rep.Coverage.Layout.AdminDir != "adm1ng" {
		t.Fatalf("Coverage.Layout.AdminDir = %q, quiere adm1ng", rep.Coverage.Layout.AdminDir)
	}
	if rep.Coverage.Layout.RemapSource != "operator" {
		t.Fatalf("Coverage.Layout.RemapSource = %q, quiere operator", rep.Coverage.Layout.RemapSource)
	}
}
