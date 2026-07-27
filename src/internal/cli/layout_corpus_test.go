package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"j0witness/internal/corpus"
	"j0witness/internal/lab"
)

// layoutCorpusReport es el subconjunto del informe que interesa a las
// aserciones de fase 2d, Task 6 (corpus de admin renombrado): hallazgos y
// coverage.layout completo (los 6 campos de report.LayoutCoverage).
type layoutCorpusReport struct {
	Findings []struct {
		RuleID   string `json:"rule_id"`
		Subject  string `json:"subject"`
		Severity string `json:"severity"`
	} `json:"findings"`
	Coverage struct {
		Layout *struct {
			Standard      bool   `json:"standard"`
			AdminDirFound string `json:"admin_dir_found"`
			RemapApplied  bool   `json:"remap_applied"`
			AdminDir      string `json:"admin_dir"`
			ApiDir        string `json:"api_dir"`
			RemapSource   string `json:"remap_source"`
		} `json:"layout"`
	} `json:"coverage"`
}

func parseLayoutCorpusReport(t *testing.T, doc []byte) layoutCorpusReport {
	t.Helper()
	var rep layoutCorpusReport
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatalf("informe no parsea: %v\n%s", err, doc)
	}
	return rep
}

// TestLayoutRenamedAutoremapNoStorm (fase 2d, Task 6) es el corazón de la
// feature: un árbol minicms con administrator/ renombrado a adm1ng/ (misma
// fixture que layout-nonstandard.yaml usa vía el op rename_dir de
// internal/corpus/corpus.go — reutilizado sin cambios, no se necesita un
// helper nuevo: "el fixture ya lo materializa renombrado", como prevé el
// brief), escaneado SIN bandera, debe:
//  1. Auto-detectarse (coverage.layout.remap_source == "auto-detected") y
//     remapearse (remap_applied == true, admin_dir == "adm1ng").
//  2. NO disparar J0W-LAYOUT-001 (el remapeo aplicado retira esa
//     observación, ver finding/derive.go case observe.LayoutRemap).
//  3. NO disparar la tormenta de J0W-CORE-* que ocurriría si
//     Canonicalize no aplicara (corediff vería TODO administrator/ ausente
//     Y todo adm1ng/ como contenido ajeno al core: cientos de
//     J0W-CORE-003/005 potenciales sobre un árbol tan pequeño como minicms).
//
// La aserción concreta de "sin tormenta" no es solo "exit 0": es que el
// NÚMERO TOTAL de hallazgos del árbol renombrado sea IDÉNTICO al del árbol
// estándar (clean-minicms, que no tiene mutaciones de contenido y por tanto
// hallazgos == 0) — la canonicalización hace ambos árboles equivalentes de
// cara al análisis, así que sus perfiles de hallazgos deben serlo también.
func TestLayoutRenamedAutoremapNoStorm(t *testing.T) {
	h := newHarness(t)

	stdRecipe, stdExit, stdDoc, stdStderr := h.scanCase(t, "clean-minicms")
	assertExpectations(t, stdRecipe, stdExit, stdDoc, stdStderr)
	stdReport := parseLayoutCorpusReport(t, stdDoc)

	r, exit, doc, stderr := h.scanCase(t, "layout-renamed-autoremap")
	assertExpectations(t, r, exit, doc, stderr)
	rep := parseLayoutCorpusReport(t, doc)

	// La aserción "sin tormenta", concreta: mismo número de hallazgos que el
	// árbol estándar (ambos 0), no solo ausencia de algunos rule_id puntuales.
	if len(rep.Findings) != len(stdReport.Findings) {
		t.Errorf("layout-renamed-autoremap: %d hallazgos, esperaba %d (igual que clean-minicms, sin tormenta admin): %+v",
			len(rep.Findings), len(stdReport.Findings), rep.Findings)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("layout-renamed-autoremap: %d hallazgos, esperaba 0: %+v", len(rep.Findings), rep.Findings)
	}

	if rep.Coverage.Layout == nil {
		t.Fatal("layout-renamed-autoremap: coverage.layout ausente, esperaba remapeo declarado")
	}
	lc := rep.Coverage.Layout
	if !lc.RemapApplied {
		t.Error("coverage.layout.remap_applied debe ser true")
	}
	if lc.RemapSource != "auto-detected" {
		t.Errorf("coverage.layout.remap_source=%q, esperaba \"auto-detected\"", lc.RemapSource)
	}
	if lc.AdminDir != "adm1ng" {
		t.Errorf("coverage.layout.admin_dir=%q, esperaba \"adm1ng\"", lc.AdminDir)
	}
	if lc.Standard {
		t.Error("coverage.layout.standard debe ser false (el árbol real SÍ tiene el dir renombrado)")
	}
}

// TestLayoutRenamedFlagOperatorSource (fase 2d, Task 6) es la contraparte con
// --administrator-dir=adm1ng explícito sobre el MISMO árbol renombrado: debe
// verificar igual de limpio que la auto-detección, difiriendo solo en
// remap_source ("operator" en vez de "auto-detected") — layout.Resolve
// prioriza la bandera del operador sobre DetectAdmin (internal/layout/config.go).
func TestLayoutRenamedFlagOperatorSource(t *testing.T) {
	h := newHarness(t)
	r, exit, doc, stderr := h.scanCase(t, "layout-renamed-flag")
	assertExpectations(t, r, exit, doc, stderr)
	rep := parseLayoutCorpusReport(t, doc)

	if len(rep.Findings) != 0 {
		t.Errorf("layout-renamed-flag: %d hallazgos, esperaba 0: %+v", len(rep.Findings), rep.Findings)
	}
	if rep.Coverage.Layout == nil {
		t.Fatal("layout-renamed-flag: coverage.layout ausente, esperaba remapeo declarado")
	}
	lc := rep.Coverage.Layout
	if !lc.RemapApplied {
		t.Error("coverage.layout.remap_applied debe ser true")
	}
	if lc.RemapSource != "operator" {
		t.Errorf("coverage.layout.remap_source=%q, esperaba \"operator\" (--administrator-dir explícito)", lc.RemapSource)
	}
	if lc.AdminDir != "adm1ng" {
		t.Errorf("coverage.layout.admin_dir=%q, esperaba \"adm1ng\"", lc.AdminDir)
	}
}

// TestLayoutRenamedTrojanCaught (fase 2d, Task 6) prueba que el remapeo de
// layout NO ciega la detección (Principio XI): un archivo del core admin
// modificado con una inyección, viviendo bajo el nombre renombrado
// (adm1ng/components/com_app/app.php), SIGUE cazándose como J0W-CORE-002
// crítico. Además confirma que el subject reportado es la ruta REAL
// realizada ("adm1ng/...") y no la canónica interna ("administrator/..."),
// y que el remapeo sigue declarado (sin J0W-LAYOUT-001) pese al hallazgo.
func TestLayoutRenamedTrojanCaught(t *testing.T) {
	h := newHarness(t)
	r, exit, doc, stderr := h.scanCase(t, "layout-renamed-trojan")
	assertExpectations(t, r, exit, doc, stderr)
	rep := parseLayoutCorpusReport(t, doc)

	const wantSubject = "adm1ng/components/com_app/app.php"
	var found bool
	for _, f := range rep.Findings {
		if f.RuleID == "J0W-CORE-002" && f.Subject == wantSubject {
			found = true
			if f.Severity != "critical" {
				t.Errorf("J0W-CORE-002 %s: severity=%q, esperaba critical", wantSubject, f.Severity)
			}
		}
		// El subject nunca debe llevar la ruta canónica interna sin realizar:
		// probaría que el Realize de fase 2d, T5 no se aplicó a este hallazgo.
		if f.RuleID == "J0W-CORE-002" && f.Subject == "administrator/components/com_app/app.php" {
			t.Errorf("J0W-CORE-002 con subject canónico sin realizar (%s): el remapeo debe mostrar la ruta REAL", f.Subject)
		}
	}
	if !found {
		t.Errorf("no se encontró J0W-CORE-002 sobre %s (subject realizado): %+v", wantSubject, rep.Findings)
	}

	if rep.Coverage.Layout == nil {
		t.Fatal("layout-renamed-trojan: coverage.layout ausente, esperaba remapeo declarado pese al troyano")
	}
	if !rep.Coverage.Layout.RemapApplied {
		t.Error("coverage.layout.remap_applied debe seguir siendo true: el troyano no invalida el remapeo")
	}
}

// TestLayoutRenamedExtensionAdminDiscovered (fase 2d, Task 6, fix round 1)
// prueba el fix de extmap.SafeReader: una extensión legítima cuyo lado admin
// (administrator/components/com_labext/…, manifiesto incluido) queda dentro
// del directorio de admin renombrado debe seguir descubriéndose con
// normalidad. Antes del fix, SafeReader abría la ruta CANÓNICA del
// manifiesto contra el árbol REAL (que solo tiene adm1ng/…): el Open fallaba
// y Discover lo reportaba como ext_manifest_malformed (J0W-EXT-003) — un
// falso positivo de Principio VI sobre una extensión perfectamente legítima.
// El contrato genérico (assertExpectations, vía la receta) ya cubre la
// ausencia de J0W-EXT-003/CORE-004/EXT-001/LAYOUT-001 y el exit 0 limpio;
// aquí, además, se confirma explícitamente que com_labext SÍ aparece en
// extensions[] como type "component" — la prueba positiva de descubrimiento,
// no solo la ausencia del hallazgo.
func TestLayoutRenamedExtensionAdminDiscovered(t *testing.T) {
	h := newHarness(t)
	r, exit, doc, stderr := h.scanCase(t, "layout-renamed-extension-admin")
	assertExpectations(t, r, exit, doc, stderr)

	var rep parsedVerificationReport
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatalf("informe no parsea: %v\n%s", err, doc)
	}
	var found bool
	for _, e := range rep.Extensions {
		if e.Name != "com_labext" {
			continue
		}
		found = true
		if e.Type != "component" {
			t.Errorf("com_labext: type=%q, esperaba component", e.Type)
		}
	}
	if !found {
		t.Fatalf("com_labext no aparece en extensions[] bajo admin renombrado: el manifiesto admin-side no se descubrió (%+v)", rep.Extensions)
	}
}

// TestLayoutCollisionUsageError (fase 2d, Task 6) prueba el fallo-ruidoso de
// layout.Resolve (Principio VI): adm1ng/ (renombrado) MÁS un administrator/
// literal señuelo (sin esqueleto) en el mismo árbol es una colisión — no se
// puede canonicalizar sin ambigüedad — y el scan debe fallar con
// USAGE_ERROR ANTES de tocar el análisis.
//
// No usa scanCase/assertExpectations: un fallo de resolución no produce
// informe JSON en stdout (Main devuelve el ExitError sin llegar a
// assembleReport), y assertExpectations siempre intenta parsear el
// documento. Por eso este test materializa la receta directamente (mismo
// mecanismo que scanCase, sin el paso de escaneo con aserciones JSON) y
// llama a h.run por su cuenta.
func TestLayoutCollisionUsageError(t *testing.T) {
	h := newHarness(t)
	r, err := corpus.Load(filepath.Join(recipesDir(t), "layout-collision.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(h.root, "case-"+r.Case)
	if err := r.Materialize(lab.MiniProvider{}, target); err != nil {
		t.Fatal(err)
	}

	args := append([]string{"scan", target}, r.ScanArgs...)
	exit, doc, stderr := h.run(t, args...)
	if exit != int(ExitUsageError) {
		t.Fatalf("exit=%d, esperaba %d (USAGE_ERROR); stderr=%s\ndoc=%s", exit, ExitUsageError, stderr, doc)
	}
	if !strings.Contains(stderr, "colisión") {
		t.Errorf("stderr no menciona la colisión de layout: %s", stderr)
	}
}
