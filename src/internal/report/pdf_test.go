package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"j0witness/internal/finding"
	"j0witness/internal/i18n"
	"j0witness/internal/observe"
	"j0witness/internal/provenance"
)

// inputWithFindings arma un BuildInput con exactamente n hallazgos J0W-CODE-001
// (uno por observación CodeSuspicious/obfuscated_eval, cada una con subject
// distinto), para probar que RenderPDF refleja el CONTENIDO del informe (más
// hallazgos → PDF distinto y mayor), no solo la cabecera fija.
func inputWithFindings(n int) BuildInput {
	obs := make([]observe.Observation, 0, n)
	for i := 0; i < n; i++ {
		subject := []byte(fmt.Sprintf("path/file%d.php", i))
		o, _ := observe.New(subject, observe.CodeSuspicious, map[string]any{
			"construct": "obfuscated_eval", "sink": "eval", "trigger": "base64_decode", "line": i,
		}, observe.SrcCodescan, observe.High, int64(i))
		obs = append(obs, o)
	}
	finds := finding.Derive(obs, "5.1.0", map[string]bool{}, i18n.ES)

	return BuildInput{
		Prov: provenance.Provenance{
			ToolVersion:    "0.0.0-test",
			ToolHash:       "deadbeef",
			Invocation:     []string{"j0witness", "scan", "--target", "/tmp/fixture"},
			ThreatModel:    provenance.ModelPrimary,
			CatalogVersion: "1.0.0",
			RulesetVersion: "1.0.0",
			NetworkUsed:    false,
		},
		Baseline: BaseRef{
			CMS:           "joomla",
			Version:       "5.1.0",
			PackageSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			ManifestSHA:   "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			Source:        "official-package",
		},
		TargetPath:   "/tmp/fixture",
		EntriesTotal: 10,
		FilesRegular: 8,
		BytesTotal:   4096,
		BytesHashed:  4096,
		Version: Version{
			Confidence:  "high",
			WitnessUsed: 3,
		},
		Observations: obs,
		Findings:     finds,
		FailOn:       finding.MediumS,
		Started:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Finished:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// minimalBuildInput arma un BuildInput mínimo pero completo (Prov, Baseline,
// Version, un par de Findings, Started/Finished fijos) para tener un
// documento canónico de fixture estable entre invocaciones de RenderPDF.
func minimalBuildInput() BuildInput {
	mk := func(subject string, typ observe.Type, ev map[string]any) observe.Observation {
		o, _ := observe.New([]byte(subject), typ, ev, observe.SrcCorediff, observe.High, 1)
		return o
	}
	obs := []observe.Observation{
		mk("index.php", observe.FileModified, map[string]any{"executable": true}),
	}
	finds := finding.Derive(obs, "1.1.0", map[string]bool{}, i18n.ES)

	return BuildInput{
		Prov: provenance.Provenance{
			ToolVersion:    "0.0.0-test",
			ToolHash:       "deadbeef",
			Invocation:     []string{"j0witness", "scan", "--target", "/tmp/fixture"},
			ThreatModel:    provenance.ModelPrimary,
			CatalogVersion: "1.0.0",
			RulesetVersion: "1.0.0",
			NetworkUsed:    false,
		},
		Baseline: BaseRef{
			CMS:           "joomla",
			Version:       "5.1.0",
			PackageSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			ManifestSHA:   "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			Source:        "official-package",
		},
		TargetPath:   "/tmp/fixture",
		EntriesTotal: 10,
		FilesRegular: 8,
		BytesTotal:   4096,
		BytesHashed:  4096,
		Version: Version{
			Confidence:  "high",
			WitnessUsed: 3,
		},
		Observations: obs,
		Findings:     finds,
		FailOn:       finding.MediumS,
		Started:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Finished:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// minimalBuildInputLang es minimalBuildInput() con Language y los Findings
// re-derivados en lang: ejercita RenderPDF/RenderText con el chrome en/es (Task
// 4) sobre un fixture por lo demás idéntico.
func minimalBuildInputLang(lang i18n.Lang) BuildInput {
	in := minimalBuildInput()
	in.Findings = finding.Derive(in.Observations, "1.1.0", map[string]bool{}, lang)
	in.Language = lang
	return in
}

func TestRenderPDFDeterministic(t *testing.T) {
	for _, lang := range []i18n.Lang{i18n.ES, i18n.EN} {
		t.Run(string(lang), func(t *testing.T) {
			_, doc, err := Build(minimalBuildInputLang(lang))
			if err != nil {
				t.Fatal(err)
			}
			a, err := RenderPDF(doc)
			if err != nil {
				t.Fatal(err)
			}
			b, err := RenderPDF(doc)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a, b) {
				t.Fatalf("RenderPDF no es reproducible (%s): %d vs %d bytes, difieren", lang, len(a), len(b))
			}
			if !bytes.HasPrefix(a, []byte("%PDF-")) {
				t.Fatalf("no parece un PDF (%s): %q", lang, a[:min(8, len(a))])
			}
			if len(a) < 400 {
				t.Fatalf("PDF sospechosamente pequeño (%s): %d bytes", lang, len(a))
			}
		})
	}
}

// TestRenderPDFReflectsContentEN cubre el Task 4: un informe con
// language:"en" produce un PDF válido (prefijo %PDF, tamaño no trivial) y
// distinto en bytes del mismo documento en "es" — el chrome (títulos de
// sección, resumen de instalación…) sí cambia con el idioma.
func TestRenderPDFReflectsContentEN(t *testing.T) {
	_, docES, err := Build(minimalBuildInputLang(i18n.ES))
	if err != nil {
		t.Fatal(err)
	}
	_, docEN, err := Build(minimalBuildInputLang(i18n.EN))
	if err != nil {
		t.Fatal(err)
	}
	en, err := RenderPDF(docEN)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(en, []byte("%PDF-")) {
		t.Fatalf("no parece un PDF: %q", en[:min(8, len(en))])
	}
	if len(en) < 400 {
		t.Fatalf("PDF (en) sospechosamente pequeño: %d bytes", len(en))
	}
	es, err := RenderPDF(docES)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(en, es) {
		t.Fatal("RenderPDF(en) es byte-idéntico a RenderPDF(es): el chrome no está traducido")
	}
}

// TestRenderPDFReflectsContent prueba que el render refleja el contenido del
// informe: dos informes idénticos salvo que el segundo tiene MÁS hallazgos →
// su PDF es más grande y distinto (el layout completo no es un molde
// estático que ignore r.Findings), y ambos siguen siendo reproducibles.
func TestRenderPDFReflectsContent(t *testing.T) {
	_, docA, err := Build(inputWithFindings(1))
	if err != nil {
		t.Fatal(err)
	}
	_, docB, err := Build(inputWithFindings(3))
	if err != nil {
		t.Fatal(err)
	}
	a, err := RenderPDF(docA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RenderPDF(docB)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("PDF no refleja el contenido del informe")
	}
	if len(b) <= len(a) {
		t.Fatalf("más hallazgos debería dar PDF mayor: %d vs %d", len(a), len(b))
	}

	// Ambos documentos siguen siendo reproducibles con el layout completo.
	a2, err := RenderPDF(docA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, a2) {
		t.Fatal("RenderPDF(docA) no es reproducible")
	}
	b2, err := RenderPDF(docB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, b2) {
		t.Fatal("RenderPDF(docB) no es reproducible")
	}
}

// TestRenderPDFReflectsExtensionsByType prueba que la sección "Resumen de la
// instalación" (Task 2) refleja Coverage.ExtensionsByType: dos informes
// idénticos salvo el desglose de extensiones por tipo producen PDFs
// distintos, y cada uno sigue siendo reproducible (render ×2 idéntico) con la
// sección nueva — ancla el requisito de determinismo: iterar extTypeOrder,
// nunca range sobre el map.
func TestRenderPDFReflectsExtensionsByType(t *testing.T) {
	inA := minimalBuildInput()
	inA.Extensions = []Ext{
		{Type: "plugin", Name: "p1", ManifestPath: "plugins/system/p1/p1.xml"},
		{Type: "plugin", Name: "p2", ManifestPath: "plugins/system/p2/p2.xml"},
	}
	inB := minimalBuildInput()
	inB.Extensions = []Ext{
		{Type: "component", Name: "c1", ManifestPath: "components/com_c1/com_c1.xml"},
		{Type: "module", Name: "m1", ManifestPath: "modules/mod_m1/mod_m1.xml"},
		{Type: "template", Name: "t1", ManifestPath: "templates/t1/templateDetails.xml"},
	}

	_, docA, err := Build(inA)
	if err != nil {
		t.Fatal(err)
	}
	_, docB, err := Build(inB)
	if err != nil {
		t.Fatal(err)
	}

	a, err := RenderPDF(docA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RenderPDF(docB)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("PDF no refleja Coverage.ExtensionsByType: dos desgloses distintos dieron el mismo PDF")
	}

	a2, err := RenderPDF(docA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, a2) {
		t.Fatal("RenderPDF(docA) con extensions_by_type no es reproducible")
	}
	b2, err := RenderPDF(docB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, b2) {
		t.Fatal("RenderPDF(docB) con extensions_by_type no es reproducible")
	}
}

// TestRenderPDFEmptyFindings prueba que un informe SIN hallazgos renderiza
// sin pánico y produce un PDF válido con la sección "Ninguno.".
func TestRenderPDFEmptyFindings(t *testing.T) {
	_, doc, err := Build(inputWithFindings(0))
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderPDF(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Fatalf("no parece un PDF: %q", out[:min(8, len(out))])
	}
}

// TestRenderPDFMalformedJSON prueba que un documento canónico corrupto
// devuelve un error (no panic): RenderPDF nunca debe reventar el proceso
// que sirve el informe por un JSON de entrada roto.
func TestRenderPDFMalformedJSON(t *testing.T) {
	out, err := RenderPDF([]byte("{not json"))
	if err == nil {
		t.Fatal("RenderPDF con JSON malformado debería devolver error, no nil")
	}
	if out != nil {
		t.Fatalf("RenderPDF con JSON malformado debería devolver nil bytes, dio %d bytes", len(out))
	}
}

// sampleCanonical arma el documento canónico de minimalBuildInput() y, si
// withBlocks es true, le añade BaselineVerification y Coverage.ForeignRoots
// (Task 1 del plan 002-extensiones-mapa-propiedad) antes de re-serializar con
// CanonicalMarshal — para probar que RenderPDF dibuja ambos bloques nuevos.
func sampleCanonical(t *testing.T, withBlocks bool) []byte {
	t.Helper()
	_, doc, err := Build(minimalBuildInput())
	if err != nil {
		t.Fatal(err)
	}
	if !withBlocks {
		return doc
	}
	var rep Report
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatal(err)
	}
	rep.BaselineVerification = &BaselineVerification{
		VerifiedAgainst: "embedded-catalog",
		CatalogVersion:  "joomla-5.4.7",
		PackageSHA256:   "abc",
		ManifestSource:  "rederived-from-verified-package",
		Assurance:       "verified",
	}
	rep.Coverage.ForeignRoots = []ForeignRoot{
		{Root: "map", Files: 132, Executables: 3, DistributionDir: false},
		{Root: "images", Files: 10, Executables: 0, DistributionDir: true},
	}
	out, err := CanonicalMarshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// sampleCanonicalDT arma el documento canónico de minimalBuildInput() con
// Coverage.Database y Coverage.Timeline añadidos (Task 2 del plan
// plan-pdf-bloques-cobertura), análogo a sampleCanonical(withBlocks=true)
// pero para los bloques de la capa L7 (dbscan) y L6 (timeline).
// Correspondence:"mismatch" ejercita también la línea de salvedad
// pdf.database_mismatch.
func sampleCanonicalDT(t *testing.T) []byte {
	t.Helper()
	_, doc, err := Build(minimalBuildInput())
	if err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatal(err)
	}
	rep.Coverage.Database = &DBCoverage{
		Prefix:           "site1_",
		UsersParsed:      2,
		ExtensionsParsed: 222,
		ModulesParsed:    91,
		PrivilegedRoster: []string{"admin"},
		Correspondence:   "mismatch",
		AbsentFraction:   0.33,
	}
	rep.Coverage.Timeline = &TimelineCoverage{
		CohortEarliest: "2020-01-01T00:00:00Z",
		CohortLatest:   "2020-06-01T00:00:00Z",
		TotalFiles:     9000,
		Outliers:       0,
		Manipulations:  0,
	}
	out, err := CanonicalMarshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRenderPDFDatabaseAndTimeline cubre Task 2 del plan
// plan-pdf-bloques-cobertura: un informe con Coverage.Database y
// Coverage.Timeline debe producir un PDF mayor que uno sin esos bloques (el
// chrome nuevo se dibuja de verdad), y seguir siendo reproducible.
func TestRenderPDFDatabaseAndTimeline(t *testing.T) {
	base := mustRenderPDF(t, sampleCanonical(t, false))
	withDT := mustRenderPDF(t, sampleCanonicalDT(t))
	if len(withDT) <= len(base) {
		t.Errorf("el PDF con database+timeline debe ser mayor: %d vs %d", len(withDT), len(base))
	}
	again := mustRenderPDF(t, sampleCanonicalDT(t))
	if !bytes.Equal(withDT, again) {
		t.Error("RenderPDF no determinista con database+timeline")
	}
}

// sampleCanonicalRoster arma el documento canónico de minimalBuildInput()
// con Coverage.Database.PrivilegedRoster de exactamente n cuentas
// ("admin01".."adminNN", ancho fijo para que el único delta de bytes entre
// dos tamaños de roster sea la propia lista + el indicador de truncación,
// nunca el ancho de los nombres). Usado por
// TestRenderPDFDatabaseRosterTruncationIndicator (review final, Principio
// VII: la línea de cuentas privilegiadas no debe truncar en silencio).
func sampleCanonicalRoster(t *testing.T, n int) []byte {
	t.Helper()
	_, doc, err := Build(minimalBuildInput())
	if err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatal(err)
	}
	roster := make([]string, n)
	for i := 0; i < n; i++ {
		roster[i] = fmt.Sprintf("admin%02d", i+1)
	}
	rep.Coverage.Database = &DBCoverage{
		Prefix:           "site1_",
		UsersParsed:      n,
		ExtensionsParsed: 1,
		ModulesParsed:    1,
		PrivilegedRoster: roster,
	}
	out, err := CanonicalMarshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRenderPDFDatabaseRosterTruncationIndicator cubre el hallazgo del
// review final del feature 014 (Principio VII): un PrivilegedRoster de más
// de topN cuentas debe DEJAR VISIBLE que se truncó (sufijo "y N más"), no
// limitarse a cortar la lista en silencio. topN cuentas (sin truncar) vs
// topN+1 (truncado, con sufijo) comparten las primeras topN entradas
// idénticas ("admin01".."admin10"): cualquier diferencia de tamaño entre
// ambos PDFs viene del indicador de truncación, no del contenido de la
// lista — y el render sigue siendo determinista.
func TestRenderPDFDatabaseRosterTruncationIndicator(t *testing.T) {
	exact := mustRenderPDF(t, sampleCanonicalRoster(t, topN))
	truncated := mustRenderPDF(t, sampleCanonicalRoster(t, topN+1))
	if len(truncated) <= len(exact) {
		t.Errorf("un roster truncado (%d cuentas) debe mostrar el indicador de truncación y ser mayor que uno sin truncar (%d cuentas): %d vs %d bytes", topN+1, topN, len(truncated), len(exact))
	}
	again := mustRenderPDF(t, sampleCanonicalRoster(t, topN+1))
	if !bytes.Equal(truncated, again) {
		t.Error("RenderPDF no determinista con el roster truncado")
	}
}

func mustRenderPDF(t *testing.T, canonical []byte) []byte {
	t.Helper()
	out, err := RenderPDF(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRenderPDFForeignAndBaseline cubre Task 1 del plan
// 002-extensiones-mapa-propiedad: un informe con BaselineVerification y
// Coverage.ForeignRoots debe producir un PDF mayor que uno sin esos bloques
// (el chrome nuevo se dibuja de verdad), y seguir siendo reproducible.
func TestRenderPDFForeignAndBaseline(t *testing.T) {
	base := mustRenderPDF(t, sampleCanonical(t, false))
	with := mustRenderPDF(t, sampleCanonical(t, true))
	if len(with) <= len(base) {
		t.Errorf("el PDF con baseline_verification+foreign_roots debe ser mayor (%d) que sin ellos (%d)", len(with), len(base))
	}
	again := mustRenderPDF(t, sampleCanonical(t, true))
	if !bytes.Equal(with, again) {
		t.Error("RenderPDF no determinista con los bloques nuevos")
	}
}

// TestRenderPDFStandardLayout cubre el caso real más común: un árbol
// administrator/ estándar (LayoutStandard: true), donde Coverage.Layout es
// nil. Todas las demás fixtures de este archivo dejan LayoutStandard en su
// cero-valor (false), así que sin este test la rama "estándar" de
// writeCoverage (la que se ejecuta en la inmensa mayoría de escaneos reales)
// no estaba cubierta.
func TestRenderPDFStandardLayout(t *testing.T) {
	in := minimalBuildInput()
	in.LayoutStandard = true
	_, doc, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Coverage.Layout != nil {
		t.Fatalf("Coverage.Layout = %+v, quiere nil (árbol estándar)", rep.Coverage.Layout)
	}

	a, err := RenderPDF(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(a, []byte("%PDF-")) {
		t.Fatalf("no parece un PDF: %q", a[:min(8, len(a))])
	}
	b, err := RenderPDF(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("RenderPDF no es reproducible con layout estándar: %d vs %d bytes, difieren", len(a), len(b))
	}
}
