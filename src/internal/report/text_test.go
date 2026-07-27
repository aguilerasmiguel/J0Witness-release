package report

import (
	"strings"
	"testing"
	"time"

	"j0witness/internal/finding"
	"j0witness/internal/i18n"
	"j0witness/internal/observe"
	"j0witness/internal/provenance"
)

// textFixtureInput arma el BuildInput fijo (baseline, un finding J0W-CORE-001,
// dos extensiones de terceros) usado por TestRenderTextEnglish y
// TestRenderTextSpanishUnchanged para ejercitar el desglose completo del
// chrome (cabecera, cobertura, resumen de instalación, hallazgo, inventario de
// extensiones, resumen) en ambos idiomas sobre EXACTAMENTE el mismo contenido.
func textFixtureInput(lang i18n.Lang) BuildInput {
	obs := []observe.Observation{
		func() observe.Observation {
			o, _ := observe.New([]byte("index.php"), observe.FileModified, map[string]any{"executable": true}, observe.SrcCorediff, observe.High, 1)
			return o
		}(),
	}
	finds := finding.Derive(obs, "1.1.0", map[string]bool{}, lang)

	return BuildInput{
		Language: lang,
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
		Extensions: []Ext{
			{Type: "plugin", Name: "p1", ManifestPath: "plugins/system/p1/p1.xml"},
			{Type: "component", Name: "c1", ManifestPath: "components/com_c1/com_c1.xml"},
		},
		Observations: obs,
		Findings:     finds,
		FailOn:       finding.MediumS,
		Started:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Finished:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// TestRenderTextSpanishUnchanged ancla la byte-identidad del Task 4: sobre el
// fixture de textFixtureInput con language "es" (retrocompat, cero-valor),
// RenderText debe seguir produciendo EXACTAMENTE la cadena dorada capturada
// del renderer ANTES de esta migración a i18n (verificado empíricamente: se
// generó con `git stash` sobre el text.go pre-Task-4 y el mismo fixture).
func TestRenderTextSpanishUnchanged(t *testing.T) {
	const golden = "J0Witness — informe de integridad (schema 1.13.0)\n" +
		"objetivo: /tmp/fixture (10 entradas, 8 archivos, 4096 bytes)\n" +
		"baseline: joomla 5.1.0 (paquete cccccccccccc, origen official-package)\n" +
		"modelo de amenaza: webserver-user-no-root\n" +
		"versión: inferida=no concluyente (confianza high) declarada=no legible testigos=3\n" +
		"\n" +
		"cobertura: 10 entradas analizadas, 4096 bytes hasheados; 0 no analizadas; 0 omisiones\n" +
		"\n" +
		"Resumen de la instalación:\n" +
		"  versión de Joomla: inferida=no concluyente (confianza high) declarada=no legible\n" +
		"  extensiones de terceros: 2\n" +
		"    componentes 1\n" +
		"    plugins 1\n" +
		"  analizado: 8 archivos, 4096 bytes\n" +
		"  verificación de extensiones: 0/2 verificables\n" +
		"\n" +
		"hallazgos (1):\n" +
		"\n" +
		"[HIGH] J0W-CORE-001 6c92012295e3b973 — index.php\n" +
		"  observado : archivo del core con contenido distinto al distribuido\n" +
		"  comparado : distribución oficial 1.1.0\n" +
		"  relevancia: cualquier divergencia del core no atribuible a normalización es una modificación efectiva\n" +
		"  confianza : high\n" +
		"\n" +
		"extensiones de terceros: 2 descubiertas, 0 archivos atribuidos\n" +
		"  (integridad no verificada contra el autor — feature posterior)\n" +
		"  component  c1             ?        ?                0 archivos\n" +
		"  plugin     p1             ?        ?                0 archivos\n" +
		"\n" +
		"resumen: critical=0 high=1 medium=0 low=0 info=0 → exit 1\n"

	_, doc, err := Build(textFixtureInput(i18n.ES))
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderText(doc)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != golden {
		t.Fatalf("salida es no es byte-idéntica a la dorada:\n--- got ---\n%s\n--- want ---\n%s", out, golden)
	}
}

// TestRenderTextEnglish cubre el Task 4: sobre el mismo fixture con
// language:"en", el chrome de RenderText sale en inglés (cabecera,
// "Installation summary", inventario de extensiones de terceros, cobertura…)
// y ningún centinela de chrome español sobrevive.
func TestRenderTextEnglish(t *testing.T) {
	_, doc, err := Build(textFixtureInput(i18n.EN))
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderText(doc)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)

	for _, want := range []string{"findings", "Installation summary", "third-party extensions", "coverage"} {
		if !strings.Contains(s, want) {
			t.Errorf("falta chrome en inglés: %q\n%s", want, s)
		}
	}
	for _, bad := range []string{"hallazgos", "Resumen de la instalación", "cobertura", "versión", "comparado", "relevancia"} {
		if strings.Contains(s, bad) {
			t.Errorf("chrome español presente en salida en: %q\n%s", bad, s)
		}
	}
}

// TestRenderTextBaselineVerification cubre el Task 3 (feature 013):
// RenderText imprime la línea text.baseline_verified con catalog_version y
// assurance (crudos, sin traducir) cuando Report.BaselineVerification está
// presente, y la omite por completo cuando es nil (el fixture base de
// textFixtureInput no lo declara — TestRenderTextSpanishUnchanged ya ancla
// esa ausencia byte a byte).
func TestRenderTextBaselineVerification(t *testing.T) {
	in := textFixtureInput(i18n.ES)
	in.Observations = append(in.Observations, func() observe.Observation {
		o, _ := observe.New(nil, observe.BaselineVerified, map[string]any{
			"version": "5.1.0", "package_sha256": in.Baseline.PackageSHA256, "manifest_sha256": in.Baseline.ManifestSHA,
			"verified_against": "embedded-catalog", "catalog_version": "joomla-5.4.7",
			"manifest_source": "rederived-from-verified-package", "assurance": "verified",
		}, observe.SrcBaseline, observe.High, 2)
		return o
	}())

	_, doc, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderText(doc)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "baseline verificado contra el catálogo embebido (joomla-5.4.7, assurance: verified)") {
		t.Fatalf("falta la línea de baseline_verified en es:\n%s", s)
	}

	// language:"en" reproduce la misma línea traducida, con los mismos valores
	// crudos (catalog_version/assurance no se traducen, Principio VII).
	inEN := in
	inEN.Language = i18n.EN
	_, docEN, err := Build(inEN)
	if err != nil {
		t.Fatal(err)
	}
	outEN, err := RenderText(docEN)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(outEN), "baseline verified against the embedded catalog (joomla-5.4.7, assurance: verified)") {
		t.Fatalf("falta la línea de baseline_verified en en:\n%s", outEN)
	}
}

// TestRenderTextInstallationSummary cubre el Task 2: RenderText proyecta una
// sección "Resumen de la instalación" con la versión de Joomla y el desglose
// de extensiones de terceros por tipo (orden fijo extTypeOrder), antes de los
// hallazgos.
func TestRenderTextInstallationSummary(t *testing.T) {
	version := "5.4.7"
	exts := []Ext{
		{Type: "plugin", Name: "p1", ManifestPath: "plugins/system/p1/p1.xml"},
		{Type: "plugin", Name: "p2", ManifestPath: "plugins/system/p2/p2.xml"},
		{Type: "component", Name: "c1", ManifestPath: "components/com_c1/com_c1.xml"},
	}
	_, doc, err := Build(BuildInput{
		Extensions:   exts,
		FailOn:       finding.MediumS,
		FilesRegular: 1234,
		BytesTotal:   567890,
		Version: Version{
			Inferred:   &version,
			Confidence: "high",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	out, err := RenderText(doc)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)

	if !strings.Contains(text, "Resumen de la instalación") {
		t.Fatalf("el texto no contiene el encabezado \"Resumen de la instalación\":\n%s", text)
	}
	if !strings.Contains(text, "5.4.7") {
		t.Fatalf("el texto no contiene la versión inferida 5.4.7:\n%s", text)
	}
	if !strings.Contains(text, "componentes 1") {
		t.Fatalf("el texto no contiene el desglose \"componentes 1\":\n%s", text)
	}
	if !strings.Contains(text, "plugins 2") {
		t.Fatalf("el texto no contiene el desglose \"plugins 2\":\n%s", text)
	}

	// La sección debe aparecer ANTES de los hallazgos.
	idxSummary := strings.Index(text, "Resumen de la instalación")
	idxFindings := strings.Index(text, "hallazgos (")
	if idxSummary == -1 || idxFindings == -1 || idxSummary >= idxFindings {
		t.Fatalf("\"Resumen de la instalación\" debe aparecer antes de \"hallazgos (\": summary@%d findings@%d", idxSummary, idxFindings)
	}
}

// TestRenderTextInstallationSummaryUnknownExtType cubre el MINOR 1 de la
// revisión final: un tipo de extensión fuera del extTypeOrder fijo (p.ej. un
// Ext.Type desconocido o vacío) NO debe desaparecer del desglose por tipo —
// cuenta en el total (attribution.third_party_extensions) y debe aparecer
// como línea propia, para que la suma de líneas coincida con el total.
func TestRenderTextInstallationSummaryUnknownExtType(t *testing.T) {
	exts := []Ext{
		{Type: "plugin", Name: "p1", ManifestPath: "plugins/system/p1/p1.xml"},
		{Type: "widget", Name: "w1", ManifestPath: "widgets/w1/w1.xml"},
	}
	_, doc, err := Build(BuildInput{
		Extensions: exts,
		FailOn:     finding.MediumS,
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderText(doc)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)

	if !strings.Contains(text, "widget 1") {
		t.Fatalf("el texto no contiene el desglose \"widget 1\" para el tipo desconocido:\n%s", text)
	}
	if !strings.Contains(text, "plugins 1") {
		t.Fatalf("el texto no contiene el desglose \"plugins 1\":\n%s", text)
	}
	if !strings.Contains(text, "extensiones de terceros: 2") {
		t.Fatalf("el total de extensiones de terceros debe ser 2 (suma de las líneas del desglose):\n%s", text)
	}
}

// TestRenderTextInstallationSummaryNoExtensions cubre el caso sin extensiones
// de terceros: la sección se renderiza limpia ("ninguna"), sin pánico.
func TestRenderTextInstallationSummaryNoExtensions(t *testing.T) {
	_, doc, err := Build(BuildInput{FailOn: finding.MediumS})
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderText(doc)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, "Resumen de la instalación") {
		t.Fatalf("el texto no contiene el encabezado \"Resumen de la instalación\":\n%s", text)
	}
	if !strings.Contains(text, "ninguna") {
		t.Fatalf("un informe sin extensiones debe mostrar \"ninguna\":\n%s", text)
	}
}
