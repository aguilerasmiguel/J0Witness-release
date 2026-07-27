package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"j0witness/internal/i18n"
)

// extTypeOrder es el orden fijo en que se recorren los tipos de extensión al
// proyectar Coverage.ExtensionsByType (un map): iterarlo con range directo
// rompería el determinismo (Principio IV, ver pdf.go). Se define una sola vez
// aquí y la usan tanto RenderText como RenderPDF. Es dato de ORDEN, no de
// idioma — las etiquetas por idioma viven en i18n.ExtTypeLabel.
var extTypeOrder = []string{"component", "module", "plugin", "template", "library", "language", "file", "package"}

// versionSummary devuelve la versión de Joomla inferida/declarada con sus
// fallbacks ("no concluyente"/"no legible") cuando el puntero es nil. Usado
// tanto por RenderText (cabecera y "Resumen de la instalación") como por
// RenderPDF, para no duplicar el nil-check en ambos renderers.
func versionSummary(r *Report) (inferred, declared string) {
	inferred, declared = "no concluyente", "no legible"
	if r.VersionInf.Inferred != nil {
		inferred = *r.VersionInf.Inferred
	}
	if r.VersionInf.Declared != nil {
		declared = *r.VersionInf.Declared
	}
	return inferred, declared
}

// thirdPartyTotal devuelve Coverage.Attribution.ThirdPartyExtensions, o 0 si
// Attribution es nil (informe sin extensiones de terceros). Usado por ambos
// renderers en la sección "Resumen de la instalación".
func thirdPartyTotal(r *Report) int {
	if r.Coverage.Attribution != nil {
		return r.Coverage.Attribution.ThirdPartyExtensions
	}
	return 0
}

// extraExtTypes devuelve, en orden alfabético (determinismo: nunca range de
// map para salida, ver comentario en pdf.go), las claves de byType que NO
// están en extTypeOrder. Coverage.ExtensionsByType podría en teoría contener
// un tipo fuera de la lista fija (Ext.Type vacío/desconocido, o un tipo
// futuro de Joomla); esas claves SÍ cuentan en el total
// (attribution.third_party_extensions) pero antes no se imprimían en el
// desglose por tipo, así que las líneas no sumaban el total. Se renderizan
// aparte usando el string crudo como etiqueta.
func extraExtTypes(byType map[string]int) []string {
	known := make(map[string]bool, len(extTypeOrder))
	for _, t := range extTypeOrder {
		known[t] = true
	}
	var extra []string
	for t := range byType {
		if !known[t] {
			extra = append(extra, t)
		}
	}
	sort.Strings(extra)
	return extra
}

// RenderText es una proyección derivada del documento JSON canónico: se
// genera DESDE el JSON ya emitido, nunca desde el análisis (Principio X).
func RenderText(canonical []byte) ([]byte, error) {
	var r Report
	if err := json.Unmarshal(canonical, &r); err != nil {
		return nil, fmt.Errorf("el documento canónico no parsea: %w", err)
	}
	lang, err := i18n.Parse(r.Language)
	if err != nil {
		lang = i18n.ES
	}
	var b strings.Builder
	fmt.Fprintf(&b, i18n.T(lang, "text.header", nil), r.SchemaVersion)
	fmt.Fprintf(&b, i18n.T(lang, "text.target", nil),
		r.Target.Path, r.Target.EntriesTotal, r.Target.FilesRegular, r.Target.BytesTotal)
	fmt.Fprintf(&b, i18n.T(lang, "text.baseline", nil),
		r.Provenance.Baseline.CMS, r.Provenance.Baseline.Version,
		short(r.Provenance.Baseline.PackageSHA256), r.Provenance.Baseline.Source)
	// baseline_verification (1.13.0, feature 013): solo se emite cuando el
	// bloque está presente (resolveBaseline pudo verificar contra el catálogo
	// embebido; ausente si la versión quedó fuera de cobertura). Valores de
	// enum crudos (catalog_version/assurance), sin traducir (Principio VII).
	if r.BaselineVerification != nil {
		fmt.Fprintf(&b, i18n.T(lang, "text.baseline_verified", nil),
			r.BaselineVerification.CatalogVersion, r.BaselineVerification.Assurance)
	}
	fmt.Fprintf(&b, i18n.T(lang, "text.threatmodel", nil), r.Provenance.ThreatModel)

	inferred, declared := versionSummary(&r)
	fmt.Fprintf(&b, i18n.T(lang, "text.version", nil),
		inferred, r.VersionInf.Confidence, declared, r.VersionInf.WitnessUsed)
	if r.VersionInf.MixedVersions {
		b.WriteString(i18n.T(lang, "text.mixed", nil))
	}

	fmt.Fprintf(&b, i18n.T(lang, "text.coverage", nil),
		r.Coverage.Analyzed.Entries, r.Coverage.Analyzed.BytesHashed,
		len(r.Coverage.NotAnalyzed), len(r.Coverage.Omissions))
	for _, na := range r.Coverage.NotAnalyzed {
		fmt.Fprintf(&b, i18n.T(lang, "text.notanalyzed", nil), na.Path, na.Reason)
	}

	// Raíces ajenas a la distribución (feature 012, refinamiento post-shipping):
	// contenido de disco ajeno tanto al core como a las extensiones
	// registradas, agregado por raíz de nivel superior — cobertura, nunca un
	// hallazgo. r.Coverage.ForeignRoots ya viene ordenado (report.ForeignRoots:
	// DistributionDir asc, luego executables desc, luego root asc — las
	// raíces genuinamente ajenas surgen primero); se itera tal cual, sin
	// volver a ordenar ni recorrer un map. Cada línea etiqueta la raíz como
	// ajena a la distribución o dir de Joomla con contenido de usuario, para
	// que el analista distinga app/media de dirs estándar del CMS.
	if len(r.Coverage.ForeignRoots) > 0 {
		fmt.Fprintf(&b, i18n.T(lang, "text.foreign_roots", nil), len(r.Coverage.ForeignRoots))
		for _, fr := range r.Coverage.ForeignRoots {
			label := i18n.T(lang, "text.foreign_root_foreign", nil)
			if fr.DistributionDir {
				label = i18n.T(lang, "text.foreign_root_joomla", nil)
			}
			fmt.Fprintf(&b, i18n.T(lang, "text.foreign_root_line", nil), fr.Root, fr.Files, fr.Executables, label)
		}
	}

	writeInstallationSummaryText(&b, &r, lang)

	fmt.Fprintf(&b, i18n.T(lang, "text.findings_header", nil), len(r.Findings))
	if len(r.Findings) == 0 {
		b.WriteString(i18n.T(lang, "text.finding_none", nil))
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, i18n.T(lang, "text.finding_block", nil), strings.ToUpper(f.Severity), f.RuleID, f.ID, f.Subject)
		fmt.Fprintf(&b, i18n.T(lang, "text.f_observed", nil), f.Observed)
		fmt.Fprintf(&b, i18n.T(lang, "text.f_compared", nil), f.ComparedTo)
		fmt.Fprintf(&b, i18n.T(lang, "text.f_rationale", nil), f.Rationale)
		fmt.Fprintf(&b, i18n.T(lang, "text.f_confidence", nil), f.Confidence)
		if f.Alternative != "" {
			fmt.Fprintf(&b, i18n.T(lang, "text.f_alternative", nil), f.Alternative)
		}
	}

	// Inventario de extensiones de terceros (feature 002).
	if len(r.Extensions) > 0 {
		att := r.Coverage.Attribution
		if att != nil {
			fmt.Fprintf(&b, i18n.T(lang, "text.ext_header_att", nil),
				att.ThirdPartyExtensions, att.FilesAttributed)
			b.WriteString(i18n.T(lang, "text.ext_unverified_note", nil))
		} else {
			fmt.Fprintf(&b, i18n.T(lang, "text.ext_header_plain", nil), len(r.Extensions))
		}
		for _, e := range r.Extensions {
			ver, auth := "?", "?"
			if e.DeclaredVersion != nil {
				ver = *e.DeclaredVersion
			}
			if e.DeclaredAuthor != nil {
				auth = *e.DeclaredAuthor
			}
			fmt.Fprintf(&b, i18n.T(lang, "text.ext_row", nil), e.Type, e.Name, ver, auth, e.FilesDeclared)
		}
	}

	if len(r.Suppressions) > 0 {
		fmt.Fprintf(&b, i18n.T(lang, "text.suppr_header", nil), len(r.Suppressions))
		for _, s := range r.Suppressions {
			fmt.Fprintf(&b, i18n.T(lang, "text.suppr_row", nil), s.RuleID, s.PathGlob, len(s.Matched), s.Reason)
		}
	}

	fmt.Fprintf(&b, i18n.T(lang, "text.summary", nil),
		r.Summary.BySeverity["critical"], r.Summary.BySeverity["high"],
		r.Summary.BySeverity["medium"], r.Summary.BySeverity["low"],
		r.Summary.BySeverity["info"], r.Summary.ExitCode)
	if r.Summary.UnverifiedExecutables > 0 {
		fmt.Fprintf(&b, i18n.T(lang, "text.unverified_exec", nil),
			r.Summary.UnverifiedExecutables)
	}
	return []byte(b.String()), nil
}

// writeInstallationSummaryText proyecta la sección "Resumen de la
// instalación": versión de Joomla, extensiones de terceros por tipo (orden
// fijo extTypeOrder, seguido de cualquier tipo fuera de esa lista en orden
// alfabético vía extraExtTypes — nunca range sobre el map, ver comentario en
// pdf.go), archivos/bytes analizados, cobertura de análisis de código (L4) y de
// verificación de extensiones. Todos los sub-bloques son nil-safe: un informe
// sin extensiones/código/verificación se renderiza sin esas líneas, sin
// pánico (Report es DATO externo, no invariante de invocación).
func writeInstallationSummaryText(b *strings.Builder, r *Report, lang i18n.Lang) {
	b.WriteString(i18n.T(lang, "text.install_header", nil))

	inferred, declared := versionSummary(r)
	fmt.Fprintf(b, i18n.T(lang, "text.install_version", nil),
		inferred, r.VersionInf.Confidence, declared)

	total := thirdPartyTotal(r)
	fmt.Fprintf(b, i18n.T(lang, "text.install_thirdparty", nil), total)
	anyExt := false
	for _, t := range extTypeOrder {
		if n := r.Coverage.ExtensionsByType[t]; n > 0 {
			fmt.Fprintf(b, i18n.T(lang, "text.install_ext_row", nil), i18n.ExtTypeLabel(lang, t), n)
			anyExt = true
		}
	}
	for _, t := range extraExtTypes(r.Coverage.ExtensionsByType) {
		if n := r.Coverage.ExtensionsByType[t]; n > 0 {
			fmt.Fprintf(b, i18n.T(lang, "text.install_ext_row", nil), t, n)
			anyExt = true
		}
	}
	if !anyExt {
		b.WriteString(i18n.T(lang, "text.install_ext_none", nil))
	}

	fmt.Fprintf(b, i18n.T(lang, "text.install_analyzed", nil), r.Target.FilesRegular, r.Target.BytesTotal)

	if r.Coverage.CodeAnalysis != nil {
		fmt.Fprintf(b, i18n.T(lang, "text.install_code", nil),
			r.Coverage.CodeAnalysis.FilesScanned, r.Coverage.CodeAnalysis.FilesFlagged)
	}

	if r.Coverage.ExtensionVerification != nil {
		ev := r.Coverage.ExtensionVerification
		fmt.Fprintf(b, i18n.T(lang, "text.install_verif", nil),
			ev.ExtensionsVerified, ev.ExtensionsVerifiable)
	}
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
