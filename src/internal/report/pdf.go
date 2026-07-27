package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"j0witness/internal/i18n"

	"github.com/go-pdf/fpdf"
)

// severityOrder es el ÚNICO orden en que se recorren severidades para
// SALIDA (chips del resumen, agrupación de hallazgos): fijo y descendente.
// r.Summary.BySeverity es un map — iterarlo directamente con range rompería
// el Principio IV (orden de iteración de maps en Go no es determinista).
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// severityColor: paleta fija por severidad (fijada por el brief de la tarea,
// no configurable — forma parte de la identidad visual determinista del
// informe).
var severityColor = map[string][3]int{
	"critical": {192, 57, 43},
	"high":     {230, 126, 34},
	"medium":   {241, 196, 15},
	"low":      {52, 152, 219},
	"info":     {149, 165, 166},
}

// topN acota cuántas entradas de listas potencialmente largas (not_analyzed,
// unverified_executables) se listan en el PDF antes de resumir "y N más".
const topN = 10

// leftX es el margen izquierdo de contenido usado en todo el cuerpo del
// informe (coincide con el usado por la banda de cabecera de Task 1).
const leftX = 12.0

// RenderPDF es una proyección derivada del documento JSON canónico: se genera
// DESDE el JSON ya emitido, nunca desde el análisis (Principio X). Función
// PURA y DETERMINISTA del informe: mismo JSON → mismos bytes PDF.
//
// fpdf, por defecto, timestampa CreationDate/ModDate con time.Now() —
// ambos se fijan aquí desde run.finished_at (un valor DEL informe, no del
// reloj) para que dos invocaciones sobre el mismo documento canónico
// produzcan bytes idénticos (Principio IV). El /ID del trailer solo lo
// emite fpdf en modo cifrado (Protect), que este renderer no usa, así que
// no hace falta neutralizarlo aparte. SetCatalogSort(true) es necesario
// además: fpdf recorre sus catálogos internos de recursos (p.ej. las
// fuentes usadas) desde un map de Go, cuyo orden de iteración NO es
// determinista entre ejecuciones; sin esto, dos renders del mismo
// documento pueden emitir los mismos objetos PDF en distinto orden
// (bytes distintos, mismo tamaño). SetCatalogSort fuerza ese recorrido en
// orden estable — es, según el propio comentario de fpdf, "typically only
// used for test purposes to facilitate PDF comparison", exactamente
// nuestro caso (Principio IV).
func RenderPDF(canonical []byte) ([]byte, error) {
	var r Report
	if err := json.Unmarshal(canonical, &r); err != nil {
		return nil, fmt.Errorf("el documento canónico no parsea: %w", err)
	}
	lang, err := i18n.Parse(r.Language)
	if err != nil {
		lang = i18n.ES
	}

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetCatalogSort(true)
	// Determinismo: fecha desde el informe (no del reloj), producer fijo.
	finished, _ := time.Parse(time.RFC3339, r.Run.FinishedAt)
	pdf.SetCreationDate(finished)
	pdf.SetModificationDate(finished)
	pdf.SetProducer("J0Witness", false)
	tr := pdf.UnicodeTranslatorFromDescriptor("") // UTF-8 → cp1252

	// Los hallazgos pueden ser largos: que fluyan a nuevas páginas en vez de
	// desbordar o truncarse en silencio.
	pdf.SetAutoPageBreak(true, 15)

	toolHashShort := r.Provenance.ToolHash
	if len(toolHashShort) > 12 {
		toolHashShort = toolHashShort[:12]
	}
	pdf.AliasNbPages("")
	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(120, 120, 120)
		pdf.CellFormat(0, 10, tr(fmt.Sprintf(i18n.T(lang, "pdf.footer", nil), pdf.PageNo(), toolHashShort)), "", 0, "C", false, 0, "")
		pdf.SetTextColor(0, 0, 0)
	})

	pdf.AddPage()
	// Banda de cabecera.
	pdf.SetFillColor(30, 41, 59) // slate-800
	pdf.Rect(0, 0, 210, 22, "F")
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 16)
	pdf.SetXY(12, 6)
	pdf.CellFormat(0, 8, tr(fmt.Sprintf(i18n.T(lang, "pdf.header", nil), r.SchemaVersion)), "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetX(12)
	pdf.CellFormat(0, 5, tr(fmt.Sprintf(i18n.T(lang, "pdf.target", nil), r.Target.Path, r.Run.FinishedAt)), "", 1, "L", false, 0, "")

	pdf.SetTextColor(0, 0, 0)
	pdf.SetY(28)

	writeInstallationSummary(pdf, tr, &r, lang)
	writeExecutiveSummary(pdf, tr, &r, lang)
	writeFindings(pdf, tr, &r, lang)
	writeCoverage(pdf, tr, &r, lang)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("generando PDF: %w", err)
	}
	return buf.Bytes(), nil
}

// ensureSpace añade una página nueva si no quedan al menos needed mm antes
// del margen inferior de auto-salto (15mm, fijado en SetAutoPageBreak). Se
// usa para que un bloque (p.ej. una entrada de hallazgo con su barra de
// color) no arranque al borde de la página y quede partido de forma fea;
// fpdf ya hace su propio salto automático dentro de cada MultiCell si el
// bloque es más largo de lo previsto aquí.
func ensureSpace(pdf *fpdf.Fpdf, needed float64) {
	_, pageH := pdf.GetPageSize()
	_, _, _, bottom := pdf.GetMargins()
	if pdf.GetY()+needed > pageH-bottom {
		pdf.AddPage()
	}
}

func sectionTitle(pdf *fpdf.Fpdf, tr func(string) string, title string) {
	ensureSpace(pdf, 12)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetTextColor(0, 0, 0)
	pdf.SetX(leftX)
	pdf.CellFormat(0, 8, tr(title), "", 1, "L", false, 0, "")
}

// writeInstallationSummary dibuja la sección "Resumen de la instalación":
// versión de Joomla, extensiones de terceros por tipo (orden fijo
// extTypeOrder, seguido de cualquier tipo fuera de esa lista en orden
// alfabético vía extraExtTypes — NUNCA range sobre el map
// Coverage.ExtensionsByType, para no romper el determinismo del PDF, ver
// comentario de cabecera en RenderPDF), archivos/bytes analizados, cobertura de análisis de código (L4) y de
// verificación de extensiones, y (si presente) la re-verificación del
// baseline contra el catálogo embebido (BaselineVerification, feature 013).
// Todo el texto pasa por tr() (cp1252): las
// etiquetas de tipo llevan tildes (módulos/plantillas/librerías/idiomas).
func writeInstallationSummary(pdf *fpdf.Fpdf, tr func(string) string, r *Report, lang i18n.Lang) {
	sectionTitle(pdf, tr, i18n.T(lang, "pdf.install_header", nil))
	pdf.SetFont("Helvetica", "", 10)

	inferred, declared := versionSummary(r)
	pdf.SetX(leftX)
	pdf.MultiCell(0, 5, tr(fmt.Sprintf(i18n.T(lang, "pdf.install_version", nil), inferred, r.VersionInf.Confidence, declared)), "", "L", false)

	total := thirdPartyTotal(r)
	pdf.SetX(leftX)
	pdf.MultiCell(0, 5, tr(fmt.Sprintf(i18n.T(lang, "pdf.install_thirdparty", nil), total)), "", "L", false)
	anyExt := false
	for _, t := range extTypeOrder {
		if n := r.Coverage.ExtensionsByType[t]; n > 0 {
			pdf.SetX(leftX + 4)
			pdf.MultiCell(0, 4.5, tr(fmt.Sprintf(i18n.T(lang, "pdf.install_ext_row", nil), i18n.ExtTypeLabel(lang, t), n)), "", "L", false)
			anyExt = true
		}
	}
	for _, t := range extraExtTypes(r.Coverage.ExtensionsByType) {
		if n := r.Coverage.ExtensionsByType[t]; n > 0 {
			pdf.SetX(leftX + 4)
			pdf.MultiCell(0, 4.5, tr(fmt.Sprintf(i18n.T(lang, "pdf.install_ext_row", nil), t, n)), "", "L", false)
			anyExt = true
		}
	}
	if !anyExt {
		pdf.SetX(leftX + 4)
		pdf.MultiCell(0, 4.5, tr(i18n.T(lang, "pdf.install_ext_none", nil)), "", "L", false)
	}

	pdf.SetX(leftX)
	pdf.MultiCell(0, 5, tr(fmt.Sprintf(i18n.T(lang, "pdf.install_analyzed", nil), r.Target.FilesRegular, r.Target.BytesTotal)), "", "L", false)

	if r.Coverage.CodeAnalysis != nil {
		pdf.SetX(leftX)
		pdf.MultiCell(0, 5, tr(fmt.Sprintf(i18n.T(lang, "pdf.install_code", nil), r.Coverage.CodeAnalysis.FilesScanned, r.Coverage.CodeAnalysis.FilesFlagged)), "", "L", false)
	}

	if r.Coverage.ExtensionVerification != nil {
		ev := r.Coverage.ExtensionVerification
		pdf.SetX(leftX)
		pdf.MultiCell(0, 5, tr(fmt.Sprintf(i18n.T(lang, "pdf.install_verif", nil), ev.ExtensionsVerified, ev.ExtensionsVerifiable)), "", "L", false)
	}

	if r.BaselineVerification != nil {
		pdf.SetX(leftX)
		pdf.MultiCell(0, 5, tr(fmt.Sprintf(i18n.T(lang, "pdf.baseline_verified", nil),
			r.BaselineVerification.CatalogVersion, r.BaselineVerification.Assurance)), "", "L", false)
	}
	pdf.Ln(2)
}

// writeExecutiveSummary dibuja los chips de severidad (Summary.BySeverity en
// orden fijo) y las líneas de estado de cobertura de alto nivel: integridad
// verificada, verificación de extensiones, modelo de amenaza, ejecutables
// sin verificar y estado del layout de administrator/.
func writeExecutiveSummary(pdf *fpdf.Fpdf, tr func(string) string, r *Report, lang i18n.Lang) {
	sectionTitle(pdf, tr, i18n.T(lang, "pdf.exec_header", nil))

	pdf.SetFont("Helvetica", "B", 10)
	x := leftX
	y := pdf.GetY() + 1
	for _, sev := range severityOrder {
		count := r.Summary.BySeverity[sev]
		c := severityColor[sev]
		label := fmt.Sprintf(i18n.T(lang, "pdf.severity_chip", nil), i18n.SeverityLabel(lang, sev), count)
		w := pdf.GetStringWidth(tr(label)) + 8
		pdf.SetFillColor(c[0], c[1], c[2])
		pdf.SetTextColor(255, 255, 255)
		pdf.SetXY(x, y)
		pdf.CellFormat(w, 7, tr(label), "", 0, "C", true, 0, "")
		x += w + 3
	}
	pdf.SetTextColor(0, 0, 0)
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetXY(leftX, y+10)

	// El texto "verificada"/"no verificada" viene del catálogo i18n
	// (ids pdf.integrity_yes/pdf.integrity_no) en lugar de ✓/✗: cp1252 no
	// tiene esos glifos y los convierte silenciosamente a "." (UnicodeTranslator
	// en fpdf), dejando un punto confuso delante del texto.
	integrity := i18n.T(lang, "pdf.integrity_no", nil)
	extLine := i18n.T(lang, "pdf.ext_verif_na", nil)
	if r.Coverage.Attribution != nil {
		if r.Coverage.Attribution.IntegrityVerified {
			integrity = i18n.T(lang, "pdf.integrity_yes", nil)
		}
	}
	if r.Coverage.ExtensionVerification != nil {
		ev := r.Coverage.ExtensionVerification
		extLine = fmt.Sprintf(i18n.T(lang, "pdf.ext_verif_line", nil), ev.ExtensionsVerified, ev.ExtensionsVerifiable, ev.FilesModified)
	}
	layoutLine := i18n.T(lang, "pdf.layout_standard", nil)
	if r.Coverage.Layout != nil {
		layoutLine = fmt.Sprintf(i18n.T(lang, "pdf.layout_nonstandard", nil), r.Coverage.Layout.RemapApplied, r.Coverage.Layout.AdminDir)
	}

	lines := []string{
		fmt.Sprintf(i18n.T(lang, "pdf.exec_integrity_line", nil), integrity, r.Provenance.ThreatModel),
		fmt.Sprintf(i18n.T(lang, "pdf.exec_unverified", nil), r.Summary.UnverifiedExecutables),
		extLine,
		layoutLine,
	}
	for _, line := range lines {
		pdf.SetX(leftX)
		pdf.MultiCell(0, 5, tr(line), "", "L", false)
	}
	pdf.Ln(2)
}

// writeFindings recorre r.Findings — ya ordenados por severidad desc — y los
// agrupa por severidad (orden fijo severityOrder) con un encabezado de grupo
// y, por cada hallazgo, una barra de color de severidad a la izquierda.
func writeFindings(pdf *fpdf.Fpdf, tr func(string) string, r *Report, lang i18n.Lang) {
	sectionTitle(pdf, tr, i18n.T(lang, "pdf.findings_header", nil))

	if len(r.Findings) == 0 {
		pdf.SetFont("Helvetica", "", 10)
		pdf.SetX(leftX)
		pdf.CellFormat(0, 6, tr(i18n.T(lang, "pdf.findings_none", nil)), "", 1, "L", false, 0, "")
		pdf.Ln(2)
		return
	}

	for _, sev := range severityOrder {
		var group []F
		for _, f := range r.Findings {
			if f.Severity == sev {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}
		ensureSpace(pdf, 10)
		c := severityColor[sev]
		pdf.SetFont("Helvetica", "B", 11)
		pdf.SetTextColor(c[0], c[1], c[2])
		pdf.SetX(leftX)
		pdf.CellFormat(0, 7, tr(fmt.Sprintf(i18n.T(lang, "pdf.severity_group_header", nil), i18n.SeverityLabel(lang, sev), len(group))), "", 1, "L", false, 0, "")
		pdf.SetTextColor(0, 0, 0)
		for _, f := range group {
			writeFinding(pdf, tr, f, c, lang)
		}
	}
}

// writeFinding dibuja una entrada de hallazgo: barra de color a la
// izquierda, rule_id + subject en negrita, y observed/rationale/
// base_severity (si degradada)/alternative_hypothesis en gris.
func writeFinding(pdf *fpdf.Fpdf, tr func(string) string, f F, color [3]int, lang i18n.Lang) {
	ensureSpace(pdf, 12)
	y0 := pdf.GetY()
	pdf.SetFillColor(color[0], color[1], color[2])
	pdf.Rect(leftX-2, y0, 1.6, 5.5, "F")

	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(0, 0, 0)
	pdf.SetX(leftX + 2)
	pdf.MultiCell(0, 5, tr(fmt.Sprintf(i18n.T(lang, "pdf.finding_title", nil), f.RuleID, f.Subject)), "", "L", false)

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(90, 90, 90)
	var body []string
	if f.Observed != "" {
		body = append(body, fmt.Sprintf(i18n.T(lang, "pdf.finding_observed", nil), f.Observed))
	}
	if f.Rationale != "" {
		body = append(body, fmt.Sprintf(i18n.T(lang, "pdf.finding_rationale", nil), f.Rationale))
	}
	if f.BaseSeverity != "" && f.BaseSeverity != f.Severity {
		body = append(body, fmt.Sprintf(i18n.T(lang, "pdf.finding_base_severity", nil), f.BaseSeverity))
	}
	if f.Alternative != "" {
		body = append(body, fmt.Sprintf(i18n.T(lang, "pdf.finding_alternative", nil), f.Alternative))
	}
	for _, line := range body {
		pdf.SetX(leftX + 2)
		pdf.MultiCell(0, 4.5, tr(line), "", "L", false)
	}
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(2)
}

// writeCoverage dibuja las salvedades de cobertura: rutas no analizadas
// (top N), omisiones de fuzzy hash (top N), ejecutables sin verificar (top N,
// con flagged_by_code si el detector de código lo marcó), el estado
// detallado del layout y, si presentes, las raíces ajenas a la distribución
// (Coverage.ForeignRoots, top N, feature 012), la correlación con la base de
// datos (Coverage.Database, feature 011, capa L7) y el análisis temporal
// (Coverage.Timeline, feature 009, capa L6) — todas las listas ya vienen
// ordenadas por el productor (PrivilegedRoster incluido), se iteran tal
// cual (nunca re-ordenar ni iterar un map, por determinismo).
func writeCoverage(pdf *fpdf.Fpdf, tr func(string) string, r *Report, lang i18n.Lang) {
	sectionTitle(pdf, tr, i18n.T(lang, "pdf.coverage_header", nil))
	pdf.SetFont("Helvetica", "", 10)

	pdf.SetX(leftX)
	if len(r.Coverage.NotAnalyzed) == 0 {
		pdf.MultiCell(0, 5, tr(i18n.T(lang, "pdf.cov_notanalyzed_none", nil)), "", "L", false)
	} else {
		pdf.MultiCell(0, 5, tr(fmt.Sprintf(i18n.T(lang, "pdf.cov_notanalyzed_header", nil), len(r.Coverage.NotAnalyzed))), "", "L", false)
		for i, na := range r.Coverage.NotAnalyzed {
			if i >= topN {
				pdf.SetX(leftX)
				pdf.MultiCell(0, 4.5, tr(fmt.Sprintf(i18n.T(lang, "pdf.cov_more", nil), len(r.Coverage.NotAnalyzed)-topN)), "", "L", false)
				break
			}
			line := fmt.Sprintf(i18n.T(lang, "pdf.cov_notanalyzed_row", nil), na.Path, na.Reason)
			if na.Detail != "" {
				line += ": " + na.Detail
			}
			pdf.SetX(leftX)
			pdf.MultiCell(0, 4.5, tr(line), "", "L", false)
		}
	}
	pdf.Ln(1)

	pdf.SetX(leftX)
	if len(r.Coverage.Omissions) == 0 {
		pdf.MultiCell(0, 5, tr(i18n.T(lang, "pdf.cov_omissions_none", nil)), "", "L", false)
	} else {
		pdf.MultiCell(0, 5, tr(fmt.Sprintf(i18n.T(lang, "pdf.cov_omissions_header", nil), len(r.Coverage.Omissions))), "", "L", false)
		for i, om := range r.Coverage.Omissions {
			if i >= topN {
				pdf.SetX(leftX)
				pdf.MultiCell(0, 4.5, tr(fmt.Sprintf(i18n.T(lang, "pdf.cov_more", nil), len(r.Coverage.Omissions)-topN)), "", "L", false)
				break
			}
			line := fmt.Sprintf(i18n.T(lang, "pdf.cov_omissions_row", nil), om.Path, om.What, om.Reason)
			pdf.SetX(leftX)
			pdf.MultiCell(0, 4.5, tr(line), "", "L", false)
		}
	}
	pdf.Ln(1)

	pdf.SetX(leftX)
	var ue *UnverifiedExecs
	if r.Coverage.Attribution != nil {
		ue = r.Coverage.Attribution.UnverifiedExecutables
	}
	if ue == nil || ue.Count == 0 {
		pdf.MultiCell(0, 5, tr(i18n.T(lang, "pdf.cov_unverified_none", nil)), "", "L", false)
	} else {
		pdf.MultiCell(0, 5, tr(fmt.Sprintf(i18n.T(lang, "pdf.cov_unverified_header", nil), ue.Count)), "", "L", false)
		for i, uf := range ue.Files {
			if i >= topN {
				pdf.SetX(leftX)
				pdf.MultiCell(0, 4.5, tr(fmt.Sprintf(i18n.T(lang, "pdf.cov_more", nil), ue.Count-topN)), "", "L", false)
				break
			}
			flag := ""
			if uf.FlaggedByCode {
				flag = i18n.T(lang, "pdf.cov_flagged_by_code", nil)
			}
			pdf.SetX(leftX)
			pdf.MultiCell(0, 4.5, tr(fmt.Sprintf(i18n.T(lang, "pdf.cov_unverified_row", nil), uf.Path, uf.Extension, flag)), "", "L", false)
		}
	}
	pdf.Ln(1)

	pdf.SetX(leftX)
	if r.Coverage.Layout == nil {
		pdf.MultiCell(0, 5, tr(i18n.T(lang, "pdf.cov_layout_standard", nil)), "", "L", false)
	} else {
		l := r.Coverage.Layout
		line := fmt.Sprintf(i18n.T(lang, "pdf.cov_layout_nonstandard_prefix", nil), l.AdminDirFound, l.RemapApplied)
		if l.RemapApplied {
			line += fmt.Sprintf(i18n.T(lang, "pdf.cov_layout_remap_details", nil), l.AdminDir, l.ApiDir, l.RemapSource)
		}
		line += ")."
		pdf.MultiCell(0, 5, tr(line), "", "L", false)
	}

	if len(r.Coverage.ForeignRoots) > 0 {
		pdf.Ln(1)
		pdf.SetX(leftX)
		pdf.MultiCell(0, 5, tr(fmt.Sprintf(i18n.T(lang, "pdf.foreign_header", nil), len(r.Coverage.ForeignRoots))), "", "L", false)
		for i, fr := range r.Coverage.ForeignRoots {
			if i >= topN {
				pdf.SetX(leftX)
				pdf.MultiCell(0, 4.5, tr(fmt.Sprintf(i18n.T(lang, "pdf.cov_more", nil), len(r.Coverage.ForeignRoots)-topN)), "", "L", false)
				break
			}
			label := i18n.T(lang, "pdf.foreign_foreign", nil)
			if fr.DistributionDir {
				label = i18n.T(lang, "pdf.foreign_joomla", nil)
			}
			pdf.SetX(leftX)
			pdf.MultiCell(0, 4.5, tr(fmt.Sprintf(i18n.T(lang, "pdf.foreign_line", nil), fr.Root, fr.Files, fr.Executables, label)), "", "L", false)
		}
	}

	if db := r.Coverage.Database; db != nil {
		pdf.Ln(1)
		pdf.SetX(leftX)
		pdf.MultiCell(0, 5, tr(fmt.Sprintf(i18n.T(lang, "pdf.database_header", nil), db.Prefix)), "", "L", false)
		pdf.SetX(leftX)
		pdf.MultiCell(0, 4.5, tr(fmt.Sprintf(i18n.T(lang, "pdf.database_counts", nil), db.UsersParsed, db.ExtensionsParsed, db.ModulesParsed)), "", "L", false)
		if len(db.PrivilegedRoster) > 0 {
			roster := db.PrivilegedRoster
			rosterText := strings.Join(roster, ", ")
			if len(roster) > topN {
				// Principio VII: la lista de cuentas privilegiadas es la línea
				// más sensible de este bloque — truncar en silencio ocultaría
				// cuántas cuentas con privilegios de Super User existen. Se
				// añade el mismo sufijo "y N más" que ya usan
				// NotAnalyzed/Omissions/UnverifiedExecs/ForeignRoots
				// (pdf.cov_more), en vez de una clave nueva.
				rosterText = strings.Join(roster[:topN], ", ") + " " + fmt.Sprintf(i18n.T(lang, "pdf.cov_more", nil), len(roster)-topN)
			}
			pdf.SetX(leftX)
			pdf.MultiCell(0, 4.5, tr(fmt.Sprintf(i18n.T(lang, "pdf.database_roster", nil), rosterText)), "", "L", false)
		}
		if db.Correspondence == "mismatch" {
			pdf.SetX(leftX)
			pdf.MultiCell(0, 4.5, tr(fmt.Sprintf(i18n.T(lang, "pdf.database_mismatch", nil), db.AbsentFraction)), "", "L", false)
		}
	}

	if tl := r.Coverage.Timeline; tl != nil {
		pdf.Ln(1)
		pdf.SetX(leftX)
		pdf.MultiCell(0, 5, tr(i18n.T(lang, "pdf.timeline_header", nil)), "", "L", false)
		pdf.SetX(leftX)
		pdf.MultiCell(0, 4.5, tr(fmt.Sprintf(i18n.T(lang, "pdf.timeline_line", nil), tl.CohortEarliest, tl.CohortLatest, tl.TotalFiles, tl.Outliers, tl.Manipulations)), "", "L", false)
	}
}
