// chrome.go añade al catálogo de i18n las cadenas de "chrome" de los
// renderizadores del informe (internal/report/text.go y pdf.go): títulos de
// sección, etiquetas y el resumen de instalación. Estas NO son prosa de
// hallazgos (eso vive en i18n.go, derivado en internal/finding) — son las
// cadenas fijas que envuelven esa prosa en la proyección de texto/PDF.
//
// Los ids llevan prefijo "text."/"pdf." (ver TestChromeVerbParity en
// i18n_test.go, que exige que "es" y "en" de cada entrada aquí tengan la
// misma secuencia de verbos fmt). Los "es" son VERBATIM los literales que
// existían en text.go/pdf.go antes de esta migración (byte-identidad,
// Principio IV): no se reformatea ni un espacio.
package i18n

// extTypeLabels traduce cada tipo de extensión a su etiqueta de
// visualización, en el "Resumen de la instalación" (texto y PDF). ES es
// verbatim el mapa que vivía en internal/report/text.go antes de esta
// migración.
var extTypeLabels = map[Lang]map[string]string{
	ES: {
		"component": "componentes",
		"module":    "módulos",
		"plugin":    "plugins",
		"template":  "plantillas",
		"library":   "librerías",
		"language":  "idiomas",
		"file":      "archivos",
		"package":   "paquetes",
	},
	EN: {
		"component": "components",
		"module":    "modules",
		"plugin":    "plugins",
		"template":  "templates",
		"library":   "libraries",
		"language":  "languages",
		"file":      "files",
		"package":   "packages",
	},
}

// ExtTypeLabel devuelve la etiqueta de tipo de extensión en lang; si code no
// se reconoce (tipo desconocido/futuro) o lang no tiene tabla, devuelve el
// propio code crudo (fallback determinista).
func ExtTypeLabel(lang Lang, code string) string {
	if m, ok := extTypeLabels[lang]; ok {
		if s, ok := m[code]; ok {
			return s
		}
	}
	return code
}

// severityLabels traduce cada código de severidad (crudo, ver F.Severity) a
// su etiqueta de VISUALIZACIÓN en el PDF (chips de resumen ejecutivo y
// encabezados de grupo de hallazgos). ES es verbatim el mapa severityLabel
// que vivía en internal/report/pdf.go antes de esta migración. El código
// crudo (f.Severity: "critical"/"high"/"medium"/"low"/"info") NUNCA se
// traduce — solo esta etiqueta derivada para mostrar.
var severityLabels = map[Lang]map[string]string{
	ES: {
		"critical": "CRÍTICA",
		"high":     "ALTA",
		"medium":   "MEDIA",
		"low":      "BAJA",
		"info":     "INFO",
	},
	EN: {
		"critical": "CRITICAL",
		"high":     "HIGH",
		"medium":   "MEDIUM",
		"low":      "LOW",
		"info":     "INFO",
	},
}

// SeverityLabel devuelve la etiqueta de severidad a mostrar en lang; si code
// no se reconoce, devuelve el propio code crudo (fallback determinista).
func SeverityLabel(lang Lang, code string) string {
	if m, ok := severityLabels[lang]; ok {
		if s, ok := m[code]; ok {
			return s
		}
	}
	return code
}

func init() {
	for id, e := range chromeMessages {
		messages[id] = e
	}
}

// chromeMessages son las entradas de chrome descritas en la cabecera del
// archivo. Se fusionan en el catálogo compartido "messages" (i18n.go) desde
// init(), así T(lang, id, params) las resuelve igual que la prosa de
// hallazgos.
var chromeMessages = map[string]entry{
	// --- text.go ---
	"text.header":               {es: "J0Witness — informe de integridad (schema %s)\n", en: "J0Witness — integrity report (schema %s)\n"},
	"text.target":               {es: "objetivo: %s (%d entradas, %d archivos, %d bytes)\n", en: "target: %s (%d entries, %d files, %d bytes)\n"},
	"text.baseline":             {es: "baseline: %s %s (paquete %s, origen %s)\n", en: "baseline: %s %s (package %s, source %s)\n"},
	"text.baseline_verified":    {es: "baseline verificado contra el catálogo embebido (%s, assurance: %s)\n", en: "baseline verified against the embedded catalog (%s, assurance: %s)\n"},
	"text.threatmodel":          {es: "modelo de amenaza: %s\n", en: "threat model: %s\n"},
	"text.version":              {es: "versión: inferida=%s (confianza %s) declarada=%s testigos=%d\n", en: "version: inferred=%s (confidence %s) declared=%s witnesses=%d\n"},
	"text.mixed":                {es: "ATENCIÓN: instalación con archivos de más de una versión\n", en: "WARNING: installation with files from more than one version\n"},
	"text.coverage":             {es: "\ncobertura: %d entradas analizadas, %d bytes hasheados; %d no analizadas; %d omisiones\n", en: "\ncoverage: %d entries analyzed, %d bytes hashed; %d not analyzed; %d omissions\n"},
	"text.notanalyzed":          {es: "  no mirado: %s (%s)\n", en: "  not looked at: %s (%s)\n"},
	"text.foreign_roots":        {es: "\nraíces ajenas a la distribución (%d):\n", en: "\nroots foreign to the distribution (%d):\n"},
	"text.foreign_root_line":    {es: "  %s/ — %d archivos, %d ejecutables (%s)\n", en: "  %s/ — %d files, %d executables (%s)\n"},
	"text.foreign_root_foreign": {es: "ajena a la distribución", en: "foreign to the distribution"},
	"text.foreign_root_joomla":  {es: "dir de Joomla, contenido de usuario", en: "Joomla dir, user content"},
	"text.findings_header":      {es: "\nhallazgos (%d):\n", en: "\nfindings (%d):\n"},
	"text.finding_none":         {es: "  ninguno\n", en: "  none\n"},
	"text.finding_block":        {es: "\n[%s] %s %s — %s\n", en: "\n[%s] %s %s — %s\n"},
	"text.f_observed":           {es: "  observado : %s\n", en: "  observed  : %s\n"},
	"text.f_compared":           {es: "  comparado : %s\n", en: "  compared  : %s\n"},
	"text.f_rationale":          {es: "  relevancia: %s\n", en: "  rationale : %s\n"},
	"text.f_confidence":         {es: "  confianza : %s\n", en: "  confidence: %s\n"},
	"text.f_alternative":        {es: "  hipótesis alternativa: %s\n", en: "  alternative hypothesis: %s\n"},
	"text.ext_header_att":       {es: "\nextensiones de terceros: %d descubiertas, %d archivos atribuidos\n", en: "\nthird-party extensions: %d discovered, %d files attributed\n"},
	"text.ext_unverified_note":  {es: "  (integridad no verificada contra el autor — feature posterior)\n", en: "  (integrity not verified against the author — later feature)\n"},
	"text.ext_header_plain":     {es: "\nextensiones de terceros: %d\n", en: "\nthird-party extensions: %d\n"},
	"text.ext_row":              {es: "  %-10s %-14s %-8s %-16s %d archivos\n", en: "  %-10s %-14s %-8s %-16s %d files\n"},
	"text.suppr_header":         {es: "\nsupresiones aplicadas (%d):\n", en: "\nsuppressions applied (%d):\n"},
	"text.suppr_row":            {es: "  %s %s → %d hallazgos (motivo: %s)\n", en: "  %s %s → %d findings (reason: %s)\n"},
	"text.summary":              {es: "\nresumen: critical=%d high=%d medium=%d low=%d info=%d → exit %d\n", en: "\nsummary: critical=%d high=%d medium=%d low=%d info=%d → exit %d\n"},
	"text.unverified_exec":      {es: "ejecutables atribuidos sin verificar: %d (ver coverage.attribution.unverified_executables)\n", en: "unverified attributed executables: %d (see coverage.attribution.unverified_executables)\n"},
	"text.install_header":       {es: "\nResumen de la instalación:\n", en: "\nInstallation summary:\n"},
	"text.install_version":      {es: "  versión de Joomla: inferida=%s (confianza %s) declarada=%s\n", en: "  Joomla version: inferred=%s (confidence %s) declared=%s\n"},
	"text.install_thirdparty":   {es: "  extensiones de terceros: %d\n", en: "  third-party extensions: %d\n"},
	"text.install_ext_row":      {es: "    %s %d\n", en: "    %s %d\n"},
	"text.install_ext_none":     {es: "    ninguna\n", en: "    none\n"},
	"text.install_analyzed":     {es: "  analizado: %d archivos, %d bytes\n", en: "  analyzed: %d files, %d bytes\n"},
	"text.install_code":         {es: "  código PHP: %d escaneados, %d marcados\n", en: "  PHP code: %d scanned, %d flagged\n"},
	"text.install_verif":        {es: "  verificación de extensiones: %d/%d verificables\n", en: "  extension verification: %d/%d verifiable\n"},

	// --- pdf.go ---
	"pdf.footer": {es: "Página %d/{nb}   ·   tool_hash %s", en: "Page %d/{nb}   ·   tool_hash %s"},
	"pdf.header": {es: "J0Witness — Informe de integridad (schema %s)", en: "J0Witness — Integrity report (schema %s)"},
	"pdf.target": {es: "objetivo: %s   ·   %s", en: "target: %s   ·   %s"},

	"pdf.install_header":  {es: "Resumen de la instalación", en: "Installation summary"},
	"pdf.exec_header":     {es: "Resumen ejecutivo", en: "Executive summary"},
	"pdf.findings_header": {es: "Hallazgos", en: "Findings"},
	"pdf.coverage_header": {es: "Cobertura y salvedades", en: "Coverage and caveats"},

	"pdf.install_version":    {es: "Versión de Joomla: inferida=%s (confianza %s) declarada=%s", en: "Joomla version: inferred=%s (confidence %s) declared=%s"},
	"pdf.install_thirdparty": {es: "Extensiones de terceros: %d", en: "Third-party extensions: %d"},
	"pdf.install_ext_row":    {es: "- %s: %d", en: "- %s: %d"},
	"pdf.install_ext_none":   {es: "- ninguna", en: "- none"},
	"pdf.install_analyzed":   {es: "Analizado: %d archivos, %d bytes", en: "Analyzed: %d files, %d bytes"},
	"pdf.install_code":       {es: "Código PHP: %d escaneados, %d marcados", en: "PHP code: %d scanned, %d flagged"},
	"pdf.install_verif":      {es: "Verificación de extensiones: %d/%d verificables", en: "Extension verification: %d/%d verifiable"},

	"pdf.severity_chip":       {es: "%s: %d", en: "%s: %d"},
	"pdf.integrity_yes":       {es: "verificada", en: "verified"},
	"pdf.integrity_no":        {es: "no verificada", en: "not verified"},
	"pdf.ext_verif_na":        {es: "Verificación de extensiones: n/d (sin extensiones de terceros)", en: "Extension verification: n/a (no third-party extensions)"},
	"pdf.ext_verif_line":      {es: "Verificación de extensiones: %d/%d verificables (%d modificadas)", en: "Extension verification: %d/%d verifiable (%d modified)"},
	"pdf.layout_standard":     {es: "Layout administrator/: estándar", en: "Layout administrator/: standard"},
	"pdf.layout_nonstandard":  {es: "Layout administrator/: no estándar (remap_applied=%t, admin_dir=%s)", en: "Layout administrator/: non-standard (remap_applied=%t, admin_dir=%s)"},
	"pdf.exec_integrity_line": {es: "Integridad de extensiones: %s   ·   Modelo de amenaza: %s", en: "Extension integrity: %s   ·   Threat model: %s"},
	"pdf.exec_unverified":     {es: "Ejecutables sin verificar: %d", en: "Unverified executables: %d"},

	"pdf.findings_none":         {es: "Ninguno.", en: "None."},
	"pdf.severity_group_header": {es: "%s (%d)", en: "%s (%d)"},
	"pdf.finding_title":         {es: "%s — %s", en: "%s — %s"},
	"pdf.finding_observed":      {es: "Observado: %s", en: "Observed: %s"},
	"pdf.finding_rationale":     {es: "Razonamiento: %s", en: "Rationale: %s"},
	"pdf.finding_base_severity": {es: "Severidad base (degradada por supresión/atenuante): %s", en: "Base severity (downgraded by suppression/mitigant): %s"},
	"pdf.finding_alternative":   {es: "Hipótesis alternativa: %s", en: "Alternative hypothesis: %s"},

	"pdf.cov_notanalyzed_none":          {es: "No analizado: ninguno.", en: "Not analyzed: none."},
	"pdf.cov_notanalyzed_header":        {es: "No analizado (%d):", en: "Not analyzed (%d):"},
	"pdf.cov_more":                      {es: "… y %d más", en: "… and %d more"},
	"pdf.cov_notanalyzed_row":           {es: "- %s (%s)", en: "- %s (%s)"},
	"pdf.cov_omissions_none":            {es: "Omisiones (fuzzy hash): ninguna.", en: "Omissions (fuzzy hash): none."},
	"pdf.cov_omissions_header":          {es: "Omisiones (fuzzy hash) (%d):", en: "Omissions (fuzzy hash) (%d):"},
	"pdf.cov_omissions_row":             {es: "- %s (%s): %s", en: "- %s (%s): %s"},
	"pdf.cov_unverified_none":           {es: "Ejecutables sin verificar: 0.", en: "Unverified executables: 0."},
	"pdf.cov_unverified_header":         {es: "Ejecutables sin verificar (%d):", en: "Unverified executables (%d):"},
	"pdf.cov_flagged_by_code":           {es: " [marcado por análisis de código]", en: " [flagged by code analysis]"},
	"pdf.cov_unverified_row":            {es: "- %s (%s)%s", en: "- %s (%s)%s"},
	"pdf.cov_layout_standard":           {es: "Layout: administrator/ estándar, sin remapeo.", en: "Layout: administrator/ standard, no remap."},
	"pdf.cov_layout_nonstandard_prefix": {es: "Layout: no estándar (admin_dir_found=%s, remap_applied=%t", en: "Layout: non-standard (admin_dir_found=%s, remap_applied=%t"},
	"pdf.cov_layout_remap_details":      {es: ", admin_dir=%s, api_dir=%s, remap_source=%s", en: ", admin_dir=%s, api_dir=%s, remap_source=%s"},

	// baseline_verification + coverage.foreign_roots en el PDF (1.13.0/1.12.0,
	// feature 002 plan-pdf-bloques-cobertura Task 1). El "y N más" reutiliza
	// pdf.cov_more (arriba) en lugar de duplicar una clave equivalente.
	"pdf.baseline_verified": {es: "Baseline: verificado contra el catálogo embebido (%s, assurance: %s)", en: "Baseline: verified against the embedded catalog (%s, assurance: %s)"},
	"pdf.foreign_header":    {es: "Raíces ajenas a la distribución (%d):", en: "Roots foreign to the distribution (%d):"},
	"pdf.foreign_line":      {es: "- %s/ — %d archivos, %d ejecutables (%s)", en: "- %s/ — %d files, %d executables (%s)"},
	"pdf.foreign_foreign":   {es: "ajena", en: "foreign"},
	"pdf.foreign_joomla":    {es: "dir de Joomla, contenido de usuario", en: "Joomla dir, user content"},

	// coverage.database + coverage.timeline en el PDF (Task 2,
	// plan-pdf-bloques-cobertura): correlación con el volcado (--db, capa L7)
	// y resumen de la cohorte de ctime (capa L6). PrivilegedRoster ya viene
	// ordenado por el productor (strings.Join, sin re-ordenar ni map).
	"pdf.database_header":   {es: "Correlación con la base de datos (prefijo %s):", en: "Database correlation (prefix %s):"},
	"pdf.database_counts":   {es: "- %d usuarios, %d extensiones, %d módulos", en: "- %d users, %d extensions, %d modules"},
	"pdf.database_roster":   {es: "- cuentas privilegiadas: %s", en: "- privileged accounts: %s"},
	"pdf.database_mismatch": {es: "- salvedad: el volcado no corresponde al disco (fracción ausente %.2f)", en: "- caveat: the dump does not correspond to the disk (absent fraction %.2f)"},
	"pdf.timeline_header":   {es: "Análisis temporal:", en: "Timeline analysis:"},
	"pdf.timeline_line":     {es: "- cohorte %s … %s; %d archivos, %d outliers de ctime, %d manipulaciones de mtime", en: "- cohort %s … %s; %d files, %d ctime outliers, %d mtime manipulations"},
}
