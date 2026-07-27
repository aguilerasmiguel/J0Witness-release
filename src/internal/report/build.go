package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"time"

	"j0witness/internal/finding"
	"j0witness/internal/i18n"
	"j0witness/internal/observe"
	"j0witness/internal/provenance"
)

// SchemaVersion del contrato. 1.13.0 añade baseline_verification (feature
// 013): declara, a nivel top-level, el resultado de re-verificar el baseline
// almacenado/cacheado contra el catálogo embebido (Principio VIII) en el
// momento del scan que originó el run — verified_against, catalog_version,
// package_sha256, manifest_source, assurance. Proyectado desde la
// observación observe.BaselineVerified (Task 2), NUNCA re-verificado al
// re-renderizar (Principio II): un `report` reproduce el mismo bloque desde
// la observación persistida. Ausente (omitempty) cuando la versión quedó
// fuera del catálogo (resolveBaseline no verifica en ese caso) o en informes
// previos a esta feature — byte-idénticos.
//
// 1.12.0 añade coverage.foreign_roots (feature
// 012): contenido de disco ajeno tanto a la distribución de Joomla como a las
// extensiones registradas, agregado por raíz de nivel superior — contexto
// informativo (coverage), nunca un hallazgo. Omitido (omitempty) si no hay
// contenido ajeno.
//
// 1.11.0 añade, de forma aditiva sobre 1.10.0,
// coverage.database (feature 011, capa L7 internal/dbscan): resumen de la
// correlación con un volcado mysqldump aportado vía --db (prefix,
// users_parsed, extensions_parsed, modules_parsed, privileged_roster,
// ambiguous, unsupported). Presente solo cuando se usó --db en el scan que
// originó el run; ausente (omitempty) en un scan sin --db o en un report
// re-renderizado (los hallazgos J0W-DB-* sí se re-derivan, desde las
// observaciones persistidas, pero el resumen de cobertura no se reconstruye).
//
// 1.10.0 añade, de forma aditiva sobre 1.9.0,
// coverage.timeline (feature 009): resumen del análisis temporal de la capa
// L6 (internal/timeline) — cohorte de ctime (cohort_earliest/cohort_latest,
// RFC3339), total_files, ctime_outliers y mtime_manipulations. Presente solo
// si total_files > 0 (omitempty), sin ensuciar informes previos.
//
// 1.9.0 añade, de forma aditiva sobre 1.8.0,
// coverage.config_files_scanned (feature 002, fase confscan): número de
// archivos de config del servidor (.htaccess/.user.ini/web.config)
// analizados por la capa L5 (internal/confscan); omitido (omitempty) si es
// cero. No afecta a informes previos.
//
// 1.8.0 añade, de forma aditiva sobre 1.7.0, el
// campo de nivel superior "language" (es|en): declara el idioma en que está
// resuelta la prosa del informe (hallazgos y, al renderizar, el chrome).
// Parámetro de invocación (--language en scan/report, Principio II: ambos
// subcomandos re-derivan); por defecto "es". Los informes 1.7.0 y anteriores
// no lo declaran y se interpretan como "es" (retrocompat).
//
// 1.7.0 añade, de forma aditiva sobre 1.6.0,
// coverage.extensions_by_type: recuento de extensiones de TERCEROS por tipo
// de manifiesto (component/module/plugin/template/library/language/file/
// package); core-bundled excluido (como extensions[]/third_party_extensions).
// Solo tipos presentes; ausente (omitempty) si no hay extensiones. El total
// ya lo da coverage.attribution.third_party_extensions. 1.6.0 (fase 2d) añadió,
// de forma aditiva sobre 1.5.0, cuatro campos a coverage.layout
// (remap_applied, admin_dir, api_dir, remap_source) que declaran el remapeo
// admin/api resuelto (operador o auto-detect); y realiza (canónica→real) las
// rutas de cara al operador — F.subject, coverage.not_analyzed[].path,
// coverage.omissions[].path,
// coverage.attribution.unverified_executables[].files[].path,
// extensions[].manifest_path y extensions[].roots — cuando hubo remapeo, para
// que el informe muestre la ruta real de disco en vez de la canónica interna
// (los valores dentro de "evidence" siguen siendo canónicos). 1.5.0 (fase 2c)
// añadió, de forma aditiva sobre 1.4.0, coverage.extension_verification ahora
// cubre los 5 tipos verificables (component/module/plugin/template/library,
// no solo componentes) e incorpora el nuevo denominador
// extensions_verifiable; además añade coverage.layout (presente solo cuando
// el árbol administrator/ no es estándar). 1.4.0 (fase 2a) añadió, de forma
// aditiva sobre 1.3.0, extensions[].verification_source y
// coverage.extension_verification; extensions[].verified y
// coverage.attribution.integrity_verified dejan de ser siempre false — pasan a
// true cuando hay al menos una extensión verificada contra su paquete
// oficial. 1.3.0 (feature 003, capa L4) añadió, de forma aditiva sobre 1.2.0,
// coverage.code_analysis y coverage.attribution.unverified_executables[].flagged_by_code.
// 1.2.0 (D4/red) añadió coverage.attribution.unverified_executables y
// summary.unverified_executables sobre 1.1.0.
const SchemaVersion = "1.13.0"

// Los structs siguen el orden de claves del schema: encoding/json emite los
// campos en orden de declaración → serialización canónica (Principio IV).

type Report struct {
	SchemaVersion string `json:"schema_version"`
	// Language declara el idioma en que está resuelta la prosa del informe
	// (1.8.0: es|en). Build solo lo DECLARA; la prosa de los findings ya viene
	// resuelta desde finding.Derive.
	Language   string `json:"language"`
	Run        Run    `json:"run"`
	Provenance Prov   `json:"provenance"`
	// BaselineVerification (1.13.0, feature 013): resultado de re-verificar el
	// baseline contra el catálogo embebido, proyectado desde la observación
	// observe.BaselineVerified. nil (omitempty) cuando esa observación no
	// declaró assurance (versión fuera de catálogo) — ver buildBaselineVerification.
	BaselineVerification *BaselineVerification `json:"baseline_verification,omitempty"`
	Target               Target                `json:"target"`
	VersionInf           Version               `json:"version_inference"`
	Coverage             Coverage              `json:"coverage"`
	Findings             []F                   `json:"findings"`
	Suppressions         []S                   `json:"suppressions_applied"`
	Extensions           []Ext                 `json:"extensions"` // 1.1.0 (feature 002)
	Summary              Summary               `json:"summary"`
}

// Ext es una entrada del inventario de extensiones de terceros (FR-140).
type Ext struct {
	Type            string   `json:"type"`
	Name            string   `json:"name"`
	ManifestPath    string   `json:"manifest_path"`
	DeclaredVersion *string  `json:"declared_version"`
	DeclaredAuthor  *string  `json:"declared_author"`
	Roots           []string `json:"roots"`
	FilesDeclared   int      `json:"files_declared"`
	FilesUndeclared int      `json:"files_undeclared"`
	// Verified es true cuando la extensión se comparó contra su paquete
	// oficial (fase 2a: hubo baseline cacheado y al menos un archivo
	// ext_file_verified/ext_file_modified). false si nunca se pudo comparar.
	Verified bool `json:"verified"`
	// VerificationSource declara el origen (self-asserted, Principio VII) del
	// baseline usado para verificar: "package" o "catalog-fetch". nil si
	// Verified es false.
	VerificationSource *string `json:"verification_source,omitempty"`
}

// Run es el ÚNICO bloque no determinista (Principio IV).
type Run struct {
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
	HostnameHash string `json:"hostname_hash"`
	DurationMS   int64  `json:"duration_ms"`
}

type Prov struct {
	ToolVersion    string   `json:"tool_version"`
	ToolHash       string   `json:"tool_hash"`
	Invocation     []string `json:"invocation"`
	ThreatModel    string   `json:"threat_model"`
	Baseline       BaseRef  `json:"baseline"`
	CatalogVersion string   `json:"catalog_version"`
	RulesetVersion string   `json:"ruleset_version"`
	NetworkUsed    bool     `json:"network_used"`
}

type BaseRef struct {
	CMS           string `json:"cms"`
	Version       string `json:"version"`
	PackageSHA256 string `json:"package_sha256"`
	ManifestSHA   string `json:"manifest_sha256"`
	Source        string `json:"source"`
}

// BaselineVerification declara el resultado de re-verificar el baseline
// almacenado/cacheado contra el catálogo embebido (Principio VIII, feature
// 013): identidad del paquete, re-derivación/auto-consistencia del
// manifiesto y el nivel de confianza resultante. Los mismos 5 campos que
// baseline.Verification (Task 1) volcó a la observación BaselineVerified
// (Task 2): sin renombres.
type BaselineVerification struct {
	VerifiedAgainst string `json:"verified_against"` // "embedded-catalog"
	CatalogVersion  string `json:"catalog_version"`
	PackageSHA256   string `json:"package_sha256"`
	ManifestSource  string `json:"manifest_source"`
	Assurance       string `json:"assurance"`
}

type Target struct {
	Path         string `json:"path"`
	EntriesTotal int    `json:"entries_total"`
	FilesRegular int    `json:"files_regular"`
	BytesTotal   int64  `json:"bytes_total"`
}

type Version struct {
	Inferred          *string     `json:"inferred"`
	Declared          *string     `json:"declared"`
	Confidence        string      `json:"confidence"`
	Candidates        []Candidate `json:"candidates"`
	WitnessUsed       int         `json:"witness_files_used"`
	WitnessUnreadable int         `json:"witness_files_unreadable"`
	MixedVersions     bool        `json:"mixed_versions"`
}

type Candidate struct {
	Version string `json:"version"`
	Votes   int    `json:"votes"`
}

type Coverage struct {
	Analyzed              Analyzed          `json:"analyzed"`
	NotAnalyzed           []NotAnalyzed     `json:"not_analyzed"`
	Omissions             []Omission        `json:"omissions"`
	Attribution           *Attribution      `json:"attribution,omitempty"`            // 1.1.0 (feature 002)
	CodeAnalysis          *CodeAnalysis     `json:"code_analysis,omitempty"`          // 1.3.0 (feature 003)
	ExtensionVerification *ExtVerification  `json:"extension_verification,omitempty"` // 1.4.0 (fase 2a)
	ExtensionsByType      map[string]int    `json:"extensions_by_type,omitempty"`     // 1.7.0 (terceros, por tipo)
	Layout                *LayoutCoverage   `json:"layout,omitempty"`                 // 1.5.0/1.6.0 (fase 2c/2d)
	ConfigFilesScanned    int               `json:"config_files_scanned,omitempty"`   // 1.9.0 (feature 002, capa L5)
	Timeline              *TimelineCoverage `json:"timeline,omitempty"`               // 1.10.0 (feature 009)
	Database              *DBCoverage       `json:"database,omitempty"`               // 1.11.0 (feature 011, capa L7)
	ForeignRoots          []ForeignRoot     `json:"foreign_roots,omitempty"`          // 1.12.0 (feature 012)
}

// TimelineCoverage resume la capa L6 (internal/timeline): la cohorte de ctime
// del árbol (RFC3339, mismo formato que run.finished_at) y los recuentos de
// outliers/manipulaciones. Presente solo si TotalFiles > 0 (Build), para no
// ensuciar informes previos a la 1.10.0.
type TimelineCoverage struct {
	CohortEarliest string `json:"cohort_earliest,omitempty"` // RFC3339 del ctime más antiguo de la cohorte
	CohortLatest   string `json:"cohort_latest,omitempty"`
	TotalFiles     int    `json:"total_files"`
	Outliers       int    `json:"ctime_outliers"`
	Manipulations  int    `json:"mtime_manipulations"`
}

// DBCoverage resume la capa L7 (internal/dbscan): correlación con un volcado
// mysqldump aportado vía --db. Presente solo cuando el scan que originó el
// run recibió --db (Build lo omite si Database es nil): un scan sin --db o un
// report re-renderizado quedan byte-idénticos a antes de esta feature.
// PrivilegedRoster son usernames de cuentas con privilegios de Super User
// (contexto, Principio VII); nunca email.
type DBCoverage struct {
	Prefix           string   `json:"prefix,omitempty"`
	UsersParsed      int      `json:"users_parsed"`
	ExtensionsParsed int      `json:"extensions_parsed"`
	ModulesParsed    int      `json:"modules_parsed"`
	PrivilegedRoster []string `json:"privileged_roster,omitempty"`
	Ambiguous        bool     `json:"ambiguous,omitempty"`
	Unsupported      bool     `json:"unsupported,omitempty"`
	// Correspondence/AbsentFraction (Fix B, feature 011): declaran la salvedad
	// de correspondencia dump↔disco. "mismatch" = el dump no corresponde a
	// este árbol (demasiadas extensiones habilitadas ausentes del disco) →
	// toda la Clase 2 (J0W-DB-002) se suprimió; ambos ausentes (omitempty)
	// cuando el dump corresponde o no hubo población suficiente para juzgarlo.
	Correspondence string  `json:"correspondence,omitempty"`
	AbsentFraction float64 `json:"absent_fraction,omitempty"`
}

// ExtVerification resume la verificación de extensiones de terceros contra su
// paquete oficial: cuántas de las verificables (component/module/plugin/
// template/library, fase 2c) se pudieron comparar, cuántas no (sin baseline
// cacheado o versión distinta) y cuántos archivos resultaron modificados
// (J0W-EXT-008).
type ExtVerification struct {
	ExtensionsVerifiable   int `json:"extensions_verifiable"`
	ExtensionsVerified     int `json:"extensions_verified"`
	ExtensionsUnverifiable int `json:"extensions_unverifiable"`
	FilesModified          int `json:"files_modified"`
}

// LayoutCoverage declara si el árbol de administrator/ es estándar (fase 2c,
// T5/T6). Solo se emite cuando NO es estándar: un árbol estándar no aporta
// información nueva y su ausencia no ensucia informes previos (omitempty).
// Fase 2d (T5) añade RemapApplied/AdminDir/ApiDir/RemapSource: declaran el
// remapeo resuelto (operador o auto-detect) que ya canonicalizó el árbol,
// distinguiendo "no estándar pero remapeado" (benigno) de "no estándar y sin
// resolver" (J0W-LAYOUT-001) — orden canónico: tras AdminDirFound.
type LayoutCoverage struct {
	Standard      bool   `json:"standard"`
	AdminDirFound string `json:"admin_dir_found,omitempty"`
	RemapApplied  bool   `json:"remap_applied"`
	AdminDir      string `json:"admin_dir,omitempty"`
	ApiDir        string `json:"api_dir,omitempty"`
	RemapSource   string `json:"remap_source,omitempty"`
}

// CodeAnalysis resume la capa L4: cuántos ejecutables se analizaron y cuántos
// resultaron marcados por un detector de código (feature 003).
type CodeAnalysis struct {
	FilesScanned int `json:"files_scanned"`
	FilesFlagged int `json:"files_flagged"`
}

// Attribution resume la re-atribución de archivos a extensiones (C3/FR-143):
// distingue "atribuido" de "verificado" a nivel agregado, sin hallazgo por
// archivo.
type Attribution struct {
	FilesAttributed      int `json:"files_attributed"`
	ThirdPartyExtensions int `json:"third_party_extensions"`
	// IntegrityVerified es true si al menos una extensión de terceros se
	// verificó contra su paquete oficial (fase 2a). "Verificado" significa
	// "coincide con el paquete del autor/administrador cacheado", no una
	// prueba firmada (Principio VII).
	IntegrityVerified     bool             `json:"integrity_verified"`
	UnattributedForeign   int              `json:"unattributed_foreign"`
	UnverifiedExecutables *UnverifiedExecs `json:"unverified_executables,omitempty"` // 1.2.0
}

// UnverifiedExecs declara los ejecutables atribuidos a una extensión de tercero
// cuyo contenido NO se ha verificado (integrity_verified: false). No es un
// hallazgo ni afecta al exit code: es la lista de lectura del humano, el andamio
// que impide que mejorar la atribución (D1) haga desaparecer un archivo
// manipulado en silencio.
type UnverifiedExecs struct {
	Count int                   `json:"count"`
	Files []UnverifiedExecEntry `json:"files"`
}

type UnverifiedExecEntry struct {
	Path          string `json:"path"`
	Extension     string `json:"extension"`
	FlaggedByCode bool   `json:"flagged_by_code,omitempty"` // 1.3.0
}

type Analyzed struct {
	Entries     int   `json:"entries"`
	BytesHashed int64 `json:"bytes_hashed"`
}

type NotAnalyzed struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

type Omission struct {
	Path   string `json:"path"`
	What   string `json:"what"`
	Reason string `json:"reason"`
}

type F struct {
	ID           string         `json:"id"`
	RuleID       string         `json:"rule_id"`
	Subject      string         `json:"subject"`
	Severity     string         `json:"severity"`
	BaseSeverity string         `json:"base_severity,omitempty"`
	Confidence   string         `json:"confidence"`
	Observed     string         `json:"observed"`
	ComparedTo   string         `json:"compared_to"`
	Rationale    string         `json:"rationale"`
	Alternative  string         `json:"alternative_hypothesis,omitempty"`
	Evidence     map[string]any `json:"evidence"`
	ObsRefs      []int64        `json:"observation_refs"`
}

type S struct {
	RuleID   string   `json:"rule_id"`
	PathGlob string   `json:"path_glob"`
	Reason   string   `json:"reason"`
	Matched  []string `json:"matched_findings"`
}

type Summary struct {
	BySeverity            map[string]int `json:"findings_by_severity"`
	ExitCode              int            `json:"exit_code"`
	UnverifiedExecutables int            `json:"unverified_executables,omitempty"` // 1.2.0
}

// BuildInput reúne todo lo necesario para ensamblar el informe.
type BuildInput struct {
	Prov provenance.Provenance
	// Language declara el idioma en que finding.Derive ya resolvió la prosa
	// (1.8.0). Cero-valor (i18n.Lang("")) → "es" (por defecto/retrocompat):
	// Build no traduce nada, solo declara lo que el llamador ya resolvió.
	Language     i18n.Lang
	Baseline     BaseRef
	TargetPath   string
	EntriesTotal int
	FilesRegular int
	BytesTotal   int64
	BytesHashed  int64
	Version      Version
	Observations []observe.Observation // para coverage (read_denied, omisiones)
	Findings     []finding.Finding
	Suppressions []finding.Suppression
	Extensions   []Ext // inventario de terceros (feature 002); nil en la 001
	FailOn       finding.Severity
	Started      time.Time
	Finished     time.Time

	CodeFilesScanned int // 1.3.0 (feature 003): archivos analizados por la capa L4

	// ConfigFilesScanned (1.9.0, feature 002): archivos de config del servidor
	// (.htaccess/.user.ini/web.config) analizados por la capa L5
	// (internal/confscan).
	ConfigFilesScanned int

	// Timeline (1.10.0, feature 009): resumen de la capa L6 (internal/timeline),
	// ya convertido a RFC3339 por el llamador (assembleReport, mismo helper de
	// formato que run.finished_at). nil o TotalFiles==0 → Build omite
	// coverage.timeline (sin ensuciar informes previos).
	Timeline *TimelineCoverage

	// Database (1.11.0, feature 011): resumen de la capa L7 (internal/dbscan),
	// ya mapeado desde dbscan.DBSummary por el llamador (scan.go). nil → Build
	// omite coverage.database (sin --db, o report re-renderizado sin volver a
	// aportar el dump: la salida queda byte-idéntica a antes de esta feature).
	Database *DBCoverage

	// ForeignRoots (1.12.0, feature 012): resumen agregado por raíz de nivel
	// superior del contenido de disco ajeno a Joomla y a las extensiones
	// registradas (internal/report.ForeignRoots), ya calculado por el llamador
	// (scan.go/report.go) a partir de las observaciones del run. nil (vacío) →
	// Build omite coverage.foreign_roots (omitempty), byte-idéntico a antes de
	// esta feature.
	ForeignRoots []ForeignRoot

	// LayoutStandard/LayoutAdminDir reflejan layout.Config (fase 2c, T5; fase
	// 2d actualizó la fuente a layout.Resolve/Config): si el árbol
	// administrator/ no es estándar, Build emite coverage.layout.
	LayoutStandard bool
	LayoutAdminDir string

	// LayoutRemapApplied/LayoutRemapAdminDir/LayoutRemapApiDir/LayoutRemapSource
	// (fase 2d, T5) reflejan layout.Config: declaran el remapeo admin/api
	// resuelto (si lo hubo) para poblar los 4 campos nuevos de coverage.layout.
	LayoutRemapApplied  bool
	LayoutRemapAdminDir string
	LayoutRemapApiDir   string
	LayoutRemapSource   string

	// Realize traduce una ruta canónica interna (p.ej. "administrator/x.php")
	// a la ruta REAL de disco (p.ej. "adm1ng/x.php") cuando hubo remapeo de
	// layout (fase 2d, T5). nil = identidad (sin remapeo; salida byte-idéntica
	// a antes de esta feature). Solo se aplica a rutas de cara al operador —
	// nunca a los valores dentro de "evidence" (Principio VII: el mapeo ya
	// está declarado aparte, en coverage.layout).
	Realize func(string) string
}

// Build ensambla el documento canónico (FR-040…FR-043) y calcula el exit
// code efectivo (supresiones y severidad degradada incluidas).
func Build(in BuildInput) (*Report, []byte, error) {
	lang := in.Language
	if lang == "" {
		lang = i18n.ES // por defecto / retrocompat (informes 1.7.0 y anteriores)
	}
	r := &Report{
		SchemaVersion: SchemaVersion,
		Language:      string(lang),
		Run: Run{
			StartedAt:    in.Started.UTC().Format(time.RFC3339),
			FinishedAt:   in.Finished.UTC().Format(time.RFC3339),
			HostnameHash: hostnameHash(),
			DurationMS:   in.Finished.Sub(in.Started).Milliseconds(),
		},
		Provenance: Prov{
			ToolVersion:    in.Prov.ToolVersion,
			ToolHash:       in.Prov.ToolHash,
			Invocation:     in.Prov.Invocation,
			ThreatModel:    string(in.Prov.ThreatModel),
			Baseline:       in.Baseline,
			CatalogVersion: in.Prov.CatalogVersion,
			RulesetVersion: in.Prov.RulesetVersion,
			NetworkUsed:    in.Prov.NetworkUsed,
		},
		Target: Target{
			Path:         in.TargetPath,
			EntriesTotal: in.EntriesTotal,
			FilesRegular: in.FilesRegular,
			BytesTotal:   in.BytesTotal,
		},
		VersionInf: in.Version,
	}

	r.Coverage = buildCoverage(in)
	r.BaselineVerification = buildBaselineVerification(in.Observations)

	// Los observation_refs del informe son ordinales estables dentro del run
	// (posición en el orden canónico de observaciones), no IDs de
	// autoincremento del almacén: dos runs sobre el mismo árbol producen los
	// mismos refs (SC-005).
	ordinal := make(map[int64]int64, len(in.Observations))
	for i, o := range in.Observations {
		ordinal[o.ID] = int64(i + 1)
	}

	counts := map[string]int{"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
	for _, f := range in.Findings {
		if f.SuppressedBy != nil {
			continue // lo suprimido se refleja en suppressions_applied
		}
		counts[string(f.Severity)]++
		refs := make([]int64, 0, len(f.ObsRefs))
		for _, id := range f.ObsRefs {
			if ord, ok := ordinal[id]; ok {
				refs = append(refs, ord)
			}
		}
		rf := F{
			ID: f.ID, RuleID: f.RuleID, Subject: realizePath(in.Realize, f.Subject),
			Severity: string(f.Severity), Confidence: string(f.Confidence),
			Observed: f.Observed, ComparedTo: f.ComparedTo, Rationale: f.Rationale,
			Alternative: f.Alternative, Evidence: f.Evidence, ObsRefs: refs,
		}
		if f.BaseSeverity != f.Severity {
			rf.BaseSeverity = string(f.BaseSeverity)
		}
		r.Findings = append(r.Findings, rf)
	}
	if r.Findings == nil {
		r.Findings = []F{}
	}

	// Cobertura de la capa L4 (feature 003): solo se emite si hubo análisis de
	// código o algún hallazgo J0W-CODE-*, para no ensuciar informes previos.
	flaggedPaths := codeFlaggedPaths(in.Findings)
	if in.CodeFilesScanned > 0 || len(flaggedPaths) > 0 {
		r.Coverage.CodeAnalysis = &CodeAnalysis{FilesScanned: in.CodeFilesScanned, FilesFlagged: len(flaggedPaths)}
	}

	// Cobertura de la capa L5 (feature 002, confscan): archivos de config del
	// servidor analizados. omitempty se encarga de omitir el campo si es cero
	// (informes previos a 1.9.0 quedan idénticos).
	r.Coverage.ConfigFilesScanned = in.ConfigFilesScanned

	// Cobertura de la capa L6 (feature 009, timeline): solo se emite si hubo
	// al menos un archivo en la cohorte, para no ensuciar informes previos a
	// la 1.10.0.
	if in.Timeline != nil && in.Timeline.TotalFiles > 0 {
		r.Coverage.Timeline = in.Timeline
	}

	// Cobertura de la capa L7 (feature 011, dbscan): solo se emite cuando el
	// llamador aportó un resumen (--db se usó en el scan que originó el run).
	if in.Database != nil {
		r.Coverage.Database = in.Database
	}

	// Cobertura de raíces ajenas (feature 012): omitempty se encarga de omitir
	// el campo si el llamador no aportó nada (nil), byte-idéntico a antes de
	// esta feature.
	r.Coverage.ForeignRoots = in.ForeignRoots

	// Cobertura de verificación de extensiones (fase 2a, generalizada en 2c a
	// los 5 tipos verificables).
	r.Coverage.ExtensionVerification = buildExtVerification(in)

	// Desglose de extensiones de terceros por tipo (1.7.0): solo tipos
	// presentes; nil (→ omitempty) si no hay extensiones. El total ya lo da
	// coverage.attribution.third_party_extensions.
	if len(in.Extensions) > 0 {
		byType := make(map[string]int, len(in.Extensions))
		for _, e := range in.Extensions {
			byType[e.Type]++
		}
		r.Coverage.ExtensionsByType = byType
	}

	// Cobertura de layout (fase 2c, T5/T6): solo se emite si el árbol de
	// administrator/ NO es estándar, para no ensuciar informes previos.
	if !in.LayoutStandard {
		r.Coverage.Layout = &LayoutCoverage{
			Standard:      false,
			AdminDirFound: in.LayoutAdminDir,
			RemapApplied:  in.LayoutRemapApplied,
			AdminDir:      in.LayoutRemapAdminDir,
			ApiDir:        in.LayoutRemapApiDir,
			RemapSource:   in.LayoutRemapSource,
		}
	}

	for _, s := range in.Suppressions {
		matched := s.Matched
		if matched == nil {
			matched = []string{}
		}
		r.Suppressions = append(r.Suppressions, S{RuleID: s.Rule, PathGlob: s.Path, Reason: s.Reason, Matched: matched})
	}
	if r.Suppressions == nil {
		r.Suppressions = []S{}
	}
	sort.Slice(r.Suppressions, func(i, j int) bool {
		if r.Suppressions[i].RuleID != r.Suppressions[j].RuleID {
			return r.Suppressions[i].RuleID < r.Suppressions[j].RuleID
		}
		return r.Suppressions[i].PathGlob < r.Suppressions[j].PathGlob
	})

	exit := 0
	for _, f := range in.Findings {
		if f.SuppressedBy == nil && f.Severity.Rank() >= in.FailOn.Rank() {
			exit = 1
			break
		}
	}
	// La atribución se calcula antes del summary: su conteo de ejecutables sin
	// verificar alimenta summary.unverified_executables.
	att := buildAttribution(in)
	r.Coverage.Attribution = att
	unverifiedCount := 0
	if att != nil && att.UnverifiedExecutables != nil {
		unverifiedCount = att.UnverifiedExecutables.Count
	}
	r.Summary = Summary{BySeverity: counts, ExitCode: exit, UnverifiedExecutables: unverifiedCount}

	// Bloque de extensiones (feature 002), ordenado por manifest_path.
	r.Extensions = append([]Ext{}, in.Extensions...)
	if in.Realize != nil {
		for i := range r.Extensions {
			r.Extensions[i].ManifestPath = in.Realize(r.Extensions[i].ManifestPath)
			r.Extensions[i].Roots = realizePaths(in.Realize, r.Extensions[i].Roots)
		}
	}
	sort.Slice(r.Extensions, func(i, j int) bool {
		return r.Extensions[i].ManifestPath < r.Extensions[j].ManifestPath
	})

	doc, err := CanonicalMarshal(r)
	if err != nil {
		return nil, nil, err
	}
	return r, Redact(doc), nil
}

// buildAttribution cuenta archivos atribuidos y ajenos-no-atribuidos desde las
// observaciones (C3): distingue "atribuido" de "verificado" a nivel agregado.
func buildAttribution(in BuildInput) *Attribution {
	att := &Attribution{}
	att.ThirdPartyExtensions = len(in.Extensions)
	attributed := map[string]bool{}
	seen := map[string]bool{}
	flagged := codeFlaggedPaths(in.Findings)
	verifiedPaths := extVerifiedPaths(in.Observations) // fase 2a: exclusión
	var unverified []UnverifiedExecEntry
	for _, o := range in.Observations {
		if o.Type != observe.ExtOwnsPath {
			continue
		}
		attributed[o.SubjectDisplay] = true
		if verifiedPaths[o.SubjectDisplay] {
			continue // ya verificado contra el paquete oficial (fase 2a)
		}
		var ev map[string]any
		_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
		if exec, _ := ev["executable"].(bool); exec && !seen[o.SubjectDisplay] {
			seen[o.SubjectDisplay] = true
			ext, _ := ev["extension"].(string)
			unverified = append(unverified, UnverifiedExecEntry{Path: realizePath(in.Realize, o.SubjectDisplay), Extension: ext, FlaggedByCode: flagged[o.SubjectDisplay]})
		}
	}
	att.FilesAttributed = len(attributed)
	if len(unverified) > 0 {
		sort.Slice(unverified, func(i, j int) bool { return unverified[i].Path < unverified[j].Path })
		att.UnverifiedExecutables = &UnverifiedExecs{Count: len(unverified), Files: unverified}
	}
	// Ajenos que quedaron sin atribuir = J0W-CORE-004 que sobreviven.
	for _, f := range in.Findings {
		if f.RuleID == "J0W-CORE-004" && f.SuppressedBy == nil {
			att.UnattributedForeign++
		}
	}
	// Fase 2a: al menos una extensión verificada contra su paquete oficial.
	for _, e := range in.Extensions {
		if e.Verified {
			att.IntegrityVerified = true
			break
		}
	}
	return att
}

// extVerifiedPaths devuelve el conjunto de rutas con al menos una observación
// ext_file_verified (fase 2a): ya comparadas byte a byte contra el paquete
// oficial, por lo que no pertenecen a unverified_executables aunque estén
// atribuidas y sean ejecutables.
func extVerifiedPaths(obs []observe.Observation) map[string]bool {
	out := map[string]bool{}
	for _, o := range obs {
		if o.Type == observe.ExtFileVerified {
			out[o.SubjectDisplay] = true
		}
	}
	return out
}

// isVerifiableTypeName indica si el valor serializado de Ext.Type participa
// en la verificación contra baseline (fase 2c: los 5 tipos con clave de
// elemento estable, en paridad con extmap.isVerifiableType).
func isVerifiableTypeName(s string) bool {
	switch s {
	case "component", "module", "plugin", "template", "library":
		return true
	}
	return false
}

// buildExtVerification agrega la cobertura de verificación de extensiones:
// cuántas de las extensiones verificables (component/module/plugin/template/
// library, fase 2c) se verificaron contra su paquete oficial, cuántas
// quedaron sin poder verificar (sin baseline cacheado o versión distinta) y
// cuántos archivos resultaron modificados. nil si no hay extensiones de
// terceros que reportar (informe sin capa L3).
func buildExtVerification(in BuildInput) *ExtVerification {
	if len(in.Extensions) == 0 {
		return nil
	}
	verifiable := 0
	verified := 0
	for _, e := range in.Extensions {
		if !isVerifiableTypeName(e.Type) {
			continue // fuera del universo verificable
		}
		verifiable++
		if e.Verified {
			verified++
		}
	}
	modified := 0
	for _, o := range in.Observations {
		if o.Type == observe.ExtFileModified {
			modified++
		}
	}
	return &ExtVerification{
		ExtensionsVerifiable:   verifiable,
		ExtensionsVerified:     verified,
		ExtensionsUnverifiable: verifiable - verified,
		FilesModified:          modified,
	}
}

// buildBaselineVerification proyecta el bloque top-level baseline_verification
// (1.13.0, feature 013) desde la observación observe.BaselineVerified —
// NUNCA re-verifica: es una proyección pura de la observación ya persistida
// (Principio II, mismo camino tanto en scan como en report re-render, ambos
// vía assembleReport → BuildInput.Observations). La evidencia solo declara
// las claves verified_against/catalog_version/manifest_source/assurance
// cuando el scan que la originó pudo verificar contra el catálogo (versión
// dentro de cobertura); si la observación existe pero le falta assurance
// (versión fuera de catálogo, scan.go no verificó), se omite el bloque
// entero — no hay verificación que declarar.
func buildBaselineVerification(obs []observe.Observation) *BaselineVerification {
	for _, o := range obs {
		if o.Type != observe.BaselineVerified {
			continue
		}
		var ev struct {
			VerifiedAgainst string `json:"verified_against"`
			CatalogVersion  string `json:"catalog_version"`
			PackageSHA256   string `json:"package_sha256"`
			ManifestSource  string `json:"manifest_source"`
			Assurance       string `json:"assurance"`
		}
		_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
		if ev.Assurance == "" {
			return nil // versión fuera de catálogo: resolveBaseline no verificó
		}
		return &BaselineVerification{
			VerifiedAgainst: ev.VerifiedAgainst,
			CatalogVersion:  ev.CatalogVersion,
			PackageSHA256:   ev.PackageSHA256,
			ManifestSource:  ev.ManifestSource,
			Assurance:       ev.Assurance,
		}
	}
	return nil
}

func buildCoverage(in BuildInput) Coverage {
	cov := Coverage{
		Analyzed:    Analyzed{Entries: in.EntriesTotal, BytesHashed: in.BytesHashed},
		NotAnalyzed: []NotAnalyzed{},
		Omissions:   []Omission{},
	}
	for _, o := range in.Observations {
		switch o.Type {
		case observe.ReadDenied:
			var ev struct {
				Reason string `json:"reason"`
			}
			_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
			cov.NotAnalyzed = append(cov.NotAnalyzed, NotAnalyzed{Path: realizePath(in.Realize, o.SubjectDisplay), Reason: "read_denied", Detail: ev.Reason})
		case observe.SymlinkOutOfTree:
			cov.NotAnalyzed = append(cov.NotAnalyzed, NotAnalyzed{Path: realizePath(in.Realize, o.SubjectDisplay), Reason: "symlink_out_of_tree"})
		case observe.FuzzyHashSkipped:
			var ev struct {
				Reason string `json:"reason"`
			}
			_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
			cov.Omissions = append(cov.Omissions, Omission{Path: realizePath(in.Realize, o.SubjectDisplay), What: "fuzzy_hash", Reason: ev.Reason})
		}
	}
	sort.Slice(cov.NotAnalyzed, func(i, j int) bool {
		if cov.NotAnalyzed[i].Path != cov.NotAnalyzed[j].Path {
			return cov.NotAnalyzed[i].Path < cov.NotAnalyzed[j].Path
		}
		return cov.NotAnalyzed[i].Reason < cov.NotAnalyzed[j].Reason
	})
	sort.Slice(cov.Omissions, func(i, j int) bool { return cov.Omissions[i].Path < cov.Omissions[j].Path })
	return cov
}

// codeFlaggedPaths devuelve el conjunto de rutas con al menos un hallazgo
// J0W-CODE-* (feature 003).
func codeFlaggedPaths(findings []finding.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "J0W-CODE-") {
			out[f.Subject] = true
		}
	}
	return out
}

// realizePath aplica realize a p si no es nil; identidad si lo es (sin
// remapeo de layout, la salida es byte-idéntica a antes de esta feature).
// Fase 2d (T5): traduce rutas canónicas internas a la ruta REAL de disco de
// cara al operador — nunca se aplica a valores dentro de "evidence".
func realizePath(realize func(string) string, p string) string {
	if realize == nil {
		return p
	}
	return realize(p)
}

// realizePaths aplica realizePath a cada elemento de ps, preservando el
// orden. nil realize devuelve ps sin copiar (identidad).
func realizePaths(realize func(string) string, ps []string) []string {
	if realize == nil {
		return ps
	}
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = realize(p)
	}
	return out
}

// hostnameHash: el hostname no se emite en claro.
func hostnameHash() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	sum := sha256.Sum256([]byte(h))
	return hex.EncodeToString(sum[:])
}
