// Package finding deriva hallazgos desde observaciones — nunca al revés
// (Principio II: los veredictos se derivan por consulta, no se almacenan como
// verdad primaria). Cada hallazgo se explica solo (Principio V).
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"j0witness/internal/i18n"
	"j0witness/internal/observe"
)

// Severity con orden total para comparaciones.
type Severity string

const (
	Info     Severity = "info"
	Low      Severity = "low"
	MediumS  Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

var sevRank = map[Severity]int{Info: 0, Low: 1, MediumS: 2, High: 3, Critical: 4}

// Rank expone el orden de severidad.
func (s Severity) Rank() int { return sevRank[s] }

// Finding es una conclusión derivada, con los campos obligatorios del
// Principio V: qué se observó, contra qué se comparó, por qué es relevante y
// con qué confianza; más la hipótesis alternativa cuando existe.
type Finding struct {
	ID           string
	RuleID       string
	Subject      string
	Severity     Severity
	BaseSeverity Severity // != Severity solo si la derivación degradó
	Confidence   observe.Confidence
	Observed     string
	ComparedTo   string
	Rationale    string
	Alternative  string
	Evidence     map[string]any
	ObsRefs      []int64
	SuppressedBy *Suppression
}

// stableID deriva el identificador determinista (SC-005): mismas entradas →
// mismo id, citable y suprimible entre ejecuciones.
func stableID(ruleID, subject string, evidence map[string]any) string {
	raw, _ := json.Marshal(evidence) // claves ordenadas por encoding/json
	h := sha256.Sum256([]byte(ruleID + "\x00" + subject + "\x00" + string(raw)))
	return hex.EncodeToString(h[:8])
}

// Derive recorre las observaciones de un run (en orden estable) y produce los
// hallazgos según la taxonomía J0W-CORE-001…012 de data-model.md.
// identicalToBaseline permite degradar hallazgos cuya explicación benigna es
// concluyente: el archivo es byte a byte el que distribuye el proyecto
// (Joomla publica favicons PNG con extensión .ico y JPEG nombrados .png).
func Derive(obs []observe.Observation, baselineVersion string, identicalToBaseline map[string]bool, lang i18n.Lang) []Finding {
	// L3 (feature 002): pre-escaneo de las observaciones de propiedad para la
	// re-atribución. Un file_unexpected cuyo sujeto está atribuido a una
	// extensión (ext_owns_path) NO produce J0W-CORE-004; queda explicado y se
	// cuenta en cobertura. La precedencia de contracts/finding-taxonomy.md la
	// aplica deriveOne para las propias observaciones ext_*.
	// Un archivo cae bajo la capa de extensiones si tiene cualquier
	// observación ext_* sobre él: sea atribuido (ext_owns_path, silencioso),
	// ejecutable-en-carpeta (ext_owns_folder_exec → J0W-EXT-002) o no declarado
	// (ext_undeclared → J0W-EXT-001). En todos los casos el hallazgo específico
	// de la extensión reemplaza al genérico J0W-CORE-004 (precedencia de
	// contracts/finding-taxonomy.md).
	handledByExt := map[string]bool{}
	for _, o := range obs {
		switch o.Type {
		case observe.ExtOwnsPath, observe.ExtOwnsFolderExec, observe.ExtUndeclared:
			handledByExt[o.SubjectDisplay] = true
		}
	}
	// L4 (feature 002): un archivo con observación config_directive_suspicious
	// (Task 1, internal/confscan) es un archivo de configuración ya explicado
	// por J0W-CONFIG-001/002/003; no debe además reportarse como "archivo
	// inesperado" genérico (precedencia: específico > genérico).
	handledByConfig := map[string]bool{}
	for _, o := range obs {
		if o.Type == observe.ConfigDirective {
			handledByConfig[o.SubjectDisplay] = true
		}
	}
	// Feature de análisis temporal (task 2): pre-escaneo de ctime_outlier
	// (Task 1, internal/timeline) para corroborar hallazgos existentes sobre
	// el mismo subject (subject → days_after_cohort). ctime_outlier nunca
	// produce un hallazgo por sí mismo (ver deriveOne); solo anota.
	ctimeOutlier := map[string]int64{}
	for _, o := range obs {
		if o.Type == observe.CtimeOutlier {
			var ev map[string]any
			_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
			days, _ := ev["days_after_cohort"].(float64) // JSON number → float64
			ctimeOutlier[o.SubjectDisplay] = int64(days)
		}
	}
	// L7 (dbscan, task 3): pre-escaneo de extensiones activas en BD (present_on_disk
	// == true, con disk_paths) para correlacionar (anotar, NUNCA elevar —
	// Principio VI) hallazgos de disco cuyo subject caiga bajo alguna de sus
	// raíces instaladas. dbActiveExtPaths mapea raíz de disco → element.
	dbActiveExtPaths := map[string]string{}
	for _, o := range obs {
		if o.Type != observe.DBExtensionState {
			continue
		}
		var ev map[string]any
		_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
		present, _ := ev["present_on_disk"].(bool)
		if !present {
			continue
		}
		element, _ := ev["element"].(string)
		paths, _ := ev["disk_paths"].([]any)
		for _, p := range paths {
			if root, ok := p.(string); ok && root != "" {
				dbActiveExtPaths[root] = element
			}
		}
	}
	// Iterar en orden ordenado de raíces asegura que un subject bajo dos
	// raíces se anote de forma estable (determinismo, Principio IV), sin
	// depender del orden de iteración del mapa.
	dbActiveExtRoots := make([]string, 0, len(dbActiveExtPaths))
	for root := range dbActiveExtPaths {
		dbActiveExtRoots = append(dbActiveExtRoots, root)
	}
	sort.Strings(dbActiveExtRoots)

	var out []Finding
	for _, o := range obs {
		// Re-atribución: el file_unexpected manejado por la capa de extensiones
		// se suprime aquí (Principio II: la observación persiste; solo la vista
		// de hallazgos la omite en favor del hallazgo J0W-EXT específico).
		if o.Type == observe.FileUnexpected && handledByExt[o.SubjectDisplay] {
			continue
		}
		if o.Type == observe.FileUnexpected && handledByConfig[o.SubjectDisplay] {
			continue // específico > genérico: el hallazgo J0W-CONFIG reemplaza al CORE-004
		}
		f := deriveOne(o, baselineVersion, lang)
		if f == nil {
			continue
		}
		if f.RuleID == "J0W-CORE-010" && identicalToBaseline[f.Subject] {
			// Degradación, nunca elevación (Principio VI): la distribución
			// oficial lo publica exactamente así.
			f.Severity = Info
			f.Alternative = i18n.T(lang, "core010.alt.identical", nil)
		}
		// Corroboración por ctime-outlier (feature de análisis temporal, task 2):
		// anota el hallazgo, no lo crea ni le cambia la severidad, y nunca se
		// anota a sí mismo el propio J0W-TIME-001. Corre después de deriveOne
		// (que ya calculó stableID), así que los IDs quedan estables.
		if f.RuleID != "J0W-TIME-001" {
			if days, ok := ctimeOutlier[f.Subject]; ok {
				if f.Evidence == nil {
					f.Evidence = map[string]any{}
				}
				f.Evidence["ctime_outlier"] = true
				f.Evidence["ctime_days_after_cohort"] = days
				f.Rationale += i18n.T(lang, "corroboration.ctime_outlier", map[string]any{"days": days})
			}
		}
		// Corroboración por extensión activa en BD (dbscan, task 3): anota el
		// hallazgo, no lo crea ni le cambia la severidad (Principio VI), y nunca
		// se anota a sí mismo un hallazgo J0W-DB-*. Corre después de deriveOne
		// (que ya calculó stableID), así que los IDs quedan estables.
		if !strings.HasPrefix(f.RuleID, "J0W-DB-") {
			for _, root := range dbActiveExtRoots {
				if f.Subject == root || strings.HasPrefix(f.Subject, root+"/") {
					element := dbActiveExtPaths[root]
					if f.Evidence == nil {
						f.Evidence = map[string]any{}
					}
					f.Evidence["db_active_extension"] = element
					f.Rationale += i18n.T(lang, "corroboration.db_extension", map[string]any{"element": element})
					break
				}
			}
		}
		out = append(out, *f)
	}
	// Orden del contrato: severidad desc, rule_id asc, subject asc, id asc.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity.Rank() != out[j].Severity.Rank() {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func deriveOne(o observe.Observation, baselineVersion string, lang i18n.Lang) *Finding {
	var ev map[string]any
	_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
	subject := o.SubjectDisplay
	base := func(rule string, sev Severity, observed, compared, rationale, alternative string) *Finding {
		return &Finding{
			ID: stableID(rule, subject, ev), RuleID: rule, Subject: subject,
			Severity: sev, BaseSeverity: sev, Confidence: o.Confidence,
			Observed: observed, ComparedTo: compared, Rationale: rationale,
			Alternative: alternative, Evidence: ev, ObsRefs: []int64{o.ID},
		}
	}
	compared := i18n.T(lang, "compared.baseline", map[string]any{"version": baselineVersion})

	switch o.Type {
	case observe.FileModified:
		if inj, _ := ev["injection"].(bool); inj {
			return base("J0W-CORE-002", Critical,
				i18n.T(lang, "core002.observed", nil), compared,
				i18n.T(lang, "core002.rationale", nil), "")
		}
		f := base("J0W-CORE-001", High,
			i18n.T(lang, "core001.observed", nil), compared,
			i18n.T(lang, "core001.rationale", nil), "")
		if deg, ok := ev["degree"].(float64); ok && deg < 0.02 {
			f.Severity = MediumS // divergencia mínima: degradación, nunca elevación
			f.Alternative = i18n.T(lang, "core001.alt.minor", nil)
		}
		if exec, _ := ev["executable"].(bool); !exec {
			if bin, _ := ev["binary"].(bool); bin {
				f.Severity = Low // base_severity conserva el original (Principio VI)
				f.Alternative = i18n.T(lang, "core001.alt.inert", nil)
			}
		}
		return f
	case observe.EOLNormalization:
		f := base("J0W-CORE-006", Info,
			i18n.T(lang, "core006.observed", nil), compared,
			i18n.T(lang, "core006.rationale", nil), i18n.T(lang, "core006.alt", nil))
		return f
	case observe.FileMissing:
		if expected, _ := ev["expected_post_install"].(bool); expected {
			return base("J0W-CORE-003", Info,
				i18n.T(lang, "core003.installation.observed", nil), compared,
				i18n.T(lang, "core003.installation.rationale", nil),
				i18n.T(lang, "core003.installation.alt", nil))
		}
		if collapsed, _ := ev["subtree_collapsed"].(bool); collapsed {
			n := 0
			if v, ok := ev["files_missing"].(float64); ok { // JSON: números → float64
				n = int(v)
			}
			f := base("J0W-CORE-003", MediumS,
				i18n.T(lang, "core003.collapsed.observed", map[string]any{"n": n}),
				compared,
				i18n.T(lang, "core003.collapsed.rationale", nil),
				i18n.T(lang, "core003.collapsed.alt", nil))
			switch cls, _ := ev["missing_class"].(string); cls {
			case "inert_asset":
				f.Severity = Low
			case "expected_absent":
				f.Severity = Info
				// "executable"/"" → medium (base)
			}
			return f
		}
		f := base("J0W-CORE-003", MediumS,
			i18n.T(lang, "core003.observed", nil), compared,
			i18n.T(lang, "core003.rationale", nil),
			i18n.T(lang, "core003.alt", nil))
		switch cls, _ := ev["missing_class"].(string); cls {
		case "inert_asset":
			f.Severity = Low
			f.Rationale = i18n.T(lang, "core003.rationale.inert_asset", nil)
			f.Alternative = i18n.T(lang, "core003.alt.inert_asset", nil)
		case "expected_absent":
			f.Severity = Info
			f.Rationale = i18n.T(lang, "core003.rationale.expected_absent", nil)
			f.Alternative = i18n.T(lang, "core003.alt.expected_absent", nil)
			// "executable" / "" → se queda MediumS (base), sin degradar; Rationale sin cambios
		}
		return f
	case observe.FileUnexpected:
		executable, _ := ev["executable"].(bool)
		forbidden, _ := ev["in_forbidden_exec"].(bool)
		inCore, _ := ev["in_core_dir"].(bool)
		if executable && forbidden {
			if artifact, _ := ev["runtime_artifact"].(bool); artifact {
				f := base("J0W-CORE-005", Info,
					i18n.T(lang, "core005.artifact.observed", nil),
					compared,
					i18n.T(lang, "core005.artifact.rationale", nil),
					i18n.T(lang, "core005.artifact.alt", nil))
				f.BaseSeverity = Critical // registra la degradación (Principio VI: nunca elevación)
				return f
			}
			return base("J0W-CORE-005", Critical,
				i18n.T(lang, "core005.observed", nil), compared,
				i18n.T(lang, "core005.rationale", nil), "")
		}
		if inCore {
			sev := High
			if !executable {
				sev = MediumS
			}
			return base("J0W-CORE-004", sev,
				i18n.T(lang, "core004.observed", nil), compared,
				i18n.T(lang, "core004.rationale", nil),
				i18n.T(lang, "core004.alt", nil))
		}
		return nil // contenido de usuario fuera del core: cobertura, no hallazgo
	case observe.FileObsoleteKnown:
		if match, _ := ev["hash_matches_history"].(bool); match {
			return base("J0W-CORE-011", Info,
				i18n.T(lang, "core011.observed", nil), compared,
				i18n.T(lang, "core011.rationale", nil),
				i18n.T(lang, "core011.alt", nil))
		}
		f := base("J0W-CORE-009", High,
			i18n.T(lang, "core009.observed", nil), compared,
			i18n.T(lang, "core009.rationale", nil), "")
		if exec, _ := ev["executable"].(bool); !exec {
			if bin, _ := ev["binary"].(bool); bin {
				f.Severity = Low
				f.Alternative = i18n.T(lang, "core009.alt.inert", nil)
			}
		}
		return f
	case observe.TypeMismatch:
		f := base("J0W-CORE-010", MediumS,
			i18n.T(lang, "core010.observed", nil), i18n.T(lang, "core010.compared", nil),
			i18n.T(lang, "core010.rationale", nil),
			i18n.T(lang, "core010.alt", nil))
		if magic, _ := ev["magic"].(string); isInertMagic(magic) {
			f.Severity = Info // el contenido es otra imagen/media inerte, no un script
			f.Alternative = i18n.T(lang, "core010.alt.inert", nil)
		}
		return f
	case observe.VersionInferred:
		if mismatch, _ := ev["declared_mismatch"].(bool); mismatch {
			return base("J0W-CORE-007", High,
				i18n.T(lang, "core007.observed", nil),
				i18n.T(lang, "compared.witness", nil),
				i18n.T(lang, "core007.rationale", nil), "")
		}
		return nil
	case observe.MixedVersions:
		return base("J0W-CORE-008", MediumS,
			i18n.T(lang, "core008.observed", nil), i18n.T(lang, "compared.witness", nil),
			i18n.T(lang, "core008.rationale", nil),
			i18n.T(lang, "core008.alt", nil))
	case observe.ConfigStructure:
		anomalies, _ := ev["anomalies"].([]any)
		if len(anomalies) > 0 {
			return base("J0W-CORE-012", MediumS,
				i18n.T(lang, "core012.observed", nil), i18n.T(lang, "core012.compared", nil),
				i18n.T(lang, "core012.rationale", nil), "")
		}
		return nil

	// L3 (feature 002): familia J0W-EXT. La precedencia por sujeto la garantiza
	// el orden de estas observaciones y el filtro de re-atribución en Derive.
	case observe.ExtUndeclared:
		if exec, _ := ev["executable"].(bool); exec {
			ext, _ := ev["extension"].(string)
			return base("J0W-EXT-001", High,
				i18n.T(lang, "ext001.observed", map[string]any{"ext": ext}),
				i18n.T(lang, "compared.manifest", map[string]any{"ext": ext}),
				i18n.T(lang, "ext001.rationale", nil), "")
		}
		return nil // no-declarado no ejecutable: no es hallazgo (imagen, doc suelto)
	case observe.ExtOwnsFolderExec:
		ext, _ := ev["extension"].(string)
		return base("J0W-EXT-002", MediumS,
			i18n.T(lang, "ext002.observed", map[string]any{"ext": ext}),
			i18n.T(lang, "compared.manifest", map[string]any{"ext": ext}),
			i18n.T(lang, "ext002.rationale", nil),
			i18n.T(lang, "ext002.alt", nil))
	case observe.ExtManifestMalformed:
		return base("J0W-EXT-003", MediumS,
			i18n.T(lang, "ext003.observed", nil),
			i18n.T(lang, "ext003.compared", nil),
			i18n.T(lang, "ext003.rationale", nil),
			i18n.T(lang, "ext003.alt", nil))
	case observe.ExtManifestSuspicious:
		return base("J0W-EXT-004", High,
			i18n.T(lang, "ext004.observed", nil),
			i18n.T(lang, "ext004.compared", nil),
			i18n.T(lang, "ext004.rationale", nil), "")
	case observe.ExtDeclaredMissing:
		ext, _ := ev["extension"].(string)
		return base("J0W-EXT-005", Low,
			i18n.T(lang, "ext005.observed", map[string]any{"ext": ext}),
			i18n.T(lang, "compared.manifest", map[string]any{"ext": ext}),
			i18n.T(lang, "ext005.rationale", nil),
			i18n.T(lang, "ext005.alt", nil))
	case observe.ExtOwnershipConflict:
		return base("J0W-EXT-006", Info,
			i18n.T(lang, "ext006.observed", nil),
			i18n.T(lang, "ext006.compared", nil),
			i18n.T(lang, "ext006.rationale", nil), "")
	case observe.ExtManifestMissing:
		return base("J0W-EXT-007", Low,
			i18n.T(lang, "ext007.observed", nil),
			i18n.T(lang, "ext007.compared", nil),
			i18n.T(lang, "ext007.rationale", nil),
			i18n.T(lang, "ext007.alt", nil))

	// Fase 2a: verificación de extensiones contra su paquete oficial.
	// J0W-EXT-008/009 heredan de D5 la sensibilidad al contenido: una
	// divergencia en un archivo ejecutable es una modificación efectiva
	// (critical); en uno inerte es integridad de contenido, no de ejecución
	// (low). ext_file_verified no produce hallazgo: se refleja en cobertura.
	case observe.ExtFileModified:
		ext, _ := ev["extension"].(string)
		src, _ := ev["verification_source"].(string)
		exec, _ := ev["executable"].(bool)
		sev := Low
		if exec {
			sev = Critical
		}
		return base("J0W-EXT-008", sev,
			i18n.T(lang, "ext008.observed", map[string]any{"ext": ext, "src": src}),
			i18n.T(lang, "compared.official_pkg", nil),
			i18n.T(lang, "ext008.rationale", nil),
			i18n.T(lang, "ext008.alt", nil))
	case observe.ExtOfficialMissing:
		ext, _ := ev["extension"].(string)
		return base("J0W-EXT-009", MediumS,
			i18n.T(lang, "ext009.observed", map[string]any{"ext": ext}),
			i18n.T(lang, "compared.official_pkg", nil),
			i18n.T(lang, "ext009.rationale", nil), "")
	case observe.ExtFileVerified:
		return nil // se refleja en cobertura, no es hallazgo

	// Fase 2d (task 4): layout_remap es un hecho del árbol completo (no de un
	// archivo). Cuando el remapeo se aplicó (operador o auto-detect), el árbol
	// SÍ se analiza correctamente y la observación queda declarada en el
	// informe (Principio VII) sin ser un hallazgo. Solo cuando el layout es
	// no estándar Y no se pudo remapear degrada la atribución del lado admin.
	case observe.LayoutRemap:
		applied, _ := ev["remap_applied"].(bool)
		if applied {
			return nil // remapeo aplicado y declarado: no es un hallazgo
		}
		found, _ := ev["admin_dir_found"].(string)
		obsTxt := i18n.T(lang, "layout001.observed.generic", nil)
		if found != "" {
			obsTxt = i18n.T(lang, "layout001.observed.found", map[string]any{"found": found})
		}
		return base("J0W-LAYOUT-001", Low,
			obsTxt,
			i18n.T(lang, "layout001.compared", nil),
			i18n.T(lang, "layout001.rationale", nil),
			i18n.T(lang, "layout001.alt", nil))

	// L4 (feature 003): familia J0W-CODE. code_suspicious trae construct/sink/
	// trigger/line/executable; el construct decide la regla y severidad.
	case observe.CodeSuspicious:
		construct, _ := ev["construct"].(string)
		sink, _ := ev["sink"].(string)
		switch construct {
		case "obfuscated_eval":
			return base("J0W-CODE-001", Critical,
				i18n.T(lang, "code001.observed", map[string]any{"sink": sink}),
				i18n.T(lang, "compared.webshell", nil),
				i18n.T(lang, "code001.rationale", nil),
				i18n.T(lang, "code001.alt", nil))
		case "input_to_sink":
			trg, _ := ev["trigger"].(string)
			return base("J0W-CODE-002", Critical,
				i18n.T(lang, "code002.observed", map[string]any{"trg": trg, "sink": sink}),
				i18n.T(lang, "compared.rce", nil),
				i18n.T(lang, "code002.rationale", nil),
				i18n.T(lang, "code002.alt", nil))
		case "preg_e":
			return base("J0W-CODE-003", High,
				i18n.T(lang, "code003.observed", nil),
				i18n.T(lang, "code003.compared", nil),
				i18n.T(lang, "code003.rationale", nil),
				i18n.T(lang, "code003.alt", nil))
		case "dynamic_call":
			return base("J0W-CODE-004", Critical,
				i18n.T(lang, "code004.observed", nil),
				i18n.T(lang, "compared.webshell_backdoor", nil),
				i18n.T(lang, "code004.rationale", nil),
				i18n.T(lang, "code004.alt", nil))
		}
		return nil

	// L4 (feature 002): familia J0W-CONFIG. config_directive_suspicious trae
	// directive_class/directive/target/line/inert_media/state; la clase decide
	// la regla y la severidad calibrada (D5: media inerte reejecutada como PHP
	// eleva a critical; ajustes de runtime concretos elevan a high).
	case observe.ConfigDirective:
		class, _ := ev["directive_class"].(string)
		directive, _ := ev["directive"].(string)
		target, _ := ev["target"].(string)
		state, _ := ev["state"].(string)
		p := map[string]any{"directive": directive, "target": target, "state": state}
		switch class {
		case "exec_loader":
			return base("J0W-CONFIG-001", Critical,
				i18n.T(lang, "config001.observed", p), i18n.T(lang, "config.compared", nil),
				i18n.T(lang, "config001.rationale", nil), i18n.T(lang, "config001.alt", nil))
		case "handler_widen":
			sev := High
			if inert, _ := ev["inert_media"].(bool); inert {
				sev = Critical // una extensión de media inerte ejecutándose como PHP = habilitador de webshell
			}
			return base("J0W-CONFIG-002", sev,
				i18n.T(lang, "config002.observed", p), i18n.T(lang, "config.compared", nil),
				i18n.T(lang, "config002.rationale", p), i18n.T(lang, "config002.alt", nil))
		case "php_setting":
			sev := MediumS
			if directive == "allow_url_include" || directive == "disable_functions" {
				sev = High
			}
			return base("J0W-CONFIG-003", sev,
				i18n.T(lang, "config003.observed", p), i18n.T(lang, "config.compared", nil),
				i18n.T(lang, "config003.rationale", nil), i18n.T(lang, "config003.alt", nil))
		}
		return nil

	// Feature de análisis temporal (task 2): time_manipulation (mtime > ctime)
	// deriva J0W-TIME-001 en low; ctime_outlier nunca es un hallazgo autónomo,
	// solo corrobora hallazgos existentes sobre el mismo subject (ver Derive).
	case observe.TimeManipulation:
		return base("J0W-TIME-001", Low,
			i18n.T(lang, "time001.observed", nil), i18n.T(lang, "time.compared", nil),
			i18n.T(lang, "time001.rationale", nil), i18n.T(lang, "time001.alt", nil))
	case observe.CtimeOutlier:
		return nil // corroboración: nunca es hallazgo autónomo

	// L7 (dbscan, task 3): familia J0W-DB — correlación con el estado de la
	// base de datos. db_extension_state con present_on_disk == true es
	// contexto de correlación (ver dbActiveExtPaths/anotación en Derive), no
	// un hallazgo autónomo: la extensión está tanto en BD como en disco, que
	// es el estado esperado.
	case observe.DBPrivilegedAnomaly:
		username, _ := ev["username"].(string)
		reasonsAny, _ := ev["reasons"].([]any)
		reasons := make([]string, 0, len(reasonsAny))
		for _, r := range reasonsAny {
			if s, ok := r.(string); ok {
				reasons = append(reasons, s)
			}
		}
		return base("J0W-DB-001", High,
			i18n.T(lang, "db001.observed", map[string]any{"username": username, "reasons": strings.Join(reasons, ", ")}),
			i18n.T(lang, "db001.compared", nil),
			i18n.T(lang, "db001.rationale", nil),
			i18n.T(lang, "db001.alt", nil))
	case observe.DBExtensionState:
		if present, _ := ev["present_on_disk"].(bool); present {
			return nil // contexto de correlación, no hallazgo autónomo
		}
		element, _ := ev["element"].(string)
		return base("J0W-DB-002", High,
			i18n.T(lang, "db002.observed", map[string]any{"element": element}),
			i18n.T(lang, "db002.compared", nil),
			i18n.T(lang, "db002.rationale", nil),
			i18n.T(lang, "db002.alt", nil))
	case observe.DBContentPayload:
		return base("J0W-DB-003", Critical,
			i18n.T(lang, "db003.observed", nil),
			i18n.T(lang, "db003.compared", nil),
			i18n.T(lang, "db003.rationale", nil), "")
	}
	return nil
}

// isInertMagic informa de si un tipo MIME corresponde a datos inertes (no
// ejecutables ni interpretables): imagen, audio, vídeo o fuente. Sesgo
// fail-safe: cualquier otro tipo (text/*, application/*, script, desconocido)
// NO es inerte, para no degradar una posible evasión (D5).
func isInertMagic(magic string) bool {
	if magic == "image/svg+xml" {
		// El SVG admite <script> embebido: es contenido activo, no una imagen
		// rasterizada inerte. IsTextType (textdiff.go) ya lo clasifica como
		// texto; este predicado no puede contradecirlo (D5).
		return false
	}
	for _, p := range []string{"image/", "audio/", "video/", "font/"} {
		if len(magic) >= len(p) && magic[:len(p)] == p {
			return true
		}
	}
	return false
}
