package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"j0witness/internal/acquire"
	"j0witness/internal/baseline"
	"j0witness/internal/codescan"
	"j0witness/internal/confscan"
	"j0witness/internal/corediff"
	"j0witness/internal/dbscan"
	"j0witness/internal/extmap"
	"j0witness/internal/finding"
	"j0witness/internal/fingerprint"
	"j0witness/internal/i18n"
	"j0witness/internal/inventory"
	"j0witness/internal/layout"
	"j0witness/internal/observe"
	"j0witness/internal/provenance"
	"j0witness/internal/report"
	"j0witness/internal/safefs"
	"j0witness/internal/timeline"
)

func newScanCmd(app *App) *cobra.Command {
	var forcedVersion string
	var failOn string
	var languageFlag string
	var dbDumpPath string
	cmd := &cobra.Command{
		Use:   "scan <ruta>",
		Short: "Análisis completo: L0 → L1 → L2 → informe a stdout",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lang, err := i18n.Parse(languageFlag)
			if err != nil {
				return Exitf(ExitUsageError, "%v", err)
			}
			return runScan(app, args[0], forcedVersion, finding.Severity(failOn), lang, dbDumpPath)
		},
	}
	cmd.Flags().StringVar(&forcedVersion, "joomla-version", "", "fuerza la versión del baseline (la inferencia se ejecuta y reporta igualmente)")
	cmd.Flags().StringVar(&failOn, "fail-on", "medium", "severidad mínima que produce exit 1")
	cmd.Flags().StringVar(&languageFlag, "language", "es", "idioma del informe: es|en")
	cmd.Flags().StringVar(&dbDumpPath, "db", "", "dump mysqldump de la BD del sitio para correlación (offline; jamás se ejecuta)")
	return cmd
}

func runScan(app *App, target, forcedVersion string, failOn finding.Severity, lang i18n.Lang, dbDumpPath string) error {
	started := time.Now()

	// Preflight (Principio I): sin garantías, no se empieza.
	if err := safefs.Preflight(target, app.Flags.Workdir, app.Flags.CacheDir); err != nil {
		return Exitf(ExitPreflightFailed, "%v", err)
	}
	fsys, err := safefs.New(target)
	if err != nil {
		return Exitf(ExitPreflightFailed, "%v", err)
	}

	// Resolución de layout (fase 2d, task 3): ANTES de adquirir, para que la
	// adquisición pueda canonicalizar el árbol (admin/api renombrados →
	// administrator/api). layout.Resolve lee el FS vía safefs (Principio I),
	// no el inventario, así que puede correr aquí, justo tras crear fsys.
	// layoutCfg queda en scope para Tasks 4 (observación layout_remap) y 5
	// (report, vía layoutCfg.Realize).
	layoutCfg, err := layout.Resolve(fsys, app.Flags.AdminDir, app.Flags.ApiDir)
	if err != nil {
		return Exitf(ExitUsageError, "%v", err)
	}
	// realFS centraliza la reversión canónica→real (fase 2d, Task 6, fix
	// round 1): toda relectura de contenido POSTERIOR a la adquisición
	// (corediff, codescan L4, descubrimiento de extensiones L3,
	// fingerprint.Declared) recibe rutas canónicas (administrator/…) pero
	// debe abrir el árbol REAL (adm1ng/… si layoutCfg remapea) — un solo
	// wrapper en vez de repetir layoutCfg.Realize(...) en cada sitio.
	// Cuando no hay remapeo, Realize es identidad: passthrough transparente,
	// comportamiento byte-idéntico al de abrir fsys directamente.
	realFS := layout.NewRealizingOpener(fsys, layoutCfg)

	cat, err := baseline.Load(app.Flags.CatalogPath)
	if err != nil {
		return Exitf(ExitInternalError, "catálogo: %v", err)
	}

	sups, err := finding.LoadSuppressions(app.Flags.Exclusions)
	if err != nil {
		return Exitf(ExitUsageError, "%v", err)
	}

	store, runID, err := openRun(app, "analyze", fsys.Root)
	if err != nil {
		return Exitf(ExitInternalError, "inventario: %v", err)
	}
	defer store.Close()

	// L0 — adquisición.
	sum, err := acquire.Run(fsys, store, runID, acquire.Options{
		Jobs:           app.Flags.Jobs,
		FuzzyThreshold: app.Flags.FuzzyThreshold,
		Canonicalize:   layoutCfg.Canonicalize,
		Progress: func(phase string, done, total int) {
			app.Progress("phase=acquire step=%s done=%d total=%d", phase, done, total)
		},
	})
	if err != nil {
		return Exitf(ExitInternalError, "adquisición: %v", err)
	}

	entries, err := store.EntriesByRun(runID)
	if err != nil {
		return Exitf(ExitInternalError, "%v", err)
	}
	nowNS := time.Now().UnixNano()

	// L6 — análisis temporal: fuente única de la señal mtime>ctime.
	timeObs, timelineSummary := timeline.Analyze(entries, nowNS)
	app.Progress("phase=timeline files=%d outliers=%d manip=%d", timelineSummary.TotalFiles, timelineSummary.OutlierCount, timelineSummary.ManipulationCount)

	// Principio VII: la manipulación temporal degrada el modelo declarado. Ahora la
	// señal viene de la capa timeline (DRY), no de un recorrido propio.
	var threatIndicators []provenance.ThreatIndicator
	for _, o := range timeObs {
		if o.Type == observe.TimeManipulation {
			threatIndicators = append(threatIndicators, provenance.ThreatIndicator{
				Kind: "timestamp_anomaly", Subject: o.SubjectDisplay,
				Detail: "mtime posterior a ctime: timestamps manipulados",
			})
		}
	}
	threatModel := provenance.Assess(threatIndicators)
	if threatModel == provenance.ModelDegraded {
		app.Progress("threat-model=degraded indicators=%d", len(threatIndicators))
	}

	// FR-014 / C3: múltiples raíces → fallo explícito con listado.
	roots := fingerprint.DetectRoots(entries)
	if len(roots) > 1 {
		for _, r := range roots {
			display := r
			if display == "" {
				display = "."
			}
			fmt.Fprintf(app.Stderr, "j0witness: raiz-detectada=%s\n", filepath.Join(target, display))
		}
		return Exitf(ExitMultipleRoots, "hay %d instalaciones bajo el objetivo; apunta a una concreta", len(roots))
	}

	// L1 — inferencia por votación; la declarada solo alimenta FR-012.
	matches := fingerprint.EvaluateWitnesses(cat, entries)
	vote := fingerprint.Vote(matches)
	declared := fingerprint.Declared(realFS)
	app.Progress("phase=fingerprint witnesses=%d/%d", vote.WitnessUsed, vote.WitnessUsed+vote.WitnessUnreadable)

	var fpObs []observe.Observation
	fpObs = append(fpObs, fingerprint.WitnessObservations(matches, nowNS)...)
	if declared != "" {
		if o, err := observe.New(nil, observe.VersionDeclared, map[string]any{"version": declared}, observe.SrcFingerprint, observe.Medium, nowNS); err == nil {
			fpObs = append(fpObs, o)
		}
	}
	mismatch := declared != "" && vote.Winner != "" && declared != vote.Winner
	candidates := make([]map[string]any, 0, len(vote.Candidates))
	for _, c := range vote.Candidates {
		candidates = append(candidates, map[string]any{"version": c.Version, "votes": c.Votes})
	}
	if o, err := observe.New(nil, observe.VersionInferred, map[string]any{
		"inferred": vote.Winner, "declared": declared, "declared_mismatch": mismatch,
		"candidates": candidates,
	}, observe.SrcFingerprint, vote.Confidence, nowNS); err == nil {
		fpObs = append(fpObs, o)
	}
	if vote.Mixed {
		if o, err := observe.New(nil, observe.MixedVersions, map[string]any{"candidates": candidates}, observe.SrcFingerprint, vote.Confidence, nowNS); err == nil {
			fpObs = append(fpObs, o)
		}
	}

	// Selección de baseline: bandera > inferencia (US1 → US2, T041).
	version := forcedVersion
	if version == "" {
		if vote.Winner == "" {
			return Exitf(ExitVersionInconclusive, "no se pudo inferir la versión con confianza; usa --joomla-version")
		}
		version = vote.Winner
	}
	if _, ok := cat.FindRelease(version); !ok {
		return Exitf(ExitVersionUnsupported, "la versión %s queda fuera de la cobertura del catálogo (%v)", version, cat.Versions())
	}

	// L2a — baseline verificado desde caché; sin él, falla explícita. Además
	// de cargarlo, resolveBaseline lo re-contrasta contra el catálogo
	// embebido (Principio VIII) — ver el gate BASELINE_UNTRUSTED ahí.
	manifest, baseRef, content, ver, err := resolveBaseline(app, cat, version)
	if err != nil {
		return err
	}
	baselineEvidence := map[string]any{
		"version": baseRef.Version, "package_sha256": baseRef.PackageSHA256, "manifest_sha256": baseRef.ManifestSHA,
	}
	// ver queda vacío cuando la versión no está en el catálogo (resolveBaseline
	// no verifica en ese caso): la evidencia previa no se toca, sin claves
	// nuevas — Assurance es el campo que nunca queda vacío tras una
	// verificación real (siempre "verified" o "partial").
	if ver.Assurance != "" {
		baselineEvidence["verified_against"] = "embedded-catalog"
		baselineEvidence["catalog_version"] = ver.CatalogVersion
		baselineEvidence["package_sha256"] = ver.PackageSHA256
		baselineEvidence["manifest_source"] = ver.ManifestSource
		baselineEvidence["assurance"] = ver.Assurance
		// Principio VII: un operador que solo mira el exit code (0/1) no ve el
		// JSON — sin esta línea, una degradación a assurance=partial (paquete
		// no cacheado, solo auto-consistencia del manifiesto almacenado) sería
		// silenciosa. --quiet la suprime igual que el resto de phase=.
		app.Progress("phase=baseline verified_against=embedded-catalog assurance=%s manifest_source=%s", ver.Assurance, ver.ManifestSource)
	}
	if o, err2 := observe.New(nil, observe.BaselineVerified, baselineEvidence, observe.SrcBaseline, observe.High, nowNS); err2 == nil {
		fpObs = append(fpObs, o)
	}

	// L2b — clasificación frente al baseline.
	diff := corediff.Classify(corediff.Input{
		Entries:  entries,
		Manifest: manifest,
		Content:  content,
		Known:    cat.KnownIndex(),
		ReadFile: func(rel string) ([]byte, error) {
			// rel llega canonicalizado (administrator/…); realFS revierte a
			// la ruta REAL (adm1ng/… si hubo remapeo) antes de abrir — si no,
			// Open falla en cualquier árbol remapeado y la clasificación rica
			// (EOLOnly/DiffText/injection) degrada silenciosamente a "sin
			// contenido original" (fase 2d, Task 6: expuesto por
			// layout-renamed-trojan.yaml, que exige que el remapeo no ciegue
			// la detección, Principio XI).
			f, err := realFS.Open(rel)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			return io.ReadAll(f)
		},
		NowNS: nowNS,
	})
	app.Progress("phase=corediff compared=%d identical=%d", len(entries), diff.Identical)

	// L3 — extensiones: descubrimiento, mapa de propiedad, re-atribución. Se
	// inserta tras L2 y antes de la derivación (R7). Consulta el inventario, no
	// re-recorre; los manifiestos se leen vía realFS (solo lectura, revertida
	// a ruta real si hubo remapeo de layout — fase 2d, Task 6, fix round 1:
	// antes usaba fsys directo y un manifiesto admin-side dentro de un
	// directorio renombrado se reportaba, falsamente, como
	// ext_manifest_malformed).
	disc := extmap.Discover(entries, extmap.SafeReader(realFS), extmap.CoreBundledFunc(manifest), nowNS)
	ownObs := extmap.BuildOwnership(disc.Extensions, entries, app.Flags.FlagFolderExecs, nowNS)
	ownObs = append(ownObs, extmap.DetectSuspicious(disc.Extensions, nowNS)...)
	app.Progress("phase=extmap extensions=%d core_bundled=%d", len(disc.Extensions), len(disc.CoreBundled))

	// L3c — verificación de extensiones contra su paquete oficial (fase 2a):
	// compara los archivos atribuidos de cada componente contra su baseline
	// cacheado, solo cuando la versión instalada coincide (Principio VI). Los
	// baselines de extensión viven en el almacén de estado compartido del
	// workdir (state.sqlite), no en el del run (igual que resolveBaseline).
	extStore, err := openStateStore(app)
	if err != nil {
		return Exitf(ExitInternalError, "%v", err)
	}
	defer extStore.Close()
	verObs := extmap.VerifyExtensions(disc.Extensions, entries, func(element, version string) (map[string]string, string, bool) {
		id, _, source, err := extStore.FindExtensionBaseline(element, version)
		if err != nil {
			return nil, "", false
		}
		bf, err := extStore.ExtensionBaselineFiles(id)
		if err != nil {
			return nil, "", false
		}
		m := make(map[string]string, len(bf))
		for _, f := range bf {
			m[f.PathDisplay] = f.SHA256
		}
		return m, source, true
	}, nowNS)

	// El inventario de extensiones se proyecta tras la verificación (fase 2a),
	// para poder marcar verified/verification_source por extensión.
	extReport := buildExtInventory(disc, ownObs, verObs)

	// L4 — análisis estático de contenido: tokeniza cada ejecutable PHP (como
	// dato, jamás se ejecuta; Principio IX) y emite observaciones code_suspicious.
	var codeObs []observe.Observation
	codeScanned := 0
	for _, e := range entries {
		if e.Type != "file" || !isPHPExecutable(string(e.RelPath)) {
			continue
		}
		codeScanned++
		// e.RelPath es canónico; igual que en el ReadFile de corediff arriba,
		// realFS revierte a la ruta REAL cuando hubo remapeo de layout (fase
		// 2d, Task 6) — si no, L4 queda ciego para todo archivo dentro del
		// directorio de admin renombrado.
		f, err := realFS.Open(string(e.RelPath))
		if err != nil {
			continue
		}
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			continue
		}
		codeObs = append(codeObs, codescan.Scan(string(e.RelPath), data, nowNS)...)
	}
	app.Progress("phase=codescan scanned=%d flagged=%d", codeScanned, distinctSubjects(codeObs))

	// L5 — análisis de directivas de config del servidor (.htaccess/.user.ini/web.config).
	var confObs []observe.Observation
	configScanned := 0
	for _, e := range entries {
		if e.Type != "file" || !confscan.IsConfigFile(string(e.RelPath)) {
			continue
		}
		configScanned++
		f, err := realFS.Open(string(e.RelPath))
		if err != nil {
			continue
		}
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			continue
		}
		confObs = append(confObs, confscan.Scan(string(e.RelPath), data, nowNS)...)
	}
	app.Progress("phase=confscan scanned=%d flagged=%d", configScanned, distinctSubjects(confObs))

	// Fase 2d (task 4): observación layout_remap, solo cuando el árbol NO es
	// estándar (remapeado O no-resuelto); un árbol estándar no emite nada,
	// igual que la layout_nonstandard de fase 2c (sin ruido en informes
	// estándar). Declara el remapeo resuelto (Principio VII); derive.go
	// decide si además es un hallazgo (J0W-LAYOUT-001, solo si no-remapeado).
	var layoutObs []observe.Observation
	if layoutCfg.RemapApplied() || layoutCfg.NonstandardUnresolved {
		if o, e := observe.New(nil, observe.LayoutRemap, map[string]any{
			"standard":        !layoutCfg.RemapApplied() && !layoutCfg.NonstandardUnresolved,
			"remap_applied":   layoutCfg.RemapApplied(),
			"admin_dir":       layoutCfg.AdminDir,
			"api_dir":         layoutCfg.ApiDir,
			"remap_source":    string(layoutCfg.Source),
			"admin_dir_found": layoutCfg.AdminDirFound,
		}, observe.SrcAcquire, observe.High, nowNS); e == nil {
			layoutObs = append(layoutObs, o)
		}
	}

	// L7 — correlación con la base de datos (feature 011, opcional): solo
	// cuando el operador aporta --db. dbscan.Analyze consume disc.Extensions
	// (Principio III: no vuelve a recorrer disco) y deriva sus tres clases de
	// observación sin decidir hallazgos (eso lo hace finding.Derive, igual que
	// el resto de capas). El dump se PARSEA como texto, jamás se ejecuta
	// (Principio IX). Sin --db, dbObs/dbCov quedan nil: allObs y el informe
	// salen byte-idénticos a antes de esta feature.
	var dbObs []observe.Observation
	var dbCov *report.DBCoverage
	if dbDumpPath != "" {
		f, err := os.Open(dbDumpPath)
		if err != nil {
			return Exitf(ExitUsageError, "--db %s: %v", dbDumpPath, err)
		}
		dump, err := dbscan.Parse(f)
		f.Close()
		if err != nil {
			return Exitf(ExitUsageError, "--db %s: %v", dbDumpPath, err)
		}
		// Oráculo de presencia en disco (Fix A): respaldado por el inventario
		// ya recorrido (Principio III, no re-recorre disco). rel existe como
		// directorio si alguna entrada es rel o cuelga de rel+"/"; se precalcula
		// añadiendo, para cada entrada, todos sus directorios ancestros (y la
		// propia entrada si es un directorio). Las rutas del inventario son
		// canónicas (administrator/…), igual que las candidatas de
		// extInstallDirs con adminDir="administrator".
		dirSet := make(map[string]bool, len(entries))
		for _, e := range entries {
			p := string(e.RelPath)
			if e.Type == "dir" {
				dirSet[p] = true
			}
			for i := 0; i < len(p); i++ {
				if p[i] == '/' {
					dirSet[p[:i]] = true
				}
			}
		}
		dirExists := func(rel string) bool { return dirSet[rel] }
		// El inventario está SIEMPRE canonicalizado (acquire.go canonicaliza
		// RelPath a administrator/… aunque el árbol traiga el admin renombrado,
		// p.ej. adm1ng): el oráculo dirExists solo conoce rutas canónicas, así
		// que extInstallDirs debe usar el "administrator" canónico, NO el
		// app.Flags.AdminDir crudo del operador (review: pasar el nombre
		// renombrado marcaba ausentes en falso las extensiones admin-side de un
		// sitio con admin renombrado → J0W-DB-002 falso + fracción inflada que
		// podía volcar un dump correspondiente a "mismatch").
		var dbSummary dbscan.DBSummary
		dbObs, dbSummary = dbscan.Analyze(dump, disc.Extensions, dirExists, "administrator", nowNS)
		app.Progress("phase=dbscan users=%d extensions=%d modules=%d flagged=%d correspondence=%s",
			dbSummary.UsersParsed, dbSummary.ExtensionsParsed, dbSummary.ModulesParsed, dbFlaggedCount(dbObs), dbSummary.Correspondence)
		dbCov = &report.DBCoverage{
			Prefix:           dbSummary.Prefix,
			UsersParsed:      dbSummary.UsersParsed,
			ExtensionsParsed: dbSummary.ExtensionsParsed,
			ModulesParsed:    dbSummary.ModulesParsed,
			PrivilegedRoster: dbSummary.PrivilegedRoster,
			Ambiguous:        dbSummary.Ambiguous,
			Unsupported:      dbSummary.Unsupported,
			Correspondence:   dbSummary.Correspondence,
			AbsentFraction:   dbSummary.AbsentFraction,
		}
	}

	allObs := append(fpObs, diff.Observations...)
	allObs = append(allObs, disc.Observations...)
	allObs = append(allObs, ownObs...)
	allObs = append(allObs, verObs...)
	allObs = append(allObs, codeObs...)
	allObs = append(allObs, confObs...)
	allObs = append(allObs, layoutObs...)
	allObs = append(allObs, timeObs...)
	allObs = append(allObs, dbObs...)
	if _, err := store.InsertObservations(runID, allObs); err != nil {
		return Exitf(ExitInternalError, "persistiendo observaciones: %v", err)
	}

	// Derivación de hallazgos desde TODAS las observaciones del run.
	persisted, err := store.ObservationsByRun(runID)
	if err != nil {
		return Exitf(ExitInternalError, "%v", err)
	}
	findings := finding.Derive(persisted, version, identicalSet(entries, manifest), lang)
	findings = finding.Apply(findings, sups)

	// Informe canónico.
	inferredPtr := strPtr(vote.Winner)
	declaredPtr := strPtr(declared)
	verBlock := report.Version{
		Inferred: inferredPtr, Declared: declaredPtr,
		Confidence:        string(vote.Confidence),
		Candidates:        toCandidates(vote.Candidates),
		WitnessUsed:       vote.WitnessUsed,
		WitnessUnreadable: vote.WitnessUnreadable,
		MixedVersions:     vote.Mixed,
	}
	sizeBySubject := sizeBySubjectMap(entries)
	knownRoots := knownRootsFromManifest(manifest)
	doc, exitCode, err := assembleReport(app, store, runID, persisted, findings, sups, baseRef, cat, fsys.Root, sum, verBlock, failOn, started, threatModel, extReport, codeScanned, configScanned, layoutCfg, timelineSummary, dbCov, lang, sizeBySubject, knownRoots)
	if err != nil {
		return err
	}
	switch app.Flags.Format {
	case "text":
		txt, terr := report.RenderText(doc)
		if terr != nil {
			return Exitf(ExitInternalError, "%v", terr)
		}
		if _, err := app.Stdout.Write(txt); err != nil {
			return Exitf(ExitInternalError, "%v", err)
		}
	case "pdf":
		pdf, perr := report.RenderPDF(doc)
		if perr != nil {
			return Exitf(ExitInternalError, "%v", perr)
		}
		if _, err := app.Stdout.Write(pdf); err != nil {
			return Exitf(ExitInternalError, "%v", err)
		}
	case "sarif":
		sarif, serr := report.RenderSARIF(doc)
		if serr != nil {
			return Exitf(ExitInternalError, "%v", serr)
		}
		if _, err := app.Stdout.Write(sarif); err != nil {
			return Exitf(ExitInternalError, "%v", err)
		}
	default:
		if _, err := app.Stdout.Write(doc); err != nil {
			return Exitf(ExitInternalError, "%v", err)
		}
	}
	_ = store.FinishRun(runID, time.Now().UnixNano())
	if exitCode == ExitOKFindings {
		return Exitf(ExitOKFindings, "hallazgos con severidad >= %s", failOn)
	}
	return nil
}

// buildExtInventory proyecta el inventario de extensiones de terceros para el
// informe (FR-140), con recuentos de archivos declarados y no declarados
// derivados de las observaciones de propiedad, y verified/verification_source
// derivados de las observaciones de verificación contra el paquete oficial
// (fase 2a: verObs).
func buildExtInventory(disc extmap.Discovered, ownObs []observe.Observation, verObs []observe.Observation) []report.Ext {
	declared := map[string]int{}
	undeclared := map[string]int{}
	for _, o := range ownObs {
		var ev struct {
			Extension string `json:"extension"`
		}
		_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
		switch o.Type {
		case observe.ExtOwnsPath, observe.ExtOwnsFolderExec:
			declared[ev.Extension]++
		case observe.ExtUndeclared:
			undeclared[ev.Extension]++
		}
	}
	// Por ElementKey (la clave que VerifyExtensions/verObs emiten para
	// cualquiera de los 5 tipos de extensión, no solo com_X): la fuente de
	// verificación de la primera observación ext_file_verified o
	// ext_file_modified que se encuentre (hubo baseline y se comparó).
	verifiedSource := map[string]string{}
	for _, o := range verObs {
		if o.Type != observe.ExtFileVerified && o.Type != observe.ExtFileModified {
			continue
		}
		var ev struct {
			Extension          string `json:"extension"`
			VerificationSource string `json:"verification_source"`
		}
		_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
		if _, ok := verifiedSource[ev.Extension]; !ok {
			verifiedSource[ev.Extension] = ev.VerificationSource
		}
	}
	out := make([]report.Ext, 0, len(disc.Extensions))
	for _, e := range disc.Extensions {
		id := e.Name
		if id == "" {
			id = e.ManifestPath
		}
		ext := report.Ext{
			Type:            string(e.Type),
			Name:            e.Name,
			ManifestPath:    e.ManifestPath,
			DeclaredVersion: strPtr(e.Version),
			DeclaredAuthor:  strPtr(e.Author),
			Roots:           e.Layout.Roots,
			FilesDeclared:   declared[id],
			FilesUndeclared: undeclared[id],
			Verified:        false,
		}
		element := e.ElementKey
		if src, ok := verifiedSource[element]; ok {
			ext.Verified = true
			ext.VerificationSource = strPtr(src)
		}
		out = append(out, ext)
	}
	return out
}

// resolveBaseline obtiene manifiesto+contenido del caché (US3: sin red; falla
// explícita indicando qué falta y cómo obtenerlo — FR-020, escenario US3-2).
// Los baselines viven en el almacén compartido del workdir, no en el del
// objetivo.
func resolveBaseline(app *App, cat *baseline.Catalog, version string) (map[string]baseline.ManifestEntry, report.BaseRef, *baseline.Content, baseline.Verification, error) {
	store, err := openStateStore(app)
	if err != nil {
		return nil, report.BaseRef{}, nil, baseline.Verification{}, Exitf(ExitInternalError, "%v", err)
	}
	defer store.Close()
	rel, relOK := cat.FindRelease(version)
	_, pkgSHA, manSHA, source, err := store.FindBaseline(cat.CMS, version)
	if err != nil {
		return nil, report.BaseRef{}, nil, baseline.Verification{}, Exitf(ExitBaselineUnavailable,
			"el baseline de %s no está en el caché local. Obtén el paquete oficial (sha256 %s) y ejecútalo con: j0witness baseline add <paquete>. Con red autorizada: j0witness baseline fetch %s --allow-network",
			version, rel.PackageSHA256, version)
	}
	manifest, err := baseline.Manifest(store, cat.CMS, version)
	if err != nil {
		return nil, report.BaseRef{}, nil, baseline.Verification{}, Exitf(ExitInternalError, "manifiesto de %s: %v", version, err)
	}
	// El catálogo embebido es la única raíz de confianza (Principio VIII): el
	// baseline almacenado/cacheado se re-verifica contra él en cada escaneo,
	// no solo en `baseline add`. Un state.sqlite o un paquete cacheado
	// manipulados tras la incorporación quedan así detectados aquí, antes de
	// que corediff los use como referencia de comparación. Si la versión
	// queda fuera del catálogo (relOK=false) no hay nada contra qué
	// contrastar: se mantiene el comportamiento previo (sin verificación; la
	// cobertura ya degrada por otra vía en ese caso).
	var ver baseline.Verification
	if relOK {
		ver, err = baseline.Verify(rel, cat.CatalogVersion, pkgSHA, manSHA, manifest, app.Flags.CacheDir, version)
		if err != nil {
			if errors.Is(err, baseline.ErrUntrusted) {
				return nil, report.BaseRef{}, nil, baseline.Verification{}, Exitf(ExitBaselineUntrusted,
					"el baseline almacenado de %s no casa con el catálogo embebido (%v); state.sqlite o el paquete cacheado pueden estar manipulados — re-incorpora el paquete oficial con: j0witness baseline add <paquete>", version, err)
			}
			return nil, report.BaseRef{}, nil, baseline.Verification{}, Exitf(ExitInternalError, "verificando baseline: %v", err)
		}
	}
	content, err := baseline.OpenContent(app.Flags.CacheDir, version, pkgSHA)
	if err != nil {
		// Sin contenido cacheado los diffs pierden hunks pero el escaneo
		// sigue: se declara en la cobertura vía observaciones medium.
		content = nil
	}
	return manifest, report.BaseRef{
		CMS: cat.CMS, Version: version, PackageSHA256: pkgSHA, ManifestSHA: manSHA, Source: source,
	}, content, ver, nil
}

func assembleReport(app *App, store *inventory.Store, runID int64, obs []observe.Observation, findings []finding.Finding, sups []*finding.Suppression, baseRef report.BaseRef, cat *baseline.Catalog, targetPath string, sum acquire.Summary, ver report.Version, failOn finding.Severity, started time.Time, threatModel provenance.ThreatModel, extensions []report.Ext, codeScanned int, configScanned int, layoutCfg layout.Config, timelineSummary timeline.TimelineSummary, dbCov *report.DBCoverage, lang i18n.Lang, sizeBySubject map[string]int64, knownRoots map[string]bool) ([]byte, ExitCode, error) {
	supsVals := make([]finding.Suppression, 0, len(sups))
	for _, s := range sups {
		supsVals = append(supsVals, *s)
	}
	// --language se añade al final del bloque de invocación (posición fija,
	// determinista) para que el informe registre la invocación completa
	// (Principio VII), sin alterar el orden de los flags ya recogidos por
	// invocationArgs (compartido con openRun, que no conoce --language).
	args := append(invocationArgs(app), "--language", string(lang))
	// Cobertura de la capa L6 (feature 009): convierte las cohortes de ctime
	// (int64 ns) a RFC3339 con el mismo helper que ya usa el informe para
	// run.finished_at (time.Unix(0, ns).UTC().Format(time.RFC3339)).
	timelineCov := &report.TimelineCoverage{
		TotalFiles:    timelineSummary.TotalFiles,
		Outliers:      timelineSummary.OutlierCount,
		Manipulations: timelineSummary.ManipulationCount,
	}
	if timelineSummary.TotalFiles > 0 {
		timelineCov.CohortEarliest = time.Unix(0, timelineSummary.CohortEarliestNS).UTC().Format(time.RFC3339)
		timelineCov.CohortLatest = time.Unix(0, timelineSummary.CohortLatestNS).UTC().Format(time.RFC3339)
	}
	_, doc, err := report.Build(report.BuildInput{
		Prov: provenance.Provenance{
			ToolVersion:    provenance.Version,
			ToolHash:       provenance.SelfHash(),
			Invocation:     args,
			ThreatModel:    threatModel,
			CatalogVersion: cat.CatalogVersion,
			RulesetVersion: report.SchemaVersion,
			NetworkUsed:    false,
		},
		Baseline:            baseRef,
		TargetPath:          observe.DisplayPath([]byte(targetPath)),
		EntriesTotal:        sum.Entries,
		FilesRegular:        sum.RegularFiles,
		BytesTotal:          sum.BytesTotal,
		BytesHashed:         sum.BytesHashed,
		Version:             ver,
		Observations:        obs,
		Findings:            findings,
		Suppressions:        supsVals,
		Extensions:          extensions,
		CodeFilesScanned:    codeScanned,
		ConfigFilesScanned:  configScanned,
		Timeline:            timelineCov,
		Database:            dbCov,
		ForeignRoots:        report.ForeignRoots(obs, sizeBySubject, knownRoots),
		FailOn:              failOn,
		Started:             started,
		Finished:            time.Now(),
		LayoutStandard:      !layoutCfg.RemapApplied() && !layoutCfg.NonstandardUnresolved,
		LayoutAdminDir:      layoutCfg.AdminDirFound,
		LayoutRemapApplied:  layoutCfg.RemapApplied(),
		LayoutRemapAdminDir: layoutCfg.AdminDir,
		LayoutRemapApiDir:   layoutCfg.ApiDir,
		LayoutRemapSource:   string(layoutCfg.Source),
		Realize:             layoutCfg.Realize,
		Language:            lang,
	})
	if err != nil {
		return nil, ExitInternalError, Exitf(ExitInternalError, "informe: %v", err)
	}
	var parsed struct {
		Summary struct {
			ExitCode int `json:"exit_code"`
		} `json:"summary"`
	}
	_ = json.Unmarshal(doc, &parsed)
	return doc, ExitCode(parsed.Summary.ExitCode), nil
}

func invocationArgs(app *App) []string {
	return []string{
		"--format", app.Flags.Format,
		"--fuzzy-threshold", fmt.Sprint(app.Flags.FuzzyThreshold),
	}
}

// openRun abre el almacén del workdir (nombre derivado del objetivo, vía
// invDBPath — feature 002, Task 4: factorizado para que `runs`/`diff`
// deriven el mismo nombre de store sin re-implementar el hash) y crea el run.
func openRun(app *App, kind, targetRoot string) (*inventory.Store, int64, error) {
	dbPath := invDBPath(app, targetRoot)
	store, err := inventory.Open(dbPath)
	if err != nil {
		return nil, 0, err
	}
	argsJSON, _ := json.Marshal(invocationArgs(app))
	runID, err := store.CreateRun(kind, provenance.Version, provenance.SelfHash(),
		[]byte(targetRoot), observe.DisplayPath([]byte(targetRoot)), string(argsJSON),
		string(provenance.ModelPrimary), time.Now().UnixNano())
	if err != nil {
		store.Close()
		return nil, 0, err
	}
	return store, runID, nil
}

// identicalSet enumera las rutas cuyo contenido coincide byte a byte con el
// baseline (explicación benigna concluyente para discrepancias de tipo).
func identicalSet(entries []inventory.Entry, manifest map[string]baseline.ManifestEntry) map[string]bool {
	out := map[string]bool{}
	for _, e := range entries {
		if e.Type != "file" || e.SHA256 == "" {
			continue
		}
		if want, ok := manifest[string(e.RelPath)]; ok && want.SHA256 == e.SHA256 {
			out[e.PathDisplay] = true
		}
	}
	return out
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// isPHPExecutable replica la lista de extensiones ejecutables del servidor.
func isPHPExecutable(rel string) bool {
	i := strings.LastIndexByte(rel, '.')
	if i < 0 {
		return false
	}
	switch strings.ToLower(rel[i:]) {
	case ".php", ".phar", ".phtml", ".php3", ".php4", ".php5", ".php7", ".pht":
		return true
	}
	return false
}

// sizeBySubjectMap construye el mapa tamaño-por-subject que report.ForeignRoots
// necesita para poblar ForeignRoot.Bytes: la clave DEBE ser la MISMA forma que
// llevan las observaciones (SubjectDisplay = observe.DisplayPath(RelPath)); si
// el llamador usara PathDisplay u otra forma, el join fallaría en silencio
// dejando Bytes en 0 (feature 012, Task 2).
func sizeBySubjectMap(entries []inventory.Entry) map[string]int64 {
	m := make(map[string]int64, len(entries))
	for _, e := range entries {
		if e.Type != "file" {
			continue
		}
		m[observe.DisplayPath(e.RelPath)] = e.Size
	}
	return m
}

// knownRootsFromManifest construye, a partir del manifiesto del baseline
// (map[relpath]ManifestEntry), el conjunto de primeros segmentos de ruta que
// SÍ pertenecen a la distribución de Joomla (p.ej. "images", "administrator",
// "media"). report.ForeignRoots lo usa para marcar DistributionDir: true si
// la raíz ajena agregada es en realidad un directorio ESTÁNDAR de Joomla que
// contiene contenido de usuario, false si la raíz está enteramente ausente
// del manifiesto (genuinamente añadida, p.ej. "app"/"media").
func knownRootsFromManifest(m map[string]baseline.ManifestEntry) map[string]bool {
	roots := make(map[string]bool)
	for p := range m {
		seg := p
		if i := strings.IndexByte(p, '/'); i >= 0 {
			seg = p[:i]
		}
		roots[seg] = true
	}
	return roots
}

// distinctSubjects cuenta los SubjectDisplay distintos entre obs, para que la
// línea de progreso "flagged=" coincida con coverage.code_analysis.files_flagged
// del informe (archivos distintos, no observaciones crudas: un mismo archivo
// puede producir varias observaciones code_suspicious).
func distinctSubjects(obs []observe.Observation) int {
	seen := map[string]bool{}
	for _, o := range obs {
		seen[o.SubjectDisplay] = true
	}
	return len(seen)
}

// dbFlaggedCount cuenta los subjects distintos entre dbObs que deriva.Derive
// convertiría en un hallazgo J0W-DB-* autónomo (no en mera corroboración):
// db_privileged_anomaly y db_content_payload siempre lo son; db_extension_state
// solo cuando present_on_disk es false (huérfana en BD) — con present_on_disk
// true es contexto de correlación (ver finding/derive.go), no un hallazgo. La
// línea de progreso "flagged=" así coincide con lo que el informe terminará
// mostrando, igual que distinctSubjects para codescan/confscan.
func dbFlaggedCount(obs []observe.Observation) int {
	var flagged []observe.Observation
	for _, o := range obs {
		switch o.Type {
		case observe.DBExtensionState:
			var ev struct {
				PresentOnDisk bool `json:"present_on_disk"`
			}
			_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
			if ev.PresentOnDisk {
				continue
			}
		case observe.DBPrivilegedAnomaly, observe.DBContentPayload:
			// siempre cuenta.
		default:
			continue
		}
		flagged = append(flagged, o)
	}
	return distinctSubjects(flagged)
}

func toCandidates(cs []fingerprint.Candidate) []report.Candidate {
	out := make([]report.Candidate, 0, len(cs))
	for _, c := range cs {
		out = append(out, report.Candidate{Version: c.Version, Votes: c.Votes})
	}
	return out
}
