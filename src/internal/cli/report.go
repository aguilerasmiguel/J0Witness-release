package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"j0witness/internal/acquire"
	"j0witness/internal/baseline"
	"j0witness/internal/confscan"
	"j0witness/internal/finding"
	"j0witness/internal/i18n"
	"j0witness/internal/inventory"
	"j0witness/internal/layout"
	"j0witness/internal/observe"
	"j0witness/internal/provenance"
	"j0witness/internal/report"
	"j0witness/internal/timeline"
)

func newReportCmd(app *App) *cobra.Command {
	var failOn string
	var languageFlag string
	cmd := &cobra.Command{
		Use:   "report <workdir>",
		Short: "Re-renderiza el informe desde el inventario, sin re-recorrer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lang, err := i18n.Parse(languageFlag)
			if err != nil {
				return Exitf(ExitUsageError, "%v", err)
			}
			return runReport(app, args[0], finding.Severity(failOn), lang)
		},
	}
	cmd.Flags().StringVar(&failOn, "fail-on", "medium", "severidad mínima que produce exit 1")
	cmd.Flags().StringVar(&languageFlag, "language", "es", "idioma del informe: es|en")
	return cmd
}

// extInventoryFromObs reconstruye el inventario de extensiones desde las
// observaciones persistidas (ext_discovered + ext_owns_*), ordenado por
// manifest_path. El re-render no re-descubre: proyecta lo ya observado.
func extInventoryFromObs(obs []observe.Observation) []report.Ext {
	declared := map[string]int{}
	undeclared := map[string]int{}
	for _, o := range obs {
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
	var out []report.Ext
	for _, o := range obs {
		if o.Type != observe.ExtDiscovered {
			continue
		}
		var ev struct {
			Type    string   `json:"type"`
			Name    string   `json:"name"`
			Version string   `json:"version"`
			Author  string   `json:"author"`
			Roots   []string `json:"roots"`
		}
		_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
		id := ev.Name
		if id == "" {
			id = o.SubjectDisplay
		}
		out = append(out, report.Ext{
			Type:            ev.Type,
			Name:            ev.Name,
			ManifestPath:    o.SubjectDisplay,
			DeclaredVersion: strPtr(ev.Version),
			DeclaredAuthor:  strPtr(ev.Author),
			Roots:           ev.Roots,
			FilesDeclared:   declared[id],
			FilesUndeclared: undeclared[id],
			Verified:        false,
		})
	}
	return out
}

// layoutFromObs reconstruye el layout.Config resuelto (fase 2d, T5) desde las
// observaciones persistidas: layout_remap solo se emite (y persiste) cuando
// el árbol NO es estándar (scan.go: remapeado o no-resuelto), así que su
// ausencia significa "estándar" — layout.Config{} (identidad: Realize no
// transforma nada). El re-render no vuelve a recorrer el árbol (Principio
// II): reconstruye el Config completo (admin_dir/api_dir/remap_source) desde
// la evidencia de la observación, no solo Standard/AdminDirFound, para que
// tanto coverage.layout como el Realize de las rutas del informe salgan
// idénticos a los del run original.
func layoutFromObs(obs []observe.Observation) layout.Config {
	for _, o := range obs {
		if o.Type != observe.LayoutRemap {
			continue
		}
		var ev struct {
			RemapApplied  bool   `json:"remap_applied"`
			AdminDir      string `json:"admin_dir"`
			ApiDir        string `json:"api_dir"`
			RemapSource   string `json:"remap_source"`
			AdminDirFound string `json:"admin_dir_found"`
		}
		_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
		return layout.Config{
			AdminDir:              ev.AdminDir,
			ApiDir:                ev.ApiDir,
			Source:                layout.Source(ev.RemapSource),
			NonstandardUnresolved: !ev.RemapApplied,
			AdminDirFound:         ev.AdminDirFound,
		}
	}
	return layout.Config{}
}

// runReport reconstruye el informe desde las observaciones persistidas
// (FR-008/FR-040): los hallazgos son una vista derivada y regenerable
// (Principio II). Todo salvo el bloque run es reproducción determinista.
func runReport(app *App, workdir string, failOn finding.Severity, lang i18n.Lang) error {
	started := time.Now()
	dbPath, err := latestInventoryDB(workdir)
	if err != nil {
		return Exitf(ExitUsageError, "no hay inventario en %s: %v", workdir, err)
	}
	store, err := inventory.Open(dbPath)
	if err != nil {
		return Exitf(ExitInternalError, "%v", err)
	}
	defer store.Close()

	runID, err := store.LatestRun("analyze")
	if err != nil {
		return Exitf(ExitUsageError, "el inventario no contiene ningún análisis; ejecuta scan primero")
	}
	d, err := loadRunData(app, store, runID, lang)
	if err != nil {
		if errors.Is(err, finding.ErrSuppressions) {
			return Exitf(ExitUsageError, "%v", err)
		}
		return Exitf(ExitInternalError, "%v", err)
	}

	// Cobertura de la capa L6 (feature 009): las observaciones time_manipulation/
	// ctime_outlier ya están persistidas (Derive las regenera desde obs); aquí
	// solo se recomputa el resumen desde las entries, para coverage.timeline.
	// Determinista: mismas entries → mismo resumen; nowNS no afecta la
	// matemática temporal (solo sellaría observaciones descartadas).
	_, timelineSummary := timeline.Analyze(d.Entries, time.Now().UnixNano())

	cat, err := baseline.Load(app.Flags.CatalogPath)
	if err != nil {
		return Exitf(ExitInternalError, "%v", err)
	}

	var sum acquire.Summary
	codeScanned := 0
	configScanned := 0
	for _, e := range d.Entries {
		sum.Entries++
		if e.Type == "file" {
			sum.RegularFiles++
			sum.BytesTotal += e.Size
			if e.SHA256 != "" {
				sum.BytesHashed += e.Size
			}
			if isPHPExecutable(string(e.RelPath)) {
				codeScanned++
			}
			if confscan.IsConfigFile(string(e.RelPath)) {
				configScanned++
			}
		}
	}

	// Reconstruye el inventario de extensiones desde las observaciones
	// persistidas (FR-008/Principio II: regenerable sin re-analizar).
	extReport := extInventoryFromObs(d.Obs)

	layoutCfg := layoutFromObs(d.Obs)
	// coverage.database (1.11.0, feature 011) no se reconstruye aquí: el
	// resumen agregado (prefix, *_parsed, privileged_roster) no está entre las
	// observaciones persistidas, a diferencia de layoutFromObs/
	// extInventoryFromObs. Los hallazgos J0W-DB-* sí se re-derivan (Derive
	// procesa d.Obs igual que cualquier otra observación persistida); solo el
	// bloque de cobertura queda ausente en un report re-renderizado.
	sizeBySubject := sizeBySubjectMap(d.Entries)
	doc, exitCode, err := assembleReport(app, store, runID, d.Obs, d.Findings, d.Sups, d.BaseRef, cat, d.Info.TargetDisplay, sum, d.Ver, failOn, started, provenance.ThreatModel(d.Info.ThreatModel), extReport, codeScanned, configScanned, layoutCfg, timelineSummary, nil, lang, sizeBySubject, d.KnownRoots)
	if err != nil {
		return err
	}
	switch app.Flags.Format {
	case "text":
		txt, err := report.RenderText(doc)
		if err != nil {
			return Exitf(ExitInternalError, "%v", err)
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
	if exitCode == ExitOKFindings {
		return Exitf(ExitOKFindings, "hallazgos con severidad >= %s", failOn)
	}
	return nil
}

func reconstructFromObs(obs []observe.Observation) (report.Version, report.BaseRef) {
	ver := report.Version{Confidence: "low", Candidates: []report.Candidate{}}
	var baseRef report.BaseRef
	for _, o := range obs {
		switch o.Type {
		case observe.VersionInferred:
			var ev struct {
				Inferred   string `json:"inferred"`
				Declared   string `json:"declared"`
				Candidates []struct {
					Version string `json:"version"`
					Votes   int    `json:"votes"`
				} `json:"candidates"`
			}
			_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
			if ev.Inferred != "" {
				v := ev.Inferred
				ver.Inferred = &v
			}
			if ev.Declared != "" {
				d := ev.Declared
				ver.Declared = &d
			}
			for _, c := range ev.Candidates {
				ver.Candidates = append(ver.Candidates, report.Candidate{Version: c.Version, Votes: c.Votes})
			}
			ver.Confidence = string(o.Confidence)
		case observe.VersionWitnessMatch:
			ver.WitnessUsed++
		case observe.MixedVersions:
			ver.MixedVersions = true
		case observe.BaselineVerified:
			var ev struct {
				Version     string `json:"version"`
				PackageSHA  string `json:"package_sha256"`
				ManifestSHA string `json:"manifest_sha256"`
			}
			_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
			baseRef = report.BaseRef{CMS: "joomla", Version: ev.Version,
				PackageSHA256: ev.PackageSHA, ManifestSHA: ev.ManifestSHA, Source: "local-add"}
		}
	}
	return ver, baseRef
}

// latestInventoryDB localiza el almacén más reciente del workdir.
func latestInventoryDB(workdir string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(workdir, "inv-*.sqlite"))
	if err != nil || len(matches) == 0 {
		return "", os.ErrNotExist
	}
	sort.Slice(matches, func(i, j int) bool {
		fi, _ := os.Stat(matches[i])
		fj, _ := os.Stat(matches[j])
		if fi == nil || fj == nil {
			return matches[i] < matches[j]
		}
		return fi.ModTime().After(fj.ModTime())
	})
	return matches[0], nil
}
