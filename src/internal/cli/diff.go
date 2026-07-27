package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"j0witness/internal/drift"
	"j0witness/internal/finding"
	"j0witness/internal/i18n"
	"j0witness/internal/inventory"
)

// invDBPath deriva la ruta del store SQLite del workdir para un objetivo ya
// resuelto a su forma canónica (mismo naming que openRun: "inv-" +
// hex(sha256(target)[:4])). openRun la llama con targetRoot, que ya es
// filepath.Abs (safefs.New lo garantiza); `runs`/`diff` reciben el argumento
// crudo de la CLI y deben resolverlo con filepath.Abs ANTES de llamar aquí,
// para hashear exactamente lo mismo que produjo el store durante `scan`.
func invDBPath(app *App, targetRoot string) string {
	h := sha256.Sum256([]byte(targetRoot))
	return filepath.Join(app.Flags.Workdir, "inv-"+hex.EncodeToString(h[:4])+".sqlite")
}

// newRunsCmd lista los runs de análisis persistidos para un objetivo, sin
// abrir el árbol (Principio I/IX: solo lee el store SQLite del workdir).
func newRunsCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "runs <objetivo>",
		Short: "Lista los runs de análisis persistidos para un objetivo",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRuns(app, args[0])
		},
	}
	return cmd
}

func runRuns(app *App, target string) error {
	abs, err := filepath.Abs(target)
	if err != nil {
		return Exitf(ExitUsageError, "%v", err)
	}
	store, err := inventory.Open(invDBPath(app, abs))
	if err != nil {
		return Exitf(ExitUsageError, "no hay inventario para %s: %v", target, err)
	}
	defer store.Close()

	runs, err := store.ListRuns("analyze")
	if err != nil {
		return Exitf(ExitInternalError, "%v", err)
	}
	for _, r := range runs {
		finished := time.Unix(0, r.FinishedAtNS).UTC().Format(time.RFC3339)
		fmt.Fprintf(app.Stdout, "%d\t%s\t%s\n", r.ID, finished, r.TargetDisplay)
	}
	return nil
}

// newDiffCmd deriva la deriva scan-a-scan entre dos runs del MISMO objetivo
// (feature 002): modo monitorización (un objetivo, --from/--to o los dos
// runs más recientes) o modo IR (--old/--new: dos stores SQLite distintos,
// cada uno con su propio run más reciente).
func newDiffCmd(app *App) *cobra.Command {
	var fromID, toID int64
	var oldPath, newPath string
	var languageFlag string
	var formatFlag string
	cmd := &cobra.Command{
		Use:   "diff [objetivo]",
		Short: "Deriva scan-a-scan: qué cambió entre dos runs del mismo objetivo",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lang, err := i18n.Parse(languageFlag)
			if err != nil {
				return Exitf(ExitUsageError, "%v", err)
			}
			var target string
			if len(args) == 1 {
				target = args[0]
			}
			return runDiff(app, target, oldPath, newPath, fromID, toID, formatFlag, lang)
		},
	}
	cmd.Flags().Int64Var(&fromID, "from", 0, "run id del lado antiguo (monitorización; requiere <objetivo>)")
	cmd.Flags().Int64Var(&toID, "to", 0, "run id del lado nuevo (monitorización; requiere <objetivo>)")
	cmd.Flags().StringVar(&oldPath, "old", "", "ruta al store SQLite antiguo (modo IR)")
	cmd.Flags().StringVar(&newPath, "new", "", "ruta al store SQLite nuevo (modo IR)")
	// --format local a `diff` (sombrea el --format persistente de la raíz,
	// que es json|text|pdf|sarif para `scan`/`report`): la deriva solo tiene
	// dos proyecciones (json/text) y su default es text, no json.
	cmd.Flags().StringVar(&formatFlag, "format", "text", "formato de salida: json|text")
	cmd.Flags().StringVar(&languageFlag, "language", "es", "idioma de re-derivación de hallazgos: es|en")
	return cmd
}

func runDiff(app *App, target, oldPath, newPath string, fromID, toID int64, format string, lang i18n.Lang) error {
	var storeOld, storeNew *inventory.Store
	var runOld, runNew int64

	switch {
	case oldPath != "" && newPath != "":
		var err error
		storeOld, err = inventory.Open(oldPath)
		if err != nil {
			return Exitf(ExitUsageError, "--old %s: %v", oldPath, err)
		}
		defer storeOld.Close()
		if runOld, err = storeOld.LatestRun("analyze"); err != nil {
			return Exitf(ExitUsageError, "--old %s no contiene ningún análisis: %v", oldPath, err)
		}
		storeNew, err = inventory.Open(newPath)
		if err != nil {
			return Exitf(ExitUsageError, "--new %s: %v", newPath, err)
		}
		defer storeNew.Close()
		if runNew, err = storeNew.LatestRun("analyze"); err != nil {
			return Exitf(ExitUsageError, "--new %s no contiene ningún análisis: %v", newPath, err)
		}
	case oldPath != "" || newPath != "":
		return Exitf(ExitUsageError, "--old y --new deben usarse juntos")
	default:
		if target == "" {
			return Exitf(ExitUsageError, "requiere <objetivo>, o --old y --new")
		}
		abs, err := filepath.Abs(target)
		if err != nil {
			return Exitf(ExitUsageError, "%v", err)
		}
		store, err := inventory.Open(invDBPath(app, abs))
		if err != nil {
			return Exitf(ExitUsageError, "no hay inventario para %s: %v", target, err)
		}
		defer store.Close()
		storeOld, storeNew = store, store

		switch {
		case fromID != 0 && toID != 0:
			runOld, runNew = fromID, toID
		case fromID != 0 || toID != 0:
			return Exitf(ExitUsageError, "--from y --to deben usarse juntos")
		default:
			runs, err := store.ListRuns("analyze")
			if err != nil {
				return Exitf(ExitInternalError, "%v", err)
			}
			if len(runs) < 2 {
				return Exitf(ExitUsageError, "se necesitan al menos 2 runs de análisis para %s; hay %d", target, len(runs))
			}
			runOld = runs[len(runs)-2].ID
			runNew = runs[len(runs)-1].ID
		}
	}

	dOld, err := loadRunData(app, storeOld, runOld, lang)
	if err != nil {
		return diffLoadError(err, "run antiguo", runOld)
	}
	dNew, err := loadRunData(app, storeNew, runNew, lang)
	if err != nil {
		return diffLoadError(err, "run nuevo", runNew)
	}

	dr, err := drift.Compare(toSnapshot(dOld), toSnapshot(dNew))
	if err != nil {
		return Exitf(ExitUsageError, "%v", err)
	}

	var out []byte
	switch format {
	case "json":
		out, err = dr.RenderJSON()
	default:
		out, err = dr.RenderText()
	}
	if err != nil {
		return Exitf(ExitInternalError, "%v", err)
	}
	if _, err := app.Stdout.Write(out); err != nil {
		return Exitf(ExitInternalError, "%v", err)
	}
	if dr.ExitCode() == int(ExitOKFindings) {
		return Exitf(ExitOKFindings, "hallazgos nuevos entre run %d y run %d", runOld, runNew)
	}
	return nil
}

// diffLoadError distingue el error de exclusiones inválidas (usuario) de
// cualquier otro fallo re-derivando un run (interno), igual que runReport.
func diffLoadError(err error, side string, runID int64) error {
	if errors.Is(err, finding.ErrSuppressions) {
		return Exitf(ExitUsageError, "%s (run %d): %v", side, runID, err)
	}
	return Exitf(ExitInternalError, "%s (run %d): %v", side, runID, err)
}

// toSnapshot mapea el runData re-derivado (Task 1) al drift.Snapshot que
// Compare consume: Ref sale de Info+BaseRef (la versión de baseline
// reconstruida, no Ver.Inferred — es la salvedad de actualización de core,
// FR de diseño §7), Entries y Findings se pasan tal cual (ya re-derivados y
// con supresiones aplicadas).
func toSnapshot(d runData) drift.Snapshot {
	return drift.Snapshot{
		Ref: drift.RunRef{
			RunID:           d.Info.ID,
			Target:          d.Info.TargetDisplay,
			FinishedAt:      time.Unix(0, d.Info.FinishedAtNS).UTC().Format(time.RFC3339),
			ToolVersion:     d.Info.ToolVersion,
			BaselineVersion: d.BaseRef.Version,
		},
		Entries:  d.Entries,
		Findings: d.Findings,
	}
}
