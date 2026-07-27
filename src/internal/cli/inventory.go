package cli

import (
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"j0witness/internal/acquire"
	"j0witness/internal/inventory"
	"j0witness/internal/report"
	"j0witness/internal/safefs"
)

func newInventoryCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "inventory <ruta>",
		Short: "Solo L0: recorre, captura y persiste el inventario",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			if err := safefs.Preflight(target, app.Flags.Workdir, app.Flags.CacheDir); err != nil {
				return Exitf(ExitPreflightFailed, "%v", err)
			}
			fsys, err := safefs.New(target)
			if err != nil {
				return Exitf(ExitPreflightFailed, "%v", err)
			}
			store, runID, err := openRun(app, "inventory", fsys.Root)
			if err != nil {
				return Exitf(ExitInternalError, "%v", err)
			}
			defer store.Close()
			sum, err := acquire.Run(fsys, store, runID, acquire.Options{
				Jobs:           app.Flags.Jobs,
				FuzzyThreshold: app.Flags.FuzzyThreshold,
				Progress: func(phase string, done, total int) {
					app.Progress("phase=acquire step=%s done=%d total=%d", phase, done, total)
				},
			})
			if err != nil {
				return Exitf(ExitInternalError, "adquisición: %v", err)
			}
			_ = store.FinishRun(runID, time.Now().UnixNano())
			doc, err := report.CanonicalMarshal(map[string]any{
				"store":         store.Path,
				"run_id":        runID,
				"entries":       sum.Entries,
				"files_regular": sum.RegularFiles,
				"bytes_total":   sum.BytesTotal,
				"read_errors":   sum.ReadErrors,
			})
			if err != nil {
				return Exitf(ExitInternalError, "%v", err)
			}
			_, err = app.Stdout.Write(doc)
			return err
		},
	}
}

// openStateStore abre el almacén compartido del workdir para comandos que no
// están ligados a un objetivo (baseline list/add/fetch).
func openStateStore(app *App) (*inventory.Store, error) {
	return inventory.Open(filepath.Join(app.Flags.Workdir, "state.sqlite"))
}
