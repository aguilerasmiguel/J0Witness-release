package cli

import (
	"github.com/spf13/cobra"

	"j0witness/internal/baseline"
	"j0witness/internal/report"
)

func newBaselineCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Gestión del catálogo y el caché de baselines",
	}
	cmd.AddCommand(newBaselineListCmd(app))
	cmd.AddCommand(newBaselineAddCmd(app))
	cmd.AddCommand(newBaselineFetchCmd(app))
	return cmd
}

func newBaselineListCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Versiones del catálogo y su estado en caché",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cat, err := baseline.Load(app.Flags.CatalogPath)
			if err != nil {
				return Exitf(ExitInternalError, "catálogo: %v", err)
			}
			store, err := openStateStore(app)
			if err != nil {
				return Exitf(ExitInternalError, "%v", err)
			}
			defer store.Close()

			type row struct {
				Version string `json:"version"`
				SHA256  string `json:"package_sha256"`
				State   string `json:"state"`
			}
			rows := []row{}
			for _, r := range cat.Releases {
				state := "not-cached"
				if _, _, _, _, err := store.FindBaseline(cat.CMS, r.Version); err == nil {
					state = "cached"
				}
				rows = append(rows, row{Version: r.Version, SHA256: r.PackageSHA256, State: state})
			}
			doc, err := report.CanonicalMarshal(map[string]any{
				"catalog_version": cat.CatalogVersion,
				"cms":             cat.CMS,
				"releases":        rows,
			})
			if err != nil {
				return Exitf(ExitInternalError, "%v", err)
			}
			_, err = app.Stdout.Write(doc)
			return err
		},
	}
}

func newBaselineAddCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "add <paquete.zip>",
		Short: "Incorpora un paquete oficial verificándolo contra el catálogo",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cat, err := baseline.Load(app.Flags.CatalogPath)
			if err != nil {
				return Exitf(ExitInternalError, "catálogo: %v", err)
			}
			store, err := openStateStore(app)
			if err != nil {
				return Exitf(ExitInternalError, "%v", err)
			}
			defer store.Close()
			version, manifestSHA, err := baseline.Add(cat, store, args[0], app.Flags.CacheDir)
			if err != nil {
				return Exitf(ExitUsageError, "%v", err)
			}
			app.Progress("baseline añadido: %s (manifiesto %s)", version, manifestSHA)
			doc, _ := report.CanonicalMarshal(map[string]any{"added": version, "manifest_sha256": manifestSHA})
			_, err = app.Stdout.Write(doc)
			return err
		},
	}
}

func newBaselineFetchCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "fetch <version>",
		Short: "Descarga y verifica un baseline (requiere --allow-network)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cat, err := baseline.Load(app.Flags.CatalogPath)
			if err != nil {
				return Exitf(ExitInternalError, "catálogo: %v", err)
			}
			rel, ok := cat.FindRelease(args[0])
			if !ok {
				return Exitf(ExitVersionUnsupported, "la versión %s no está en el catálogo", args[0])
			}
			if !app.Flags.AllowNetwork {
				// Principio VIII: sin autorización explícita el cliente de
				// red ni siquiera se construye.
				return Exitf(ExitBaselineUnavailable,
					"la red no está autorizada. Obtén %s manualmente (sha256 %s) y usa: j0witness baseline add <paquete>; o reejecuta con --allow-network",
					args[0], rel.PackageSHA256)
			}
			store, err := openStateStore(app)
			if err != nil {
				return Exitf(ExitInternalError, "%v", err)
			}
			defer store.Close()
			version, manifestSHA, err := baseline.Fetch(app.Stderr, cat, store, rel, app.Flags.CacheDir)
			if err != nil {
				return Exitf(ExitBaselineUnavailable, "%v", err)
			}
			doc, _ := report.CanonicalMarshal(map[string]any{"fetched": version, "manifest_sha256": manifestSHA})
			_, err = app.Stdout.Write(doc)
			return err
		},
	}
}
