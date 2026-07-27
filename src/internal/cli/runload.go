package cli

import (
	"j0witness/internal/baseline"
	"j0witness/internal/finding"
	"j0witness/internal/i18n"
	"j0witness/internal/inventory"
	"j0witness/internal/observe"
	"j0witness/internal/report"
)

// runData agrupa todo lo re-derivado de un run persistido: observaciones,
// entradas, hallazgos regenerados y los metadatos necesarios para ensamblar
// un informe. Es la unidad que comparten `report` y (feature 002) `diff`.
type runData struct {
	Info       inventory.RunInfo
	Entries    []inventory.Entry
	Obs        []observe.Observation
	Findings   []finding.Finding
	Sups       []*finding.Suppression
	Ver        report.Version
	BaseRef    report.BaseRef
	KnownRoots map[string]bool
}

// loadRunData carga un run persistido y re-deriva sus hallazgos, sin
// re-recorrer el árbol (Principio II): observaciones + entradas desde el
// inventario, versión/baseRef reconstruidos desde las observaciones, el
// conjunto idéntico-al-baseline desde el almacén de estado compartido, y los
// hallazgos derivados con las supresiones vigentes aplicadas.
func loadRunData(app *App, store *inventory.Store, runID int64, lang i18n.Lang) (runData, error) {
	var d runData
	var err error
	if d.Info, err = store.Run(runID); err != nil {
		return d, err
	}
	if d.Obs, err = store.ObservationsByRun(runID); err != nil {
		return d, err
	}
	if d.Entries, err = store.EntriesByRun(runID); err != nil {
		return d, err
	}
	d.Ver, d.BaseRef = reconstructFromObs(d.Obs)
	version := d.BaseRef.Version
	if version == "" && d.Ver.Inferred != nil {
		version = *d.Ver.Inferred
	}
	identical := map[string]bool{}
	if version != "" {
		if state, err := openStateStore(app); err == nil {
			if manifest, err := baseline.Manifest(state, "joomla", version); err == nil {
				identical = identicalSet(d.Entries, manifest)
				// KnownRoots (feature 012 refinamiento): mismo manifiesto ya
				// resuelto para `identical`, reusado para distinguir en
				// coverage.foreign_roots una raíz genuinamente ajena de un dir
				// ESTÁNDAR de Joomla con contenido de usuario. Sin
				// versión/manifiesto resuelto queda nil — fallback seguro:
				// todas las raíces se marcan distribution_dir=false.
				d.KnownRoots = knownRootsFromManifest(manifest)
			}
			state.Close()
		}
	}
	d.Findings = finding.Derive(d.Obs, version, identical, lang)
	if d.Sups, err = finding.LoadSuppressions(app.Flags.Exclusions); err != nil {
		return d, err
	}
	d.Findings = finding.Apply(d.Findings, d.Sups)
	return d, nil
}
