// Package drift compara dos snapshots persistidos (runs) del MISMO objetivo y
// reporta qué cambió entre ellos: entries añadidas/eliminadas/modificadas/
// movidas y hallazgos nuevos/resueltos. Es la capa de monitorización/IR:
// "¿qué cambió en ESTE sitio entre entonces y ahora?" — complementa (no
// reemplaza) el diff L2 contra el baseline del fabricante.
//
// Compare es una función pura y determinista (Principio IV): solo lee los dos
// Snapshots en memoria, nunca toca el árbol ni escribe nada (Principio I/IX).
// El pase de movimiento es inequívoco-1:1 — nunca adivina emparejamientos.
package drift

import (
	"fmt"
	"sort"

	"j0witness/internal/corediff"
	"j0witness/internal/finding"
	"j0witness/internal/inventory"
)

// SchemaVersion es el contrato del DriftReport (independiente del
// schema_version del informe L0-L4; ver contracts/drift.schema.json).
const SchemaVersion = "1.0.0"

// RunRef identifica el run persistido del que procede un lado del Snapshot.
type RunRef struct {
	RunID           int64  `json:"run_id"`
	Target          string `json:"target"`
	FinishedAt      string `json:"finished_at"`
	ToolVersion     string `json:"tool_version"`
	BaselineVersion string `json:"baseline_version,omitempty"`
}

// Snapshot es el estado comparable de un run: sus entries persistidas más sus
// hallazgos RE-DERIVADOS desde sus observaciones (Principio II) — los
// hallazgos nunca se almacenan como verdad primaria, así que cada lado del
// diff los reconstruye desde cero antes de llegar a Compare.
type Snapshot struct {
	Ref      RunRef
	Entries  []inventory.Entry
	Findings []finding.Finding
}

// EntryChange describe el cambio de UNA ruta entre dos snapshots. Los campos
// usados dependen del cubo: OldPath solo en moved; Old/NewSHA256 en
// added/removed/changed/moved; MtimeDelta/CtimeDelta/Executable en changed
// (ver Compare).
type EntryChange struct {
	Path       string `json:"path"`
	OldPath    string `json:"old_path,omitempty"` // solo moved
	OldSHA256  string `json:"old_sha256,omitempty"`
	NewSHA256  string `json:"new_sha256,omitempty"`
	MtimeDelta int64  `json:"mtime_delta_ns,omitempty"` // changed: new-old
	CtimeDelta int64  `json:"ctime_delta_ns,omitempty"`
	Executable bool   `json:"executable,omitempty"` // ejecutable PHP (señal)
}

// FindingChange es un hallazgo re-derivado presente en un solo lado del diff.
type FindingChange struct {
	ID       string `json:"id"`
	RuleID   string `json:"rule_id"`
	Subject  string `json:"subject"`
	Severity string `json:"severity"`
}

// DriftReport es el resultado de comparar dos snapshots del MISMO objetivo.
// Todas las listas van ordenadas por Path (findings por Subject,ID) de forma
// determinista — nunca reflejan orden de iteración de mapa.
type DriftReport struct {
	SchemaVersion string `json:"schema_version"`
	Old           RunRef `json:"old"`
	New           RunRef `json:"new"`
	Entries       struct {
		Added           []EntryChange `json:"added"`
		Removed         []EntryChange `json:"removed"`
		Changed         []EntryChange `json:"changed"`
		Moved           []EntryChange `json:"moved"`
		MetadataChanged []EntryChange `json:"metadata_changed"`
		RuntimeChurn    int           `json:"runtime_churn"`
	} `json:"entries"`
	Findings struct {
		New        []FindingChange `json:"new"`
		Resolved   []FindingChange `json:"resolved"`
		Persistent int             `json:"persistent"`
	} `json:"findings"`
	Caveats []string     `json:"caveats"`
	Summary DriftSummary `json:"summary"`
}

// DriftSummary resume el DriftReport en recuentos. Sin omitempty a propósito:
// los ceros deben aparecer (un resumen con campos ausentes es ambiguo).
type DriftSummary struct {
	Added            int `json:"added"`
	Removed          int `json:"removed"`
	Changed          int `json:"changed"`
	Moved            int `json:"moved"`
	MetadataChanged  int `json:"metadata_changed"`
	RuntimeChurn     int `json:"runtime_churn"`
	NewFindings      int `json:"new_findings"`
	ResolvedFindings int `json:"resolved_findings"`
}

// Compare compara old contra new (mismo objetivo). Algoritmo:
//  1. Guarda de objetivo: targets distintos → error.
//  2. Indexa entries de tipo "file" por PathDisplay en ambos lados; las que
//     caen bajo un directorio de escritura conocido (corediff.IsWritablePath)
//     se cuentan en RuntimeChurn y NUNCA entran en las listas.
//  3. added/removed/changed(sha distinto)/metadata_changed(mismo sha, mode/
//     uid/timestamps distintos) por comparación directa de rutas.
//  4. Pase de movimiento: un sha con EXACTAMENTE 1 removed y 1 added se
//     colapsa a moved; sha ambiguo (>1 a cualquier lado) se queda en add/
//     remove tal cual.
//  5. Hallazgos por ID: new/resolved/persistent (contado, no listado).
//  6. Todo ordenado antes de devolver.
//  7. Salvedad si difiere BaselineVersion (una actualización de core es deriva
//     masiva esperada, se declara, no se silencia).
func Compare(old, new Snapshot) (DriftReport, error) {
	if old.Ref.Target != new.Ref.Target {
		return DriftReport{}, fmt.Errorf("objetivos distintos: %q vs %q", old.Ref.Target, new.Ref.Target)
	}

	oldByPath := indexFiles(old.Entries)
	newByPath := indexFiles(new.Entries)

	added := []EntryChange{}
	changed := []EntryChange{}
	metaChanged := []EntryChange{}
	runtimeChurn := 0

	for path, ne := range newByPath {
		writable := corediff.IsWritablePath(path)
		oe, existed := oldByPath[path]
		switch {
		case !existed:
			if writable {
				runtimeChurn++
				continue
			}
			added = append(added, EntryChange{Path: path, NewSHA256: ne.SHA256})
		case oe.SHA256 != ne.SHA256:
			if writable {
				runtimeChurn++
				continue
			}
			changed = append(changed, EntryChange{
				Path:       path,
				OldSHA256:  oe.SHA256,
				NewSHA256:  ne.SHA256,
				MtimeDelta: ne.MtimeNS - oe.MtimeNS,
				CtimeDelta: ne.CtimeNS - oe.CtimeNS,
				Executable: corediff.IsExecutable(path),
			})
		case oe.Mode != ne.Mode || oe.UID != ne.UID || oe.MtimeNS != ne.MtimeNS || oe.CtimeNS != ne.CtimeNS:
			if writable {
				runtimeChurn++
				continue
			}
			metaChanged = append(metaChanged, EntryChange{
				Path:       path,
				OldSHA256:  oe.SHA256,
				NewSHA256:  ne.SHA256,
				MtimeDelta: ne.MtimeNS - oe.MtimeNS,
				CtimeDelta: ne.CtimeNS - oe.CtimeNS,
			})
		}
	}

	removed := []EntryChange{}
	for path, oe := range oldByPath {
		if _, existed := newByPath[path]; existed {
			continue // ya tratado arriba (added/changed/metadata_changed/sin cambio)
		}
		if corediff.IsWritablePath(path) {
			runtimeChurn++
			continue
		}
		removed = append(removed, EntryChange{Path: path, OldSHA256: oe.SHA256})
	}

	added, removed, moved := collapseMoves(added, removed)

	sortEntries(added)
	sortEntries(removed)
	sortEntries(changed)
	sortEntries(metaChanged)
	sortEntries(moved)

	newByID := make(map[string]finding.Finding, len(new.Findings))
	for _, f := range new.Findings {
		newByID[f.ID] = f
	}
	oldByID := make(map[string]finding.Finding, len(old.Findings))
	for _, f := range old.Findings {
		oldByID[f.ID] = f
	}

	newFindings := []FindingChange{}
	persistent := 0
	for id, f := range newByID {
		if _, ok := oldByID[id]; ok {
			persistent++
			continue
		}
		newFindings = append(newFindings, toFindingChange(f))
	}
	resolvedFindings := []FindingChange{}
	for id, f := range oldByID {
		if _, ok := newByID[id]; !ok {
			resolvedFindings = append(resolvedFindings, toFindingChange(f))
		}
	}
	sortFindings(newFindings)
	sortFindings(resolvedFindings)

	caveats := []string{}
	if old.Ref.BaselineVersion != new.Ref.BaselineVersion {
		caveats = append(caveats, fmt.Sprintf(
			"las versiones de baseline difieren (%s→%s): una actualización muestra deriva masiva del core, esperada",
			old.Ref.BaselineVersion, new.Ref.BaselineVersion))
	}

	var d DriftReport
	d.SchemaVersion = SchemaVersion
	d.Old = old.Ref
	d.New = new.Ref
	d.Entries.Added = added
	d.Entries.Removed = removed
	d.Entries.Changed = changed
	d.Entries.Moved = moved
	d.Entries.MetadataChanged = metaChanged
	d.Entries.RuntimeChurn = runtimeChurn
	d.Findings.New = newFindings
	d.Findings.Resolved = resolvedFindings
	d.Findings.Persistent = persistent
	d.Caveats = caveats
	d.Summary = DriftSummary{
		Added:            len(added),
		Removed:          len(removed),
		Changed:          len(changed),
		Moved:            len(moved),
		MetadataChanged:  len(metaChanged),
		RuntimeChurn:     runtimeChurn,
		NewFindings:      len(newFindings),
		ResolvedFindings: len(resolvedFindings),
	}
	return d, nil
}

// indexFiles indexa las entries de tipo "file" por PathDisplay; dirs,
// symlinks y "other" quedan fuera del diff de entries (fuera del ámbito de
// Compare — el join es sobre archivos).
func indexFiles(entries []inventory.Entry) map[string]inventory.Entry {
	m := make(map[string]inventory.Entry, len(entries))
	for _, e := range entries {
		if e.Type != "file" {
			continue
		}
		m[e.PathDisplay] = e
	}
	return m
}

// collapseMoves agrupa added/removed por SHA256; un sha con EXACTAMENTE 1
// removed y 1 added se colapsa a moved (par old→new). Shas con conteo
// ambiguo (>1 a cualquier lado, p.ej. archivos idénticos/vacíos) NO se
// reclaman como movimiento y se quedan en add/remove — determinista, nunca
// adivina emparejamientos (Principio IV).
func collapseMoves(added, removed []EntryChange) (addedOut, removedOut, moved []EntryChange) {
	removedBySHA := map[string][]int{}
	for i, e := range removed {
		removedBySHA[e.OldSHA256] = append(removedBySHA[e.OldSHA256], i)
	}
	addedBySHA := map[string][]int{}
	for i, e := range added {
		addedBySHA[e.NewSHA256] = append(addedBySHA[e.NewSHA256], i)
	}

	removedSkip := map[int]bool{}
	addedSkip := map[int]bool{}
	for sha, rIdxs := range removedBySHA {
		aIdxs, ok := addedBySHA[sha]
		if !ok || len(rIdxs) != 1 || len(aIdxs) != 1 {
			continue
		}
		r := removed[rIdxs[0]]
		a := added[aIdxs[0]]
		moved = append(moved, EntryChange{
			Path:      a.Path,
			OldPath:   r.Path,
			OldSHA256: sha,
			NewSHA256: sha,
		})
		removedSkip[rIdxs[0]] = true
		addedSkip[aIdxs[0]] = true
	}

	addedOut = []EntryChange{}
	for i, e := range added {
		if !addedSkip[i] {
			addedOut = append(addedOut, e)
		}
	}
	removedOut = []EntryChange{}
	for i, e := range removed {
		if !removedSkip[i] {
			removedOut = append(removedOut, e)
		}
	}
	if moved == nil {
		moved = []EntryChange{}
	}
	return addedOut, removedOut, moved
}

func sortEntries(es []EntryChange) {
	sort.Slice(es, func(i, j int) bool { return es[i].Path < es[j].Path })
}

func toFindingChange(f finding.Finding) FindingChange {
	return FindingChange{ID: f.ID, RuleID: f.RuleID, Subject: f.Subject, Severity: string(f.Severity)}
}

// sortFindings ordena por Subject (el análogo de Path para un hallazgo) y
// luego por ID como desempate determinista.
func sortFindings(fs []FindingChange) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Subject != fs[j].Subject {
			return fs[i].Subject < fs[j].Subject
		}
		return fs[i].ID < fs[j].ID
	})
}
