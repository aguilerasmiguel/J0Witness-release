package acquire

import (
	"encoding/hex"
	"time"

	"j0witness/internal/inventory"
	"j0witness/internal/observe"
	"j0witness/internal/safefs"
)

// Options configura la pasada L0.
type Options struct {
	Jobs           int
	FuzzyThreshold int64
	Progress       func(phase string, done, total int)
	// Canonicalize reescribe la ruta real de una entrada a su forma
	// canónica (p.ej. "adm1ng/…" -> "administrator/…") antes de
	// persistirla y de usarla como subject de las observaciones. nil
	// equivale a la identidad (sin remap): una instalación estándar
	// produce exactamente las mismas rutas que hoy.
	Canonicalize func(rel string) string
}

// Summary resume la adquisición para el bloque coverage del informe.
type Summary struct {
	Entries      int
	RegularFiles int
	BytesTotal   int64
	BytesHashed  int64
	ReadErrors   int
}

// Run ejecuta L0 completo: recorrido único, hashes, tipo real, persistencia
// de entradas y observaciones (FR-001…FR-008). Devuelve el resumen.
func Run(fsys *safefs.FS, store *inventory.Store, runID int64, opts Options) (Summary, error) {
	nowNS := time.Now().UnixNano()
	progress := opts.Progress
	if progress == nil {
		progress = func(string, int, int) {}
	}

	items := Walk(fsys)
	progress("walk", len(items), len(items))

	hashes := HashFiles(fsys, items, opts.Jobs, opts.FuzzyThreshold)
	progress("hash", len(hashes), len(hashes))

	canon := opts.Canonicalize
	if canon == nil {
		canon = func(s string) string { return s }
	}

	// WalkObservations toma subjects de it.RelPath: para que sus
	// observaciones (ReadDenied/SymlinkOutOfTree/HardlinkCycle/NonUTF8Path)
	// respeten el invariante de consistencia interna (subject canónico,
	// igual que la Entry persistida para el mismo archivo), se le pasa una
	// copia de items con RelPath ya canonicalizado. El lookup de hashes y
	// el resto del pipeline de abajo siguen usando `items` (rutas reales).
	citems := make([]Item, len(items))
	for i, it := range items {
		citems[i] = it
		citems[i].RelPath = canon(it.RelPath)
	}

	var sum Summary
	entries := make([]inventory.Entry, 0, len(items))
	obs := WalkObservations(citems, nowNS)

	addObs := func(o observe.Observation, err error) {
		if err == nil {
			obs = append(obs, o)
		}
	}

	for _, it := range items {
		sum.Entries++
		crel := canon(it.RelPath)
		e := inventory.Entry{
			RelPath:       []byte(crel),
			PathDisplay:   observe.DisplayPath([]byte(crel)),
			Type:          it.Type,
			Size:          it.Size,
			MtimeNS:       it.MtimeNS,
			CtimeNS:       it.CtimeNS,
			AtimeNS:       it.AtimeNS,
			UID:           it.UID,
			GID:           it.GID,
			Mode:          it.Mode,
			Inode:         it.Inode,
			Nlink:         it.Nlink,
			SymlinkTarget: []byte(it.SymlinkTarget),
			ReadError:     it.ReadError,
		}
		if it.ReadError != "" {
			sum.ReadErrors++
		}
		if it.Type == "file" {
			sum.RegularFiles++
			sum.BytesTotal += it.Size
			if r, ok := hashes[it.RelPath]; ok {
				e.SHA256 = r.SHA256
				e.TLSH = r.TLSH
				e.MagicType = r.MagicType
				e.ExtType = r.ExtType
				sum.BytesHashed += r.BytesHashed
				if r.ReadError != "" {
					e.ReadError = r.ReadError
					sum.ReadErrors++
					addObs(observe.New(e.RelPath, observe.ReadDenied,
						map[string]any{"reason": r.ReadError, "stage": "hash"},
						observe.SrcAcquire, observe.High, nowNS))
				} else {
					addObs(observe.New(e.RelPath, observe.EntryHashed,
						map[string]any{"sha256": r.SHA256, "tlsh": r.TLSH, "magic": r.MagicType},
						observe.SrcAcquire, observe.High, nowNS))
				}
				if r.TLSHSkipped != "" && r.ReadError == "" {
					addObs(observe.New(e.RelPath, observe.FuzzyHashSkipped,
						map[string]any{"reason": r.TLSHSkipped, "size": it.Size},
						observe.SrcAcquire, observe.High, nowNS))
				}
				if r.MagicMismatch() {
					addObs(observe.New(e.RelPath, observe.TypeMismatch,
						map[string]any{"magic": r.MagicType, "expected_for_extension": r.ExtType},
						observe.SrcAcquire, observe.High, nowNS))
				}
			}
		}
		entries = append(entries, e)
	}

	if err := store.InsertEntries(runID, entries); err != nil {
		return sum, err
	}
	if _, err := store.InsertObservations(runID, obs); err != nil {
		return sum, err
	}
	progress("persist", len(entries), len(entries))
	return sum, nil
}

// ToolHashHex es un helper para tests.
func ToolHashHex(b []byte) string { return hex.EncodeToString(b) }
