// Package fingerprint implementa L1: inferencia de la versión real por
// evidencia de contenido de archivos testigo, independiente de lo que la
// instalación declare (FR-010…FR-014).
package fingerprint

import (
	"j0witness/internal/baseline"
	"j0witness/internal/inventory"
	"j0witness/internal/observe"
)

// WitnessMatch registra qué versión respalda cada testigo legible.
type WitnessMatch struct {
	Path     string
	Branches []string // ramas que lo seleccionaron; vacío = cualquiera
	Versions []string // versiones cuyo hash de catálogo coincide
	Readable bool
}

// EvaluateWitnesses cruza el conjunto testigo del catálogo con el inventario
// ya adquirido (se consulta el inventario, no el filesystem).
func EvaluateWitnesses(cat *baseline.Catalog, entries []inventory.Entry) []WitnessMatch {
	bySHA := map[string]string{}
	present := map[string]bool{}
	for _, e := range entries {
		if e.Type == "file" {
			present[string(e.RelPath)] = e.ReadError == ""
			if e.SHA256 != "" {
				bySHA[string(e.RelPath)] = e.SHA256
			}
		}
	}
	out := make([]WitnessMatch, 0, len(cat.Witnesses))
	for _, w := range cat.Witnesses {
		m := WitnessMatch{
			Path:     w.Path,
			Branches: w.Branches,
			Readable: present[w.Path] && bySHA[w.Path] != "",
		}
		if m.Readable {
			sha := bySHA[w.Path]
			for version, wantSHA := range w.Hashes {
				if sha == wantSHA {
					m.Versions = append(m.Versions, version)
				}
			}
		}
		out = append(out, m)
	}
	return out
}

// WitnessObservations emite una observación por testigo con coincidencia.
func WitnessObservations(matches []WitnessMatch, nowNS int64) []observe.Observation {
	var obs []observe.Observation
	for _, m := range matches {
		if len(m.Versions) == 0 {
			continue
		}
		if o, err := observe.New([]byte(m.Path), observe.VersionWitnessMatch,
			map[string]any{"versions": m.Versions}, observe.SrcFingerprint, observe.High, nowNS); err == nil {
			obs = append(obs, o)
		}
	}
	return obs
}
