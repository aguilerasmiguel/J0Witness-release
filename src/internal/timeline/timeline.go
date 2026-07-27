// Package timeline analiza los metadatos temporales ya capturados (ctime/mtime
// por entry) sin tocar el árbol (Principio IX). Bajo el modelo primario el ctime
// es el ancla fiable; el mtime es controlable por el atacante. Determinista: la
// matemática temporal no consulta el reloj (nowNS solo sella las observaciones).
package timeline

import (
	"sort"

	"j0witness/internal/inventory"
	"j0witness/internal/observe"
	"j0witness/internal/provenance"
)

const (
	nsPerDay          = int64(24) * 60 * 60 * 1_000_000_000
	gapThresholdNS    = int64(30) * nsPerDay
	minFilesForCohort = 20
	maxOutlierFrac    = 0.05
)

// TimelineSummary alimenta coverage.timeline (Principio VII).
type TimelineSummary struct {
	CohortEarliestNS  int64
	CohortLatestNS    int64
	TotalFiles        int
	OutlierCount      int
	ManipulationCount int
}

// Analyze emite time_manipulation (mtime>ctime) y ctime_outlier (ctime tras un
// hueco grande respecto a la cohorte, cola pequeña) + un resumen.
func Analyze(entries []inventory.Entry, nowNS int64) ([]observe.Observation, TimelineSummary) {
	var obs []observe.Observation
	var sum TimelineSummary

	// (1) manipulación: mtime > ctime + slack, por archivo (fuente única; la
	// degradación global consumirá estas observaciones).
	for _, e := range entries {
		if e.Type != "file" {
			continue
		}
		if provenance.TimestampAnomaly(e.MtimeNS, e.CtimeNS) {
			ev := map[string]any{"mtime_ns": e.MtimeNS, "ctime_ns": e.CtimeNS, "delta_ns": e.MtimeNS - e.CtimeNS}
			// confianza High: el HECHO (mtime>ctime) es cierto; la incertidumbre
			// de interpretación (timestomping vs desajuste) vive en la severidad
			// Low + la hipótesis alternativa del hallazgo.
			if o, err := observe.New(e.RelPath, observe.TimeManipulation, ev, observe.SrcTimeline, observe.High, nowNS); err == nil {
				obs = append(obs, o)
				sum.ManipulationCount++
			}
		}
	}

	// (2) outliers de ctime: cohorte por hueco.
	type fentry struct {
		rel   []byte
		ctime int64
	}
	var fs []fentry
	for _, e := range entries {
		if e.Type == "file" {
			fs = append(fs, fentry{e.RelPath, e.CtimeNS})
		}
	}
	sum.TotalFiles = len(fs)
	if len(fs) == 0 {
		return obs, sum
	}
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].ctime != fs[j].ctime {
			return fs[i].ctime < fs[j].ctime
		}
		return string(fs[i].rel) < string(fs[j].rel) // desempate estable
	})
	sum.CohortEarliestNS = fs[0].ctime
	sum.CohortLatestNS = fs[len(fs)-1].ctime
	if len(fs) < minFilesForCohort {
		return obs, sum // pocos archivos: no se define cohorte
	}
	// Halla el hueco MÁS RECIENTE > umbral cuya cola (archivos por encima) sea
	// pequeña (≤ maxOutlierFrac): esos son outliers plantados-tarde. Un hueco con
	// cola grande es un update masivo → NO outliers.
	cut := -1
	for i := len(fs) - 1; i >= 1; i-- {
		if fs[i].ctime-fs[i-1].ctime > gapThresholdNS {
			tail := len(fs) - i
			if float64(tail) <= maxOutlierFrac*float64(len(fs)) {
				cut = i
			}
			break // solo el hueco más reciente
		}
	}
	if cut < 0 {
		return obs, sum
	}
	cohortUpper := fs[cut-1].ctime
	sum.CohortLatestNS = cohortUpper
	for _, f := range fs[cut:] {
		days := (f.ctime - cohortUpper) / nsPerDay
		ev := map[string]any{"ctime_ns": f.ctime, "days_after_cohort": days}
		if o, err := observe.New(f.rel, observe.CtimeOutlier, ev, observe.SrcTimeline, observe.Low, nowNS); err == nil {
			obs = append(obs, o)
			sum.OutlierCount++
		}
	}
	return obs, sum
}
