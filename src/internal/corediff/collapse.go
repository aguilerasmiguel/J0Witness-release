package corediff

import (
	"path"
	"sort"
)

const (
	collapseThreshold  = 8
	collapseSampleSize = 6
)

// CollapsedSubtree es un directorio del baseline ausente por completo cuyos
// ausentes se resumen en un solo hallazgo.
type CollapsedSubtree struct {
	Dir    string   // directorio maximal ausente-por-completo (sin barra final)
	Count  int      // nº de archivos ausentes bajo Dir
	Class  string   // clase REAL del miembro de máx severidad (ClassifyMissing): "executable" | "inert_asset" | "expected_absent" | "" (desconocido; NO se sintetiza a "executable")
	Sample []string // primeras collapseSampleSize rutas ausentes (ordenadas)
}

// classSeverityRank ordena las clases de ClassifyMissing por severidad (mayor =
// más severo): executable (3) → medium, "" desconocido (2) → medium también
// (derive.go trata ambas como medium por defecto), inert_asset → low (1),
// expected_absent → info (0). executable y "" comparten severidad pero NO
// rango: así, al agregar un subárbol, un miembro REALMENTE ejecutable siempre
// gana el desempate sobre uno de tipo desconocido (Class agregada veraz, no
// lavada a "executable" cuando ningún miembro lo es).
func classSeverityRank(cls string) int {
	switch cls {
	case "executable":
		return 3
	case "inert_asset":
		return 1
	case "expected_absent":
		return 0
	default: // "" (desconocido) → medium, rango de desempate por debajo de executable real
		return 2
	}
}

// CollapseMissingSubtrees agrupa las rutas ausentes (ya ordenadas) en subárboles
// maximales ausentes-por-completo. present es el conjunto de rutas de archivo
// PRESENTES en el árbol. Devuelve los subárboles con ≥ collapseThreshold archivos
// y el conjunto de rutas ausentes que quedan colapsadas (para que el llamante NO
// las emita individualmente). Determinista.
func CollapseMissingSubtrees(missing []string, present map[string]bool) ([]CollapsedSubtree, map[string]bool) {
	// Directorios que contienen algún archivo presente (todos los ancestros).
	presentDirs := map[string]bool{}
	for f := range present {
		for d := path.Dir(f); d != "." && d != "/" && d != ""; d = path.Dir(d) {
			presentDirs[d] = true
		}
	}
	fullyAbsent := func(dir string) bool { return !presentDirs[dir] }

	// Ancestro maximal ausente-por-completo de p (o "" si su dir está parcial).
	collapseRoot := func(p string) string {
		d := path.Dir(p)
		if d == "." || d == "/" || d == "" || !fullyAbsent(d) {
			return "" // raíz o dir parcial → no colapsable
		}
		for {
			parent := path.Dir(d)
			if parent == "." || parent == "/" || parent == "" || !fullyAbsent(parent) {
				return d
			}
			d = parent
		}
	}

	// Agrupa (orden determinista: missing ya viene ordenado; recorremos y
	// agrupamos por root, guardando orden de primera aparición de cada root).
	groups := map[string][]string{}
	var rootOrder []string
	for _, p := range missing {
		root := collapseRoot(p)
		if root == "" {
			continue
		}
		if _, seen := groups[root]; !seen {
			rootOrder = append(rootOrder, root)
		}
		groups[root] = append(groups[root], p)
	}

	var subs []CollapsedSubtree
	collapsed := map[string]bool{}
	for _, root := range rootOrder {
		members := groups[root] // ya ordenados (missing venía ordenado)
		if len(members) < collapseThreshold {
			continue
		}
		bestRank := -1
		bestClass := ""
		for _, m := range members {
			cls := ClassifyMissing(m)
			if r := classSeverityRank(cls); r > bestRank {
				bestRank = r
				bestClass = cls
			}
		}
		sample := members
		if len(sample) > collapseSampleSize {
			sample = append([]string(nil), members[:collapseSampleSize]...)
		}
		subs = append(subs, CollapsedSubtree{
			Dir: root, Count: len(members), Class: bestClass, Sample: sample,
		})
		for _, m := range members {
			collapsed[m] = true
		}
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].Dir < subs[j].Dir })
	return subs, collapsed
}
