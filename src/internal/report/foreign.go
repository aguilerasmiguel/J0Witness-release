package report

import (
	"encoding/json"
	"sort"
	"strings"

	"j0witness/internal/observe"
)

// ForeignRoot resume, agregado por raíz de nivel superior, el contenido de
// disco ajeno tanto a la distribución de Joomla como a las extensiones
// registradas: contexto informativo (coverage), nunca un hallazgo.
type ForeignRoot struct {
	Root            string `json:"root"`
	Files           int    `json:"files"`
	Executables     int    `json:"executables"`
	Bytes           int64  `json:"bytes"`
	DistributionDir bool   `json:"distribution_dir"`
}

// ForeignRoots agrega las observaciones FileUnexpected que Derive trata como
// "contenido de usuario fuera del core" (in_core_dir=false, no forbidden-exec,
// no explicadas por extensión/config), agrupadas por primer segmento de ruta.
// sizeBySubject da el tamaño por SubjectDisplay (0 si ausente). knownRoots
// distingue, para cada raíz agregada, si es un directorio DE la distribución
// de Joomla que además contiene contenido de usuario (true, p.ej.
// images/administrator/media) de una raíz genuinamente ajena — ausente por
// completo del manifiesto (false, p.ej. app/media/vendor). knownRoots
// nil/vacío es un fallback seguro: todas las raíces se marcan false.
func ForeignRoots(obs []observe.Observation, sizeBySubject map[string]int64, knownRoots map[string]bool) []ForeignRoot {
	// Conjunto de subjects ya explicados por extensión o config (misma lógica de
	// supresión que finding.Derive: específico > genérico).
	handled := map[string]bool{}
	for _, o := range obs {
		switch o.Type {
		case observe.ExtOwnsPath, observe.ExtOwnsFolderExec, observe.ExtUndeclared, observe.ConfigDirective:
			handled[o.SubjectDisplay] = true
		}
	}
	agg := map[string]*ForeignRoot{}
	for _, o := range obs {
		if o.Type != observe.FileUnexpected || handled[o.SubjectDisplay] {
			continue
		}
		var ev map[string]any
		_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
		inCore, _ := ev["in_core_dir"].(bool)
		forbidden, _ := ev["in_forbidden_exec"].(bool)
		exec, _ := ev["executable"].(bool)
		// Espejo literal de finding.Derive (internal/finding/derive.go): CORE-005
		// exige executable && forbidden, no forbidden por sí solo. Un
		// in_forbidden_exec=true con executable=false cae en Derive al "return
		// nil" de contenido ajeno (línea 319) y por tanto SÍ debe aparecer aquí.
		if inCore || (exec && forbidden) {
			continue // in_core → CORE-004; executable&&forbidden → CORE-005
		}
		root := firstSegment(o.SubjectDisplay)
		fr := agg[root]
		if fr == nil {
			fr = &ForeignRoot{Root: root}
			agg[root] = fr
		}
		fr.Files++
		if exec {
			fr.Executables++
		}
		fr.Bytes += sizeBySubject[o.SubjectDisplay]
	}
	if len(agg) == 0 {
		return nil
	}
	out := make([]ForeignRoot, 0, len(agg))
	for _, fr := range agg {
		fr.DistributionDir = knownRoots[fr.Root]
		out = append(out, *fr)
	}
	// Orden: DistributionDir asc (false primero → las raíces genuinamente
	// ajenas emergen antes que los dirs de Joomla con contenido de usuario),
	// luego Executables desc, luego Root asc.
	sort.Slice(out, func(i, j int) bool {
		if out[i].DistributionDir != out[j].DistributionDir {
			return !out[i].DistributionDir
		}
		if out[i].Executables != out[j].Executables {
			return out[i].Executables > out[j].Executables
		}
		return out[i].Root < out[j].Root
	})
	return out
}

// firstSegment devuelve el primer componente de una ruta relativa (el dir de
// nivel superior); un archivo raíz suelto es su propio segmento.
func firstSegment(rel string) string {
	if i := strings.IndexByte(rel, '/'); i >= 0 {
		return rel[:i]
	}
	return rel
}
