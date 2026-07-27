package fingerprint

import (
	"sort"
	"strings"

	"j0witness/internal/observe"
)

// VoteResult es el resultado de la votación por testigos (FR-010/FR-011).
type VoteResult struct {
	Winner            string // "" si no concluyente
	Confidence        observe.Confidence
	Candidates        []Candidate // votos desc, versión asc
	WitnessUsed       int
	WitnessUnreadable int
	Mixed             bool // FR-013: votos repartidos coherentemente
}

// Candidate acumula votos por versión.
type Candidate struct {
	Version string
	Votes   int
}

// Vote decide la versión por mayoría de testigos. La versión declarada NUNCA
// participa (R7): solo la evidencia de contenido vota.
//
// La decisión se acota a la rama de la candidata líder. El catálogo lleva un
// conjunto testigo por rama (R7: "por serie") y muchas rutas sobreviven entre
// majors: en un árbol 4.x también son legibles testigos de 3.x y 5.x que jamás
// podrán votar a una versión 4.x. Contarlos en el denominador infla el umbral
// de confianza sin que puedan aportar margen —medido: 82 legibles frente a 48
// capaces de votar—. Si el catálogo no declara ramas, el acotado es inocuo.
func Vote(matches []WitnessMatch) VoteResult {
	lead := candidates(matches, "")
	if len(lead) == 0 {
		var res VoteResult
		for _, m := range matches {
			if m.Readable {
				res.WitnessUsed++
			} else {
				res.WitnessUnreadable++
			}
		}
		res.Confidence = observe.Low
		return res
	}
	return decide(matches, branchOf(lead[0].Version))
}

// branchOf es la rama (major) de una versión punteada.
func branchOf(version string) string {
	if i := strings.IndexByte(version, '.'); i > 0 {
		return version[:i]
	}
	return version
}

// inBranch: la rama vacía no acota (primera pasada), y un testigo sin rama
// declarada sirve para cualquiera.
func inBranch(m WitnessMatch, branch string) bool {
	if branch == "" || len(m.Branches) == 0 {
		return true
	}
	for _, b := range m.Branches {
		if b == branch {
			return true
		}
	}
	return false
}

// candidates acumula votos por versión. Con branch != "" solo participan los
// testigos de esa rama y solo se acumulan votos a versiones de esa rama.
func candidates(matches []WitnessMatch, branch string) []Candidate {
	votes := map[string]int{}
	for _, m := range matches {
		if !m.Readable || !inBranch(m, branch) {
			continue
		}
		for _, v := range m.Versions {
			if branch != "" && branchOf(v) != branch {
				continue
			}
			votes[v]++
		}
	}
	out := make([]Candidate, 0, len(votes))
	for v, n := range votes {
		out = append(out, Candidate{Version: v, Votes: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Votes != out[j].Votes {
			return out[i].Votes > out[j].Votes
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// decide aplica los umbrales de confianza entre los testigos de una rama.
func decide(matches []WitnessMatch, branch string) VoteResult {
	var res VoteResult
	scoped := make([]WitnessMatch, 0, len(matches))
	for _, m := range matches {
		if !inBranch(m, branch) {
			continue
		}
		scoped = append(scoped, m)
		if m.Readable {
			res.WitnessUsed++
		} else {
			res.WitnessUnreadable++
		}
	}
	res.Candidates = candidates(scoped, branch)

	if len(res.Candidates) == 0 || res.WitnessUsed == 0 {
		res.Confidence = observe.Low
		return res
	}
	top := res.Candidates[0]
	second := 0
	if len(res.Candidates) > 1 {
		second = res.Candidates[1].Votes
	}
	// Un testigo puede votar a varias versiones si comparten hash (archivos
	// idénticos entre releases): la señal es el margen entre candidatas.
	margin := top.Votes - second
	coverage := float64(top.Votes) / float64(res.WitnessUsed)

	// FR-013: dos versiones con respaldo fuerte simultáneo y disjunto →
	// instalación mixta, no se colapsa a una sola.
	if second >= 3 && margin < top.Votes/2 && !subsetVotes(scoped, res.Candidates[0].Version, res.Candidates[1].Version) {
		res.Mixed = true
	}

	switch {
	case margin == 0:
		res.Confidence = observe.Low // empate: no concluyente
	case coverage >= 0.8 && margin >= res.WitnessUsed/3:
		// Alta solo con respaldo casi unánime: testigos discrepantes
		// (manipulados o de otra versión) degradan la confianza (T036).
		res.Winner = top.Version
		res.Confidence = observe.High
	case coverage >= 0.4:
		res.Winner = top.Version
		res.Confidence = observe.Medium
	default:
		res.Winner = top.Version
		res.Confidence = observe.Low
	}
	if res.Mixed && res.Confidence == observe.High {
		res.Confidence = observe.Medium
	}
	return res
}

// subsetVotes detecta si la segunda candidata solo acumula votos de testigos
// que también votan a la primera (hashes compartidos entre releases): eso no
// es instalación mixta, es indistinguibilidad parcial.
func subsetVotes(matches []WitnessMatch, first, second string) bool {
	for _, m := range matches {
		votesSecond, votesFirst := false, false
		for _, v := range m.Versions {
			if v == second {
				votesSecond = true
			}
			if v == first {
				votesFirst = true
			}
		}
		if votesSecond && !votesFirst {
			return false
		}
	}
	return true
}
