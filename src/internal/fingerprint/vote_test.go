package fingerprint

import (
	"testing"

	"j0witness/internal/observe"
)

func matchesFor(votes map[string]string, unreadable int) []WitnessMatch {
	var out []WitnessMatch
	for path, version := range votes {
		out = append(out, WitnessMatch{Path: path, Readable: true, Versions: []string{version}})
	}
	for i := 0; i < unreadable; i++ {
		out = append(out, WitnessMatch{Path: "x", Readable: false})
	}
	return out
}

// T036: con hasta 1/3 de testigos manipulados o ilegibles, la inferencia
// mantiene la versión correcta con confianza degradada como mucho.
func TestVoteRobustToPartialTampering(t *testing.T) {
	votes := map[string]string{}
	for i := 0; i < 6; i++ {
		votes[string(rune('a'+i))] = "5.1.4"
	}
	// 3 de 9 manipulados hacia otra versión.
	votes["h1"], votes["h2"], votes["h3"] = "4.4.0", "4.4.0", "4.4.0"

	res := Vote(matchesFor(votes, 0))
	if res.Winner != "5.1.4" {
		t.Fatalf("ganadora %q, esperaba 5.1.4 (candidatas %v)", res.Winner, res.Candidates)
	}
	if res.Confidence == observe.High {
		t.Fatal("con 1/3 de testigos discrepantes la confianza no puede ser alta")
	}
}

func TestVoteUnreadableDegradesConfidence(t *testing.T) {
	votes := map[string]string{"a": "5.1.4", "b": "5.1.4", "c": "5.1.4"}
	res := Vote(matchesFor(votes, 4)) // 4 de 7 ilegibles
	if res.Winner != "5.1.4" {
		t.Fatalf("ganadora %q", res.Winner)
	}
	if res.WitnessUnreadable != 4 {
		t.Fatalf("ilegibles: %d", res.WitnessUnreadable)
	}
}

func TestVoteTieIsInconclusive(t *testing.T) {
	votes := map[string]string{"a": "1.0.0", "b": "1.1.0"}
	res := Vote(matchesFor(votes, 0))
	if res.Winner != "" || res.Confidence != observe.Low {
		t.Fatalf("un empate debe ser no concluyente: %+v", res)
	}
}

// FR-013: votos repartidos y disjuntos → instalación mixta.
func TestVoteMixedDetection(t *testing.T) {
	votes := map[string]string{}
	for i := 0; i < 4; i++ {
		votes[string(rune('a'+i))] = "1.0.0"
	}
	for i := 0; i < 3; i++ {
		votes[string(rune('m'+i))] = "1.1.0"
	}
	res := Vote(matchesFor(votes, 0))
	if !res.Mixed {
		t.Fatalf("mixta no detectada: %+v", res)
	}
	if res.Winner != "1.0.0" {
		t.Fatalf("ganadora %q", res.Winner)
	}
}

// Testigos con hash compartido entre releases NO son instalación mixta.
func TestVoteSharedHashesNotMixed(t *testing.T) {
	var matches []WitnessMatch
	for i := 0; i < 4; i++ {
		matches = append(matches, WitnessMatch{Path: string(rune('a' + i)), Readable: true, Versions: []string{"1.0.0"}})
	}
	for i := 0; i < 3; i++ {
		// Archivos idénticos en ambas releases: votan a las dos.
		matches = append(matches, WitnessMatch{Path: string(rune('m' + i)), Readable: true, Versions: []string{"1.0.0", "1.1.0"}})
	}
	res := Vote(matches)
	if res.Mixed {
		t.Fatal("indistinguibilidad parcial clasificada como instalación mixta")
	}
	if res.Winner != "1.0.0" {
		t.Fatalf("ganadora %q", res.Winner)
	}
}
