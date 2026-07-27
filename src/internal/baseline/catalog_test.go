package baseline

import (
	"testing"
)

// El orden de Versions() es visible al usuario en el error de versión fuera de
// cobertura (scan.go): con orden por cadena, "3.10.0" queda antes de "3.9.0".
func TestVersionsOrdenSemver(t *testing.T) {
	c := &Catalog{Releases: []Release{
		{Version: "3.10.12"}, {Version: "3.9.0"}, {Version: "5.4.7"},
		{Version: "4.4.13"}, {Version: "3.9.28"},
	}}
	sortReleases(c)
	got := c.Versions()
	want := []string{"3.9.0", "3.9.28", "3.10.12", "4.4.13", "5.4.7"}
	if len(got) != len(want) {
		t.Fatalf("Versions() = %v, quiero %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Versions() = %v, quiero %v", got, want)
		}
	}
}

func TestKnownIndex(t *testing.T) {
	c := &Catalog{KnownFiles: []KnownFile{
		{Path: "libraries/legacy.php", Hashes: []string{"aaa", "bbb"}},
		{Path: "media/viejo.js", Hashes: []string{"ccc"}},
	}}
	idx := c.KnownIndex()
	if len(idx) != 2 {
		t.Fatalf("KnownIndex() tiene %d entradas, quiero 2", len(idx))
	}
	if h := idx["libraries/legacy.php"]; len(h) != 2 || h[0] != "aaa" {
		t.Fatalf("hashes de libraries/legacy.php = %v", h)
	}
	if _, ok := idx["no/existe.php"]; ok {
		t.Fatal("KnownIndex() no debe inventar rutas")
	}
}
