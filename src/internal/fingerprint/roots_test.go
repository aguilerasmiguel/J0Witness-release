package fingerprint

import (
	"testing"

	"j0witness/internal/inventory"
)

func entriesFromPaths(paths ...string) []inventory.Entry {
	out := make([]inventory.Entry, 0, len(paths))
	for _, p := range paths {
		out = append(out, inventory.Entry{RelPath: []byte(p), Type: "file"})
	}
	return out
}

// T040 (FR-014): detección de raíces por marcadores dobles.
func TestDetectRoots(t *testing.T) {
	single := entriesFromPaths("libraries/src/Version.php", "administrator/index.php", "index.php")
	if roots := DetectRoots(single); len(roots) != 1 || roots[0] != "" {
		t.Fatalf("raíz única: %v", roots)
	}

	multi := entriesFromPaths(
		"libraries/src/Version.php", "administrator/index.php",
		"blog/libraries/src/Version.php", "blog/administrator/index.php",
	)
	roots := DetectRoots(multi)
	if len(roots) != 2 || roots[0] != "" || roots[1] != "blog" {
		t.Fatalf("raíces múltiples: %v", roots)
	}

	// Un solo marcador (backup parcial) no constituye raíz.
	partial := entriesFromPaths("backup/libraries/src/Version.php")
	if roots := DetectRoots(partial); len(roots) != 0 {
		t.Fatalf("backup parcial contado como raíz: %v", roots)
	}
}
