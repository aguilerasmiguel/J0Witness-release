package fingerprint

import (
	"sort"
	"strings"

	"j0witness/internal/inventory"
)

// rootMarkers identifican la raíz de una instalación Joomla dentro del
// inventario. Se exigen dos marcadores coincidentes para no confundir un
// backup parcial con una instalación.
var rootMarkers = []string{
	"libraries/src/Version.php",
	"administrator/index.php",
}

// DetectRoots enumera las raíces de instalación Joomla presentes bajo el
// objetivo (FR-014 / Clarificación C3). "" es la raíz del propio objetivo.
func DetectRoots(entries []inventory.Entry) []string {
	candidates := map[string]int{}
	for _, e := range entries {
		if e.Type != "file" {
			continue
		}
		p := string(e.RelPath)
		for _, marker := range rootMarkers {
			if p == marker {
				candidates[""]++
			} else if strings.HasSuffix(p, "/"+marker) {
				candidates[strings.TrimSuffix(p, "/"+marker)]++
			}
		}
	}
	var roots []string
	for root, hits := range candidates {
		if hits >= len(rootMarkers) {
			roots = append(roots, root)
		}
	}
	sort.Strings(roots)
	return roots
}
