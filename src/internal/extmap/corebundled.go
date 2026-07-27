package extmap

import "j0witness/internal/baseline"

// CoreBundledFunc devuelve un predicado que decide si la ruta de un manifiesto
// pertenece al baseline del core (C2/R3): si el manifiesto está en el
// manifiesto del baseline, la extensión es de serie y ya la verifica la 001.
func CoreBundledFunc(manifest map[string]baseline.ManifestEntry) func(string) bool {
	return func(manifestPath string) bool {
		_, ok := manifest[manifestPath]
		return ok
	}
}
