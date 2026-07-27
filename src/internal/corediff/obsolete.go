package corediff

// ObsoleteStatus clasifica un archivo presente en el árbol que el baseline
// actual ya no distribuye pero que figura en la lista de obsoletos (R6).
type ObsoleteStatus int

const (
	NotObsolete ObsoleteStatus = iota
	// ObsoleteKnownHash: residuo esperado de actualización — su contenido
	// coincide con el que distribuyó alguna versión anterior (J0W-CORE-011).
	ObsoleteKnownHash
	// ObsoleteUnknownHash: el archivo obsoleto existe pero su contenido no
	// coincide con ninguna versión que lo distribuyó: los huérfanos son
	// escondite clásico de webshells (J0W-CORE-009).
	ObsoleteUnknownHash
)

// CheckObsolete evalúa una ruta contra la tabla de archivos conocidos del
// catálogo (R6 enmendado). El llamante ya comprobó que la ruta no está en el
// manifiesto del baseline: si el catálogo la conoce, es un obsoleto, y el
// hash decide si es residuo esperado o huérfano.
func CheckObsolete(rel, sha string, known map[string][]string) ObsoleteStatus {
	hashes, ok := known[rel]
	if !ok {
		return NotObsolete
	}
	for _, h := range hashes {
		if h == sha {
			return ObsoleteKnownHash
		}
	}
	return ObsoleteUnknownHash
}
