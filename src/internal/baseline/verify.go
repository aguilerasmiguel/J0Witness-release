package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"j0witness/internal/inventory"
)

// ErrUntrusted se devuelve cuando el baseline almacenado/cacheado no casa con
// el catálogo embebido (Principio VIII: el catálogo es la única raíz de
// confianza). Cualquier discrepancia — identidad de paquete, paquete cacheado
// manipulado o manifiesto alterado — se envuelve en este sentinel.
var ErrUntrusted = errors.New("baseline no confiable: no casa con el catálogo embebido")

// ErrPackageMismatch indica que el paquete cacheado en disco no coincide con
// el hash esperado (catálogo o llamador). OpenContent lo devuelve envuelto en
// su propio contexto; Verify lo reenvuelve en ErrUntrusted.
var ErrPackageMismatch = errors.New("paquete cacheado no coincide con el catálogo")

// Verification resume el resultado de una verificación exitosa: qué se pudo
// comprobar y con qué nivel de confianza.
type Verification struct {
	PackageSHA256  string
	CatalogVersion string
	// ManifestSource: "rederived-from-verified-package" cuando el paquete
	// cacheado se verificó contra el catálogo y el manifiesto se recomputó
	// de su contenido; "stored-self-consistent" cuando no hay paquete
	// cacheado y sólo se comprobó que el manifiesto almacenado es
	// internamente consistente con su propio manSHA.
	ManifestSource string
	// Assurance: "verified" (manifiesto re-derivado del paquete verificado)
	// o "partial" (sólo auto-consistencia del manifiesto almacenado).
	Assurance string
}

// ManifestSHA recomputa el manSHA canónico del contenido cacheado, usando la
// misma canonicalización que Add persiste (manifestSHA), para que la
// verificación sea byte-idéntica a la derivación original.
func (c *Content) ManifestSHA() string {
	entries := make([]inventory.Entry, 0, len(c.files))
	for name, b := range c.files {
		sum := sha256.Sum256(b)
		entries = append(entries, inventory.Entry{
			RelPath: []byte(name),
			SHA256:  hex.EncodeToString(sum[:]),
			Size:    int64(len(b)),
		})
	}
	return manifestSHA(entries) // manifestSHA ordena internamente
}

// Verify re-verifica un baseline almacenado/cacheado contra el catálogo
// embebido (única raíz de confianza, Principio VIII). Comprueba en orden:
//  1. identidad del paquete: el sha256 almacenado debe coincidir con el que
//     el catálogo declara para esa versión;
//  2. si el paquete está cacheado y su contenido verifica contra ese mismo
//     sha (OpenContent lo comprueba), el manifiesto se re-deriva de su
//     contenido y se contrasta contra el manSHA almacenado — asurance
//     "verified";
//  3. si el paquete cacheado no coincide con el sha esperado, es manipulado
//     → ErrUntrusted;
//  4. si no hay paquete cacheado, sólo se comprueba que el manifiesto
//     almacenado es auto-consistente con su propio manSHA — assurance
//     "partial" (no hay contenido original contra el que contrastar);
//  5. cualquier otro error de E/S se devuelve tal cual (no es evidencia de
//     manipulación).
func Verify(rel Release, catalogVersion, storedPkgSHA, storedManSHA string,
	storedManifest map[string]ManifestEntry, cacheDir, version string) (Verification, error) {
	if storedPkgSHA != rel.PackageSHA256 {
		return Verification{}, fmt.Errorf("%w: sha del paquete almacenado=%s catálogo=%s", ErrUntrusted, storedPkgSHA, rel.PackageSHA256)
	}
	v := Verification{PackageSHA256: rel.PackageSHA256, CatalogVersion: catalogVersion}

	content, err := OpenContent(cacheDir, version, rel.PackageSHA256)
	switch {
	case err == nil:
		if got := content.ManifestSHA(); got != storedManSHA {
			return Verification{}, fmt.Errorf("%w: manifiesto almacenado=%s re-derivado=%s", ErrUntrusted, storedManSHA, got)
		}
		v.ManifestSource, v.Assurance = "rederived-from-verified-package", "verified"
	case errors.Is(err, ErrPackageMismatch):
		return Verification{}, fmt.Errorf("%w: %w", ErrUntrusted, err) // paquete cacheado manipulado
	case errors.Is(err, os.ErrNotExist):
		// paquete no cacheado: sólo auto-consistencia del manifiesto almacenado.
		if manifestSHAFromMap(storedManifest) != storedManSHA {
			return Verification{}, fmt.Errorf("%w: auto-consistencia del manifiesto almacenado falló", ErrUntrusted)
		}
		v.ManifestSource, v.Assurance = "stored-self-consistent", "partial"
	default:
		return Verification{}, err // error de E/S no relacionado con confianza
	}
	return v, nil
}

// manifestSHAFromMap recomputa el manSHA canónico de un manifiesto almacenado
// (map[string]ManifestEntry), usando la misma canonicalización que Add. Size
// no participa del hash (sólo ruta + sha), igual que manifestSHA.
func manifestSHAFromMap(m map[string]ManifestEntry) string {
	entries := make([]inventory.Entry, 0, len(m))
	for p, e := range m {
		entries = append(entries, inventory.Entry{RelPath: []byte(p), SHA256: e.SHA256})
	}
	return manifestSHA(entries)
}
