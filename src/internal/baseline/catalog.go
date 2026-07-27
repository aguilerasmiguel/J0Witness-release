// Package baseline gestiona el catálogo de distribuciones oficiales, el caché
// local y la verificación de integridad (Principio VIII: offline por defecto,
// verificación por hash contra catálogo).
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"j0witness/data"
)

// Release es una distribución oficial conocida por el catálogo.
type Release struct {
	Version       string `json:"version"`
	PackageSHA256 string `json:"package_sha256"`
}

// Witness es un archivo testigo con su hash por versión (R7). Branches son las
// ramas (majors) que lo seleccionaron: R7 elige un conjunto por serie, y una
// ruta puede servir a varias. Vacío significa "vale para cualquier rama"
// (catálogos hechos a mano y de laboratorio).
type Witness struct {
	Path     string            `json:"path"`
	Branches []string          `json:"branches,omitempty"`
	Hashes   map[string]string `json:"hashes"`
}

// KnownFile es una ruta que alguna release del catálogo distribuyó, con todos
// los hashes con los que la distribuyó (R6 enmendado). Sustituye a la lista de
// obsoletos por versión: los obsoletos de una versión son las rutas de esta
// tabla ausentes del manifiesto de su baseline, así que no hace falta
// almacenarlas versión a versión.
type KnownFile struct {
	Path   string   `json:"path"`
	Hashes []string `json:"hashes"`
}

// Catalog es el catálogo embebido o cargado desde archivo.
type Catalog struct {
	CatalogVersion string      `json:"catalog_version"`
	CMS            string      `json:"cms"`
	Releases       []Release   `json:"releases"`
	Witnesses      []Witness   `json:"witnesses"`
	KnownFiles     []KnownFile `json:"known_files"`
}

// LoadEmbedded devuelve el catálogo embebido en el binario.
func LoadEmbedded() (*Catalog, error) {
	return parse(data.CatalogJSON)
}

// LoadFile carga un catálogo alternativo (bandera oculta --catalog; lab/CI).
func LoadFile(path string) (*Catalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("catálogo %s: %w", path, err)
	}
	return parse(raw)
}

// Load resuelve el catálogo: archivo alternativo si se indica, embebido si no.
func Load(altPath string) (*Catalog, error) {
	if altPath != "" {
		return LoadFile(altPath)
	}
	return LoadEmbedded()
}

func parse(raw []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("catálogo inválido: %w", err)
	}
	sortReleases(&c)
	return &c, nil
}

// sortReleases ordena por componentes numéricos, no por cadena: con orden
// lexicográfico "3.10.0" quedaría antes de "3.9.0", y ese orden es visible al
// usuario en el error de versión fuera de cobertura.
func sortReleases(c *Catalog) {
	sort.Slice(c.Releases, func(i, j int) bool {
		return compareVersions(c.Releases[i].Version, c.Releases[j].Version) < 0
	})
}

// compareVersions compara dos versiones punteadas componente a componente.
// Los componentes no numéricos valen 0 y se desempatan por cadena.
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			return x - y
		}
	}
	return strings.Compare(a, b)
}

// FindRelease localiza una versión en el catálogo.
func (c *Catalog) FindRelease(version string) (Release, bool) {
	for _, r := range c.Releases {
		if r.Version == version {
			return r, true
		}
	}
	return Release{}, false
}

// FindByPackageSHA localiza la release cuyo paquete oficial tiene ese hash.
func (c *Catalog) FindByPackageSHA(sha string) (Release, bool) {
	for _, r := range c.Releases {
		if r.PackageSHA256 == sha {
			return r, true
		}
	}
	return Release{}, false
}

// Versions devuelve las versiones cubiertas, ordenadas.
func (c *Catalog) Versions() []string {
	out := make([]string, len(c.Releases))
	for i, r := range c.Releases {
		out[i] = r.Version
	}
	return out
}

// KnownIndex indexa por ruta la tabla de archivos conocidos. Se construye una
// vez por ejecución: la clasificación consulta una ruta por cada archivo del
// árbol, y con ~25.000 rutas el barrido lineal costaría cientos de millones de
// comparaciones de cadena.
func (c *Catalog) KnownIndex() map[string][]string {
	idx := make(map[string][]string, len(c.KnownFiles))
	for _, k := range c.KnownFiles {
		idx[k.Path] = k.Hashes
	}
	return idx
}
