package manifest

import (
	"path"
	"regexp"
	"strings"
)

// Candidate es una ruta del inventario que parece un manifiesto de extensión,
// con el tipo esperado según su ubicación (R1).
type Candidate struct {
	ManifestPath string
	ExpectedType Type
}

var (
	reComponentManifest = regexp.MustCompile(`^administrator/components/(com_[^/]+)/[^/]+\.xml$`)
	reModuleSite        = regexp.MustCompile(`^modules/(mod_[^/]+)/[^/]+\.xml$`)
	reModuleAdmin       = regexp.MustCompile(`^administrator/modules/(mod_[^/]+)/[^/]+\.xml$`)
	rePlugin            = regexp.MustCompile(`^plugins/([^/]+)/([^/]+)/[^/]+\.xml$`)
	reTemplateSite      = regexp.MustCompile(`^templates/([^/]+)/templateDetails\.xml$`)
	reTemplateAdmin     = regexp.MustCompile(`^administrator/templates/([^/]+)/templateDetails\.xml$`)
	// Librería: el manifiesto puede vivir en un subdirectorio (p.ej.
	// manifests/libraries/eshiol/J2xml.xml), no solo en el primer nivel.
	reLibrary = regexp.MustCompile(`^administrator/manifests/libraries/.+\.xml$`)
	reFile    = regexp.MustCompile(`^administrator/manifests/files/[^/]+\.xml$`)
	rePackage = regexp.MustCompile(`^administrator/manifests/packages/[^/]+\.xml$`)
	// Idioma: cada árbol ({,administrator/,api/}language/<tag>/) trae su propio
	// install.xml (type="language"). langmetadata.xml es <metafile>, no
	// instalable → no se reconoce aquí (el parser lo descartaría igual).
	reLanguageInstall = regexp.MustCompile(`^(?:administrator/|api/)?language/[a-z]{2,3}-[A-Z]{2}/install\.xml$`)
)

// DiscoverCandidates filtra, de una lista de rutas del inventario, las que
// tienen forma de manifiesto de extensión, anotando el tipo esperado por su
// ubicación. El tipo definitivo lo confirma el parseo (`<extension type>`).
func DiscoverCandidates(paths []string) []Candidate {
	var out []Candidate
	for _, p := range paths {
		if !strings.HasSuffix(p, ".xml") {
			continue
		}
		switch {
		case reComponentManifest.MatchString(p):
			// El manifiesto de un componente suele llamarse como el componente
			// sin el prefijo com_ (content.xml), pero no siempre; aceptamos
			// cualquier .xml en la raíz de administración del componente y lo
			// confirma el parseo.
			if isComponentRootXML(p) {
				out = append(out, Candidate{ManifestPath: p, ExpectedType: Component})
			}
		case reModuleSite.MatchString(p) || reModuleAdmin.MatchString(p):
			out = append(out, Candidate{ManifestPath: p, ExpectedType: Module})
		case rePlugin.MatchString(p):
			out = append(out, Candidate{ManifestPath: p, ExpectedType: Plugin})
		case reTemplateSite.MatchString(p) || reTemplateAdmin.MatchString(p):
			out = append(out, Candidate{ManifestPath: p, ExpectedType: Template})
		case reLanguageInstall.MatchString(p):
			out = append(out, Candidate{ManifestPath: p, ExpectedType: Language})
		case reLibrary.MatchString(p):
			out = append(out, Candidate{ManifestPath: p, ExpectedType: Library})
		case reFile.MatchString(p):
			out = append(out, Candidate{ManifestPath: p, ExpectedType: File})
		case rePackage.MatchString(p):
			out = append(out, Candidate{ManifestPath: p, ExpectedType: Package})
		}
	}
	return out
}

// isComponentRootXML acepta un .xml situado directamente en la raíz de
// administración de un componente (donde Joomla coloca el manifiesto).
func isComponentRootXML(p string) bool {
	m := reComponentManifest.FindStringSubmatch(p)
	if m == nil {
		return false
	}
	// El manifiesto está en administrator/components/com_X/<algo>.xml (un nivel).
	rest := strings.TrimPrefix(p, "administrator/components/"+m[1]+"/")
	return !strings.Contains(rest, "/")
}

// ComponentName extrae com_X de la ruta de un manifiesto de componente.
func ComponentName(manifestPath string) string {
	if m := reComponentManifest.FindStringSubmatch(manifestPath); m != nil {
		return m[1]
	}
	return path.Base(path.Dir(manifestPath))
}

// ClientIsAdmin informa de si el manifiesto instala en el cliente
// administrator (prefijo administrator/) frente al site.
func ClientIsAdmin(manifestPath string) bool {
	return strings.HasPrefix(manifestPath, "administrator/")
}

// ModuleElement extrae mod_X de la ruta de un manifiesto de módulo (site o
// administrator).
func ModuleElement(manifestPath string) string {
	if m := reModuleSite.FindStringSubmatch(manifestPath); m != nil {
		return m[1]
	}
	if m := reModuleAdmin.FindStringSubmatch(manifestPath); m != nil {
		return m[1]
	}
	return path.Base(path.Dir(manifestPath))
}

// PluginGroupElement extrae (grupo, elemento) de la ruta de un manifiesto de
// plugin (p.ej. plugins/system/foo/foo.xml → "system", "foo").
func PluginGroupElement(manifestPath string) (string, string) {
	if m := rePlugin.FindStringSubmatch(manifestPath); m != nil {
		return m[1], m[2]
	}
	d := path.Dir(manifestPath)
	return path.Base(path.Dir(d)), path.Base(d)
}

// TemplateName extrae el nombre de la plantilla de la ruta de su manifiesto
// (site o administrator).
func TemplateName(manifestPath string) string {
	if m := reTemplateSite.FindStringSubmatch(manifestPath); m != nil {
		return m[1]
	}
	if m := reTemplateAdmin.FindStringSubmatch(manifestPath); m != nil {
		return m[1]
	}
	return path.Base(path.Dir(manifestPath))
}
