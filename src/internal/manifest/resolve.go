package manifest

import (
	"path"
	"strings"
)

// sectionRoots son las raíces de instalación de un tipo de extensión, tal y
// como las deriva MapLayout de su manifiesto: dónde caen <files>,
// <administration><files>, la base de <media> (con su fallback de destino) y
// el directorio donde vive el propio .xml del manifiesto.
type sectionRoots struct {
	Files         string // raíz de <files> (primaria); "" si no aplica
	AdminFiles    string // raíz de <administration><files> (solo componentes); ""
	MediaBase     string // "media"; destino real = MediaBase+"/"+mediaDest(md, MediaFallback)
	MediaFallback string // com_x (componente) o display name (resto)
	ManifestDir   string // directorio donde instala el propio .xml del manifiesto
}

// sectionRootsFor calcula las raíces de sectionRoots para los tipos con
// mapeo de instalación regular (component/module/plugin/template/library).
// Language y los tipos por defecto (file/package/unknown) NO pasan por aquí:
// se resuelven en MapLayout, que es donde su lógica especial se conserva.
func sectionRootsFor(t Type, manifestPath string, m *Manifest) sectionRoots {
	name := m.elementName()
	switch t {
	case Component:
		// com_X: la raíz se deriva del DIRECTORIO del manifiesto
		// (administrator/components/com_X/…), NO del `<name>` de display (ver
		// nota en MapLayout).
		com := ComponentName(manifestPath)
		return sectionRoots{
			Files:         "components/" + com,
			AdminFiles:    "administrator/components/" + com,
			MediaBase:     "media",
			MediaFallback: com,
			ManifestDir:   "administrator/components/" + com,
		}
	case Module:
		root := path.Dir(manifestPath)
		return sectionRoots{
			Files:         root,
			MediaBase:     "media",
			MediaFallback: name,
			ManifestDir:   root,
		}
	case Plugin:
		root := path.Dir(manifestPath)
		return sectionRoots{
			Files:         root,
			MediaBase:     "media",
			MediaFallback: name,
			ManifestDir:   root,
		}
	case Template:
		root := path.Dir(manifestPath)
		return sectionRoots{
			Files:         root,
			MediaBase:     "media",
			MediaFallback: name,
			ManifestDir:   root,
		}
	case Library:
		// La raíz real de una librería es libraries/<libraryname> (p.ej.
		// libraries/eshiol/J2xml), no libraries/<name> de display.
		// <libraryname> es la señal correcta; si falta, mejor esfuerzo con el
		// nombre sin lib_. ManifestDir es el directorio real donde vive el
		// .xml (en el árbol de manifests), que no coincide con la raíz de
		// instalación.
		root := "libraries/" + strings.TrimPrefix(name, "lib_")
		if m.LibraryName != "" {
			root = "libraries/" + strings.Trim(m.LibraryName, "/")
		}
		return sectionRoots{
			Files:         root,
			MediaBase:     "media",
			MediaFallback: name,
			ManifestDir:   path.Dir(manifestPath),
		}
	default:
		return sectionRoots{}
	}
}

// InstallTarget es la identidad y las raíces reales de una extensión
// instalada, derivadas del manifiesto INSTALADO (su ruta + contenido). Lo
// consume el simulador de instalación (T2).
type InstallTarget struct {
	Type           Type
	ElementKey     string // clave canónica (ver ExtensionKey)
	FilesRoot      string
	AdminFilesRoot string
	MediaBase      string
	MediaFallback  string
	ManifestDir    string
}

// ResolveInstall resuelve la identidad y las raíces de instalación de m,
// cuyo manifiesto vive en manifestPath. Envoltura de sectionRootsFor +
// ExtensionKey.
func (m *Manifest) ResolveInstall(manifestPath string) InstallTarget {
	sr := sectionRootsFor(m.Type, manifestPath, m)
	return InstallTarget{
		Type:           m.Type,
		ElementKey:     ExtensionKey(m.Type, manifestPath, m),
		FilesRoot:      sr.Files,
		AdminFilesRoot: sr.AdminFiles,
		MediaBase:      sr.MediaBase,
		MediaFallback:  sr.MediaFallback,
		ManifestDir:    sr.ManifestDir,
	}
}

// ExtensionKey es la clave estable y única por tipo, idéntica en el lado
// add/fetch y en el lado scan. Componente = com_x (compatibilidad con las
// líneas base de la fase 2a).
func ExtensionKey(t Type, manifestPath string, m *Manifest) string {
	switch t {
	case Component:
		return ComponentName(manifestPath)
	case Module:
		k := ModuleElement(manifestPath)
		if ClientIsAdmin(manifestPath) {
			return k + "@administrator"
		}
		return k
	case Plugin:
		g, e := PluginGroupElement(manifestPath)
		return g + "/" + e
	case Template:
		k := TemplateName(manifestPath)
		if ClientIsAdmin(manifestPath) {
			return k + "@administrator"
		}
		return k
	case Library:
		if m != nil && m.LibraryName != "" {
			return strings.Trim(m.LibraryName, "/")
		}
		return strings.TrimPrefix(strings.TrimSpace(m.Name), "lib_")
	default:
		return path.Base(path.Dir(manifestPath))
	}
}
