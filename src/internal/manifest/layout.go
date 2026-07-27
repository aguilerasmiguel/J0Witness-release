package manifest

import (
	"path"
	"sort"
	"strings"
)

// DeclKind distingue una declaración de archivo exacto de una de carpeta
// (recursiva). Determina la granularidad de la propiedad (Clarificación C1).
type DeclKind int

const (
	// DeclFile: `<filename>`/`<file>` — propiedad exacta de un archivo.
	DeclFile DeclKind = iota
	// DeclFolder: `<folder>` — propiedad recursiva de todo su contenido.
	DeclFolder
)

// Declaration es una ruta instalada que el manifiesto declara suya.
type Declaration struct {
	Path string // ruta instalada relativa a la raíz del árbol
	Kind DeclKind
}

// Layout es el resultado del mapeo declarado→instalado: las raíces que la
// extensión ocupa (FR-113) y las rutas concretas que declara.
type Layout struct {
	Roots        []string      // directorios instalados que ocupa (ordenados)
	Declarations []Declaration // rutas declaradas (ordenadas por Path)
	// LanguageFiles son traducciones que la extensión instala en la carpeta de
	// idioma compartida (fuera de sus raíces). Se atribuyen por ruta exacta al
	// margen de las raíces y NO son declaraciones (no las evalúa
	// DetectSuspicious ni definen barrido de no-declarados).
	LanguageFiles []string
}

// elementName devuelve el `<name>` de display del manifiesto, ya recortado. Se
// usa solo como fallback del destino de media (cuando <media> no trae
// `destination`) y como raíz de librería; NO para la raíz de componentes, que
// se deriva del directorio del manifiesto (ver MapLayout, caso Component: el
// display es un rótulo humano —"SP Page Builder"— y no el elemento instalado
// —com_sppagebuilder—).
func (m *Manifest) elementName() string {
	return strings.TrimSpace(m.Name)
}

// MapLayout traduce las secciones del manifiesto a ubicaciones instaladas
// según el tipo (R2). manifestPath es la ruta del propio manifiesto en el
// árbol; para módulos/plugins/plantillas la raíz de instalación se deriva de
// ahí. Devuelve las raíces ocupadas y las declaraciones concretas.
func (m *Manifest) MapLayout(manifestPath string) Layout {
	var decls []Declaration
	roots := map[string]bool{}
	add := func(root string, fs Fileset) {
		if root == "" {
			return
		}
		roots[root] = true
		for _, f := range fs.Filenames {
			decls = append(decls, Declaration{Path: cleanJoin(root, f), Kind: DeclFile})
		}
		for _, f := range fs.Files {
			f = strings.TrimSpace(f)
			if f != "" {
				decls = append(decls, Declaration{Path: cleanJoin(root, f), Kind: DeclFile})
			}
		}
		for _, d := range fs.Folders {
			decls = append(decls, Declaration{Path: cleanJoin(root, d), Kind: DeclFolder})
		}
	}

	switch m.Type {
	case Component, Module, Plugin, Template, Library:
		// Las raíces de instalación de estos tipos comparten forma (Files,
		// AdminFiles solo componentes, Media con fallback) y viven en
		// sectionRootsFor; ver ahí las notas de derivación por tipo.
		sr := sectionRootsFor(m.Type, manifestPath, m)
		add(sr.Files, m.Site)
		add(sr.AdminFiles, m.Admin)
		for _, md := range m.Media {
			add(sr.MediaBase+"/"+mediaDest(md, sr.MediaFallback), md)
		}
	case Language:
		// Un paquete de idioma posee TODO el directorio de su manifiesto
		// ({,administrator/,api/}language/<tag>/). Se declara como carpeta
		// recursiva explícita aunque el manifiesto no traiga <folder>/</folder>.
		root := path.Dir(manifestPath)
		roots[root] = true
		decls = append(decls, Declaration{Path: root, Kind: DeclFolder})
		add(root, m.Site)
	default:
		// file/package/unknown: sin mapeo específico; se ancla al directorio del
		// manifiesto como mejor esfuerzo.
		add(path.Dir(manifestPath), m.Site)
	}

	// <scriptfile>: el script de instalación (install/update/uninstall) es un
	// ejecutable relativo al directorio del manifiesto. Es una declaración
	// legítima: sin ella sale como ejecutable no declarado (J0W-EXT-001 High
	// falso). Se atribuye como archivo exacto; sigue visible en la red
	// unverified_executables (es ejecutable sin verificar, matiz anestesia).
	if m.ScriptFile != "" {
		dir := path.Dir(manifestPath)
		roots[dir] = true // garantiza InRoots (para componentes es la raíz de admin)
		decls = append(decls, Declaration{Path: cleanJoin(dir, m.ScriptFile), Kind: DeclFile})
	}

	// Traducciones <languages>: se instalan en la carpeta de idioma compartida,
	// fuera de las raíces. El cliente (site/administrator/api) varía por tipo y
	// sección, así que se generan los tres destinos candidatos por declaración;
	// BuildOwnership solo atribuye los que existen en el árbol. Van en
	// LanguageFiles, no en Declarations (ver Layout).
	langRoots := []string{"language", "administrator/language", "api/language"}
	seenLang := map[string]bool{}
	var langFiles []string
	for _, ld := range m.LangDecls {
		for _, root := range langRoots {
			p := cleanJoin(root, ld.Tag+"/"+ld.Base)
			if !seenLang[p] {
				seenLang[p] = true
				langFiles = append(langFiles, p)
			}
		}
	}
	sort.Strings(langFiles)

	rootList := make([]string, 0, len(roots))
	for r := range roots {
		rootList = append(rootList, r)
	}
	sort.Strings(rootList)
	sort.Slice(decls, func(i, j int) bool {
		if decls[i].Path != decls[j].Path {
			return decls[i].Path < decls[j].Path
		}
		return decls[i].Kind < decls[j].Kind
	})
	return Layout{Roots: rootList, Declarations: decls, LanguageFiles: langFiles}
}

func mediaDest(md Fileset, fallback string) string {
	if md.Dest != "" {
		return md.Dest
	}
	return fallback
}

// cleanJoin une root y un elemento declarado y normaliza. NO ancla los
// intentos de escape: una declaración que sale de la raíz de la extensión se
// conserva tal cual (resuelta) para que DetectSuspicious la vea fuera de las
// raíces y la marque como anomalía del manifiesto (J0W-EXT-004). Como el mapa
// de propiedad solo casa contra entradas reales del árbol, una ruta que escapa
// del todo (p.ej. `/etc/passwd`) simplemente no casa con nada.
func cleanJoin(root, elem string) string {
	elem = strings.TrimSpace(strings.Trim(elem, "/"))
	return path.Clean(root + "/" + elem)
}

// Owns informa de si una ruta instalada cae bajo alguna declaración, y con qué
// granularidad. Devuelve (poseída, esCarpetaRecursiva, exacta).
func (l Layout) Owns(rel string) (owned bool, viaFolder bool) {
	for _, d := range l.Declarations {
		switch d.Kind {
		case DeclFile:
			if rel == d.Path {
				return true, false
			}
		case DeclFolder:
			if rel == d.Path || strings.HasPrefix(rel, d.Path+"/") {
				return true, true
			}
		}
	}
	return false, false
}

// InRoots informa de si una ruta cae dentro de alguna raíz ocupada por la
// extensión (define su "árbol", donde se buscan no-declarados).
func (l Layout) InRoots(rel string) bool {
	for _, r := range l.Roots {
		if rel == r || strings.HasPrefix(rel, r+"/") {
			return true
		}
	}
	return false
}
