// Package manifest parsea los manifiestos XML de instalación de Joomla como
// datos (Principio IX: jamás como código) y traduce las rutas que declaran a
// sus ubicaciones instaladas. No conoce el inventario ni los hallazgos: solo
// XML → rutas.
package manifest

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// MaxSize es el tope anti-DoS al leer un manifiesto (los reales son de KB).
const MaxSize = 4 << 20

// ErrUnrecognized indica un XML válido que no es un manifiesto reconocible.
var ErrUnrecognized = errors.New("esquema de manifiesto no reconocido")

// Type es el tipo de extensión declarado.
type Type string

const (
	Component Type = "component"
	Module    Type = "module"
	Plugin    Type = "plugin"
	Template  Type = "template"
	Library   Type = "library"
	File      Type = "file"
	Package   Type = "package"
	Language  Type = "language"
	Unknown   Type = "unknown"
)

// Fileset representa una sección <files>/<administration><files>/<media> con
// sus carpetas y archivos declarados.
type Fileset struct {
	Folder    string   `xml:"folder,attr"`
	Dest      string   `xml:"destination,attr"`
	Filenames []string `xml:"filename"`
	Files     []string `xml:"file"`
	Folders   []string `xml:"folder"`
}

// langRef es una entrada `<language tag="…">ruta</language>`. Interesan el tag
// (carpeta de idioma destino) y el nombre base del archivo; la ruta de origen
// varía entre manifiestos (`en-GB/en-GB.x.ini` vs `language/en-GB.x.ini`).
type langRef struct {
	Tag  string `xml:"tag,attr"`
	Path string `xml:",chardata"`
}

// rawExtension mapea el XML del manifiesto moderno (`<extension>`).
type rawExtension struct {
	XMLName     xml.Name `xml:"extension"`
	Type        string   `xml:"type,attr"`
	Group       string   `xml:"group,attr"`
	Name        string   `xml:"name"`
	LibraryName string   `xml:"libraryname"` // raíz real de una librería: libraries/<libraryname>
	ScriptFile  string   `xml:"scriptfile"`  // script de instalación (relativo al dir del manifiesto)
	Author      string   `xml:"author"`
	Version     string   `xml:"version"`

	Files          Fileset   `xml:"files"`
	Media          []Fileset `xml:"media"`
	Languages      []langRef `xml:"languages>language"` // traducciones de site → language/<tag>/…
	Administration struct {
		Files     Fileset   `xml:"files"`
		Languages []langRef `xml:"languages>language"` // admin → administrator/language/<tag>/…
	} `xml:"administration"`
	UpdateServers struct {
		Servers []string `xml:"server"`
	} `xml:"updateservers"` // fase 2b: URLs del update XML oficial de la extensión
}

// Manifest es el resultado del parseo: metadatos y sus secciones de archivos.
type Manifest struct {
	Type        Type
	Group       string // para plugins
	Name        string
	LibraryName string // solo librerías: raíz = libraries/<LibraryName>
	ScriptFile  string // <scriptfile>: script de instalación, relativo al dir del manifiesto
	Author      string
	Version     string

	Site  Fileset
	Admin Fileset
	Media []Fileset

	// LangDecls son las traducciones declaradas en las secciones <languages>
	// (de site y de administración, unificadas): se instalan en la carpeta de
	// idioma compartida, FUERA de las raíces de la extensión. El cliente real
	// (site/administrator/api) varía por tipo y sección, así que no se fija aquí;
	// el mapeo genera los destinos candidatos y solo atribuye los presentes.
	LangDecls []LangDecl

	// UpdateServers son las URLs declaradas en <updateservers><server> (fase
	// 2b): de ahí se obtiene el update XML oficial para descargar el paquete.
	UpdateServers []string

	Legacy bool // provino de un esquema 1.5 interpretado como mejor esfuerzo
}

// LangDecl es una traducción declarada: su etiqueta de idioma y el nombre del
// archivo instalado (p.ej. Tag="en-GB", Base="en-GB.com_x.ini").
type LangDecl struct {
	Tag  string
	Base string
}

// Parse lee un manifiesto desde r con tope de tamaño, sin resolver entidades
// externas (encoding/xml no lo hace por defecto: XXE neutralizado) y tolerante
// a XML malformado (devuelve error, nunca panic).
func Parse(r io.Reader) (*Manifest, error) {
	limited := io.LimitReader(r, MaxSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("leyendo manifiesto: %w", err)
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("manifiesto excede el tope de %d bytes", MaxSize)
	}

	// Inspecciona el elemento raíz antes de decodificar: distingue "XML válido
	// que no es un manifiesto" (config.xml, access.xml → ErrUnrecognized, se
	// ignora) de "XML genuinamente roto" (error real → malformado).
	root, rootErr := rootElement(data)
	if rootErr != nil {
		return nil, fmt.Errorf("XML de manifiesto inválido: %w", rootErr)
	}
	switch root {
	case "install":
		if m, ok := parseLegacy(data); ok {
			return m, nil
		}
		return nil, ErrUnrecognized
	case "extension":
		// sigue al parseo completo
	default:
		return nil, ErrUnrecognized
	}

	var ext rawExtension
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	dec.Strict = false               // tolera algunas irregularidades reales
	dec.Entity = map[string]string{} // sin entidades personalizadas
	if err := dec.Decode(&ext); err != nil {
		return nil, fmt.Errorf("XML de manifiesto inválido: %w", err)
	}

	m := &Manifest{
		Type:          normalizeType(ext.Type),
		Group:         ext.Group,
		Name:          strings.TrimSpace(ext.Name),
		LibraryName:   strings.TrimSpace(ext.LibraryName),
		ScriptFile:    strings.TrimSpace(ext.ScriptFile),
		Author:        strings.TrimSpace(ext.Author),
		Version:       strings.TrimSpace(ext.Version),
		Site:          ext.Files,
		Admin:         ext.Administration.Files,
		Media:         ext.Media,
		LangDecls:     langDecls(ext.Languages, ext.Administration.Languages),
		UpdateServers: trimmedNonEmpty(ext.UpdateServers.Servers),
	}
	return m, nil
}

// trimmedNonEmpty recorta cada cadena y descarta las que quedan vacías.
func trimmedNonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// langDecls unifica las traducciones de site y administración en (tag, base).
// El tag sale del atributo; si falta, del prefijo del nombre base (`en-GB.x.ini`
// → `en-GB`). La ruta de origen (con o sin subcarpeta) es irrelevante: solo
// importa dónde queda instalado, que depende del cliente, no del manifiesto.
func langDecls(groups ...[]langRef) []LangDecl {
	var out []LangDecl
	for _, g := range groups {
		for _, r := range g {
			raw := strings.TrimSpace(r.Path)
			if raw == "" {
				continue
			}
			base := path.Base(raw)
			tag := strings.TrimSpace(r.Tag)
			if tag == "" {
				if i := strings.IndexByte(base, '.'); i > 0 {
					tag = base[:i]
				}
			}
			if tag == "" {
				continue
			}
			out = append(out, LangDecl{Tag: tag, Base: base})
		}
	}
	return out
}

// rootElement devuelve el nombre del primer elemento del documento, o un error
// si el XML no es siquiera bien formado hasta ahí.
func rootElement(data []byte) (string, error) {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	dec.Strict = false
	dec.Entity = map[string]string{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		if se, ok := tok.(xml.StartElement); ok {
			return se.Name.Local, nil
		}
	}
}

func normalizeType(t string) Type {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "component":
		return Component
	case "module":
		return Module
	case "plugin":
		return Plugin
	case "template":
		return Template
	case "library":
		return Library
	case "file":
		return File
	case "package":
		return Package
	case "language":
		return Language
	}
	return Unknown
}

// legacyInstall mapea el manifiesto 1.5 (<install>).
type legacyInstall struct {
	XMLName xml.Name `xml:"install"`
	Type    string   `xml:"type,attr"`
	Name    string   `xml:"name"`
	Author  string   `xml:"author"`
	Version string   `xml:"version"`
	Files   Fileset  `xml:"files"`
}

// parseLegacy intenta el esquema 1.5 como mejor esfuerzo (R6).
func parseLegacy(data []byte) (*Manifest, bool) {
	var inst legacyInstall
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	dec.Strict = false
	dec.Entity = map[string]string{}
	if err := dec.Decode(&inst); err != nil || inst.XMLName.Local != "install" {
		return nil, false
	}
	return &Manifest{
		Type:    normalizeType(inst.Type),
		Name:    strings.TrimSpace(inst.Name),
		Author:  strings.TrimSpace(inst.Author),
		Version: strings.TrimSpace(inst.Version),
		Site:    inst.Files,
		Legacy:  true,
	}, true
}
