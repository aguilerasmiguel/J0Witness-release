// Package extbaseline simula la instalación de un paquete de extensión (como
// dato, jamás ejecutándolo) para derivar sus hashes oficiales por ruta
// instalada. Soporta todos los tipos de extensión (fase 2c), no solo
// componentes.
package extbaseline

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"j0witness/internal/manifest"
)

const (
	// maxPkgUncompressed acota el TOTAL de bytes descomprimidos del paquete
	// (anti zip-bomb): fetch.go limita el tamaño COMPRIMIDO, pero un zip puede
	// expandir muchísimo. Falla ruidosamente antes de agotar memoria (Principio IX).
	maxPkgUncompressed = 512 << 20 // 512 MiB — holgado para paquetes reales
	// maxPkgEntries acota el número de archivos (un zip bomb también puede ser
	// millones de entradas diminutas).
	maxPkgEntries = 20000
)

// tipoLabel es el nombre en español del tipo de extensión, usado solo en los
// mensajes de error de ambigüedad de manifiesto (mismo texto que ya
// producía SimulateComponent para el caso componente, ahora generalizado).
func tipoLabel(t manifest.Type) string {
	switch t {
	case manifest.Component:
		return "componente"
	case manifest.Module:
		return "módulo"
	case manifest.Plugin:
		return "plugin"
	case manifest.Template:
		return "plantilla"
	case manifest.Library:
		return "librería"
	case manifest.Language:
		return "idioma"
	case manifest.File:
		return "archivo"
	case manifest.Package:
		return "paquete"
	default:
		return string(t)
	}
}

// SimulateExtension extrae el paquete oficial de una extensión y devuelve,
// por ruta instalada, el sha256 del archivo que el instalador colocaría en
// las raíces reales de target (Principio IX: el paquete se parsea y hashea
// como DATO, jamás se ejecuta; el mapeo es aritmética pura de rutas).
//
// target ya trae resueltas las raíces reales de instalación (ver
// manifest.InstallTarget / ResolveInstall): el paquete por sí solo no las
// determina sin ambigüedad (p.ej. el `element` de un componente, o si un
// módulo es de site o de administración). Verifica que el manifiesto del
// paquete declara el MISMO tipo que target.Type; si no, es un paquete que no
// corresponde a la extensión instalada y se rechaza.
//
// Soporta los dos layouts de paquete que usa Joomla:
//   - con prefijo (`<files folder="site">…`): todo lo que hay bajo esa
//     carpeta del paquete se mapea a la raíz de destino.
//   - plano (`<files><filename>x.php</filename><folder>tmpl</folder></files>`,
//     sin `folder=`): solo las entradas declaradas EXPLÍCITAMENTE
//     (`<filename>`/`<file>`/`<folder>`), relativas a la raíz del paquete, se
//     mapean a la raíz de destino (Principio: nada declarado, nada atribuido —
//     jamás se inventan/adivinan archivos no declarados).
func SimulateExtension(target manifest.InstallTarget, pkgRaw []byte) (string, map[string]string, string, error) {
	pkgSHA := sha256Hex(pkgRaw)

	zr, err := zip.NewReader(bytes.NewReader(pkgRaw), int64(len(pkgRaw)))
	if err != nil {
		return "", nil, "", fmt.Errorf("abriendo paquete: %w", err)
	}

	// Índice nombre→contenido (los paquetes de extensión caben en memoria, pero
	// con topes anti zip-bomb: total descomprimido y número de entradas).
	if len(zr.File) > maxPkgEntries {
		return "", nil, "", fmt.Errorf("el paquete contiene demasiados archivos (%d, tope %d): posible zip bomb", len(zr.File), maxPkgEntries)
	}
	content := map[string][]byte{}
	var totalUncompressed int64
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", nil, "", err
		}
		remaining := maxPkgUncompressed - totalUncompressed
		b, err := io.ReadAll(io.LimitReader(rc, remaining+1))
		rc.Close()
		if err != nil {
			return "", nil, "", err
		}
		if int64(len(b)) > remaining {
			return "", nil, "", fmt.Errorf("el paquete excede el tope de descompresión de %d bytes: posible zip bomb", maxPkgUncompressed)
		}
		totalUncompressed += int64(len(b))
		content[path.Clean(f.Name)] = b
	}

	// Localiza el manifiesto: un .xml en la raíz del paquete que parsee como
	// extensión del MISMO tipo que target. Recorre en orden determinista
	// (sort.Strings) y recoge TODOS los candidatos: la línea base forense no
	// puede elegir uno al azar entre iteraciones de mapa (Principio IV). Si hay
	// más de uno, la ambigüedad se reporta como error explícito en vez de
	// resolverse en silencio.
	names := make([]string, 0, len(content))
	for name := range content {
		names = append(names, name)
	}
	sort.Strings(names)

	var manCandidates []string
	parsed := map[string]*manifest.Manifest{}
	for _, name := range names {
		if strings.Contains(name, "/") || !strings.HasSuffix(name, ".xml") {
			continue
		}
		if pm, err := manifest.Parse(bytes.NewReader(content[name])); err == nil && pm.Type == target.Type {
			manCandidates = append(manCandidates, name)
			parsed[name] = pm
		}
	}
	switch len(manCandidates) {
	case 0:
		return "", nil, "", fmt.Errorf("el paquete no contiene un manifiesto de %s en la raíz", tipoLabel(target.Type))
	case 1:
		// único candidato: continúa.
	default:
		return "", nil, "", fmt.Errorf("el paquete contiene múltiples manifiestos de %s en la raíz: %s", tipoLabel(target.Type), strings.Join(manCandidates, ", "))
	}
	manName := manCandidates[0]
	m := parsed[manName]

	// put registra el hash de una ruta instalada. Una ruta ya vista con el
	// MISMO hash es idempotente (inofensiva); con hash DISTINTO es una colisión
	// ambigua del paquete (dos orígenes distintos mapean a la misma ruta
	// instalada) y debe fallar: la línea base no puede tener dos verdades para
	// la misma ruta (Principio IV).
	files := map[string]string{}
	put := func(installed string, b []byte) error {
		h := sha256Hex(b)
		if existing, ok := files[installed]; ok && existing != h {
			return fmt.Errorf("colisión de ruta instalada en el paquete: %s", installed)
		}
		files[installed] = h
		return nil
	}

	// El manifiesto y el scriptfile viven en el directorio real donde
	// Joomla instala el .xml (para componentes, la raíz de administración).
	if err := put(target.ManifestDir+"/"+manName, content[manName]); err != nil {
		return "", nil, "", err
	}
	if m.ScriptFile != "" {
		if b, ok := content[path.Clean(m.ScriptFile)]; ok {
			if err := put(target.ManifestDir+"/"+m.ScriptFile, b); err != nil {
				return "", nil, "", err
			}
		}
	}

	// Mapea una sección <files>/<administration><files>/<media> del paquete a
	// dstRoot, soportando los dos layouts:
	//   - con folder= (prefijo): todo lo que hay bajo fs.Folder/ → dstRoot.
	//   - plano (sin folder=): SOLO las entradas declaradas explícitamente
	//     (<filename>/<file>/<folder>), relativas a la raíz del paquete.
	mapFileset := func(fs manifest.Fileset, dstRoot string) error {
		if dstRoot == "" {
			return nil
		}
		if fs.Folder != "" {
			prefix := strings.Trim(fs.Folder, "/") + "/"
			for _, name := range names {
				if strings.HasPrefix(name, prefix) {
					if err := put(dstRoot+"/"+name[len(prefix):], content[name]); err != nil {
						return err
					}
				}
			}
			return nil
		}
		for _, fn := range append(append([]string{}, fs.Filenames...), fs.Files...) {
			rel := strings.Trim(strings.TrimSpace(fn), "/")
			if rel == "" {
				continue
			}
			if b, ok := content[rel]; ok {
				if err := put(dstRoot+"/"+rel, b); err != nil {
					return err
				}
			}
		}
		for _, fd := range fs.Folders {
			fd = strings.Trim(strings.TrimSpace(fd), "/")
			if fd == "" {
				continue
			}
			for _, name := range names {
				if name == fd || strings.HasPrefix(name, fd+"/") {
					if err := put(dstRoot+"/"+name, content[name]); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}

	if err := mapFileset(m.Site, target.FilesRoot); err != nil {
		return "", nil, "", err
	}
	if err := mapFileset(m.Admin, target.AdminFilesRoot); err != nil {
		return "", nil, "", err
	}
	for _, md := range m.Media {
		dest := md.Dest
		if dest == "" {
			dest = target.MediaFallback
		}
		if err := mapFileset(md, target.MediaBase+"/"+dest); err != nil {
			return "", nil, "", err
		}
	}

	return m.Version, files, pkgSHA, nil
}

// SimulateComponent extrae el paquete de un componente y devuelve, por ruta
// instalada, el sha256 del archivo que el instalador colocaría. element es el
// com_X de destino (el paquete no lo determina sin ambigüedad). No ejecuta
// nada. Wrapper 2a-compatible: construye el InstallTarget de componente
// formulaico desde element y delega en SimulateExtension.
func SimulateComponent(element string, pkgRaw []byte) (string, map[string]string, string, error) {
	target := manifest.InstallTarget{
		Type:           manifest.Component,
		ElementKey:     element,
		FilesRoot:      "components/" + element,
		AdminFilesRoot: "administrator/components/" + element,
		MediaBase:      "media",
		MediaFallback:  element,
		ManifestDir:    "administrator/components/" + element,
	}
	return SimulateExtension(target, pkgRaw)
}

// sha256Hex es el sha256 hexadecimal de b (factorizado: lo usan
// SimulateExtension y, en fase 2b, Fetch para verificar el hash que declara
// el update server).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
