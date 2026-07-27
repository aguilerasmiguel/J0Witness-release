// Package layout ejecuta un pre-flight de estructura: detecta si el árbol
// tiene el directorio de administración estándar de Joomla (administrator/)
// o si el esqueleto admin vive en otro sitio (renombrado por endurecimiento o
// para ocultar el panel). Solo detecta y declara (Principio VII); no remapea
// ni corrige nada — eso queda para un incremento posterior.
package layout

import (
	"sort"

	"j0witness/internal/safefs"
)

// skeletonMarkers son los subdirectorios cuya presencia conjunta dentro de un
// directorio de primer nivel lo identifica como raíz de administración de
// Joomla.
var skeletonMarkers = []string{"components", "manifests", "includes"}

// knownSiteRoots son los directorios de primer nivel que jamás son el admin
// renombrado: son las raíces conocidas de un sitio Joomla estándar. Se
// excluyen de la búsqueda para no confundir, p. ej., el components/ del sitio
// (que también contiene subdirectorios, pero no es la raíz admin).
var knownSiteRoots = map[string]bool{
	"components": true,
	"modules":    true,
	"plugins":    true,
	"templates":  true,
	"libraries":  true,
	"media":      true,
	"images":     true,
	"language":   true,
	"cache":      true,
	"tmp":        true,
	"api":        true,
	"includes":   true,
}

// Result es el veredicto del pre-flight de layout.
type Result struct {
	Standard      bool   // true si administrator/ existe con el esqueleto reconocible.
	AdminDirFound string // nombre del directorio candidato a admin renombrado; "" si Standard o si no se encontró ninguno.
}

// DetectAdmin comprueba si el árbol tiene un directorio administrator/ con el
// esqueleto reconocible (components/, manifests/, includes/). Si no lo tiene,
// recorre los directorios de primer nivel en orden determinista (excluyendo
// las raíces de sitio conocidas) buscando el primero que tenga el mismo
// esqueleto, y lo reporta como candidato a admin renombrado. Solo lectura
// (Principio I); solo detección, no remapea nada.
func DetectAdmin(fsys *safefs.FS) Result {
	if hasSkeleton(fsys, "administrator") {
		return Result{Standard: true}
	}

	root, err := fsys.ReadDir(".")
	if err != nil {
		return Result{Standard: false}
	}

	var candidates []string
	for _, e := range root {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "administrator" || knownSiteRoots[name] {
			continue
		}
		candidates = append(candidates, name)
	}
	sort.Strings(candidates)

	for _, name := range candidates {
		if hasSkeleton(fsys, name) {
			return Result{Standard: false, AdminDirFound: name}
		}
	}
	return Result{Standard: false}
}

// hasSkeleton comprueba si dir (relativo a la raíz del árbol) contiene los
// tres subdirectorios marcadores del esqueleto de administración de Joomla.
func hasSkeleton(fsys *safefs.FS, dir string) bool {
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return false
	}
	present := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			present[e.Name()] = true
		}
	}
	for _, marker := range skeletonMarkers {
		if !present[marker] {
			return false
		}
	}
	return true
}
