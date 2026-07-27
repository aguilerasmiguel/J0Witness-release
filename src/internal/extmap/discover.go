// Package extmap implementa L3: descubre extensiones consultando el inventario
// ya adquirido (Principio III: no re-recorre), construye el mapa de propiedad
// y emite observaciones ext_* (Principio II). No decide hallazgos: eso es de la
// capa de derivación.
package extmap

import (
	"errors"
	"io"
	"os"

	"j0witness/internal/inventory"
	"j0witness/internal/manifest"
	"j0witness/internal/observe"
)

// Extension es una extensión de terceros descubierta y mapeada.
type Extension struct {
	ManifestPath string
	Type         manifest.Type
	Name         string
	Version      string
	Author       string
	Layout       manifest.Layout
	Legacy       bool
	ElementKey   string // clave estable por tipo (manifest.ExtensionKey): com_x, "group/element", "elem"/"elem@administrator", libraryname
	Group        string // solo plugin: el grupo (system, content, ...)
	ClientAdmin  bool   // true si el extension_path/lado del manifiesto es administrator
}

// Discovered agrupa el resultado del descubrimiento.
type Discovered struct {
	Extensions   []Extension           // de terceros (core-bundled ya excluidas)
	CoreBundled  []string              // rutas de manifiesto omitidas (C2)
	Observations []observe.Observation // ext_discovered, ext_manifest_*
}

// manifestReader lee el contenido de un manifiesto (inyectable para tests).
type manifestReader func(rel string) (io.ReadCloser, error)

// Opener abre una ruta relativa de solo lectura. *safefs.FS la satisface
// directamente; layout.RealizingOpener también (mismo método, estructuralmente
// idéntico) — este paquete no importa layout a propósito: no necesita saber
// qué es un remapeo, solo que rel llega ya lista para abrirse (fase 2d, Task
// 6, fix round 1: antes SafeReader exigía *safefs.FS y abría rel tal cual,
// que en un árbol con admin renombrado es la ruta CANÓNICA, no la real —
// fallaba y Discover lo reportaba como ext_manifest_malformed, un falso
// positivo sobre una extensión legítima).
type Opener interface {
	Open(rel string) (*os.File, error)
}

// SafeReader construye un manifestReader respaldado por o, el opener (solo
// lectura).
func SafeReader(o Opener) manifestReader {
	return func(rel string) (io.ReadCloser, error) {
		return o.Open(rel)
	}
}

// Discover localiza manifiestos en el inventario, los parsea y separa las
// extensiones de terceros de las de serie (core-bundled). isCoreBundled decide
// si un manifiesto pertenece al baseline del core (C2/R3).
func Discover(entries []inventory.Entry, read manifestReader, isCoreBundled func(manifestPath string) bool, nowNS int64) Discovered {
	var res Discovered
	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Type == "file" {
			paths = append(paths, string(e.RelPath))
		}
	}

	for _, cand := range manifest.DiscoverCandidates(paths) {
		if isCoreBundled != nil && isCoreBundled(cand.ManifestPath) {
			res.CoreBundled = append(res.CoreBundled, cand.ManifestPath)
			if o, err := observe.New([]byte(cand.ManifestPath), observe.ExtCoreBundled,
				map[string]any{"reason": "manifiesto presente en el baseline del core"},
				observe.SrcExtmap, observe.High, nowNS); err == nil {
				res.Observations = append(res.Observations, o)
			}
			continue
		}
		rc, err := read(cand.ManifestPath)
		if err != nil {
			if o, e2 := observe.New([]byte(cand.ManifestPath), observe.ExtManifestMalformed,
				map[string]any{"reason": "no pude leer: " + err.Error()},
				observe.SrcExtmap, observe.High, nowNS); e2 == nil {
				res.Observations = append(res.Observations, o)
			}
			continue
		}
		man, err := manifest.Parse(rc)
		rc.Close()
		if err != nil {
			// Un XML válido que simplemente no es un manifiesto (config.xml,
			// access.xml…) se ignora en silencio: no es "malformado", es otro
			// archivo. Solo el XML genuinamente roto o ilegible se reporta.
			if errors.Is(err, manifest.ErrUnrecognized) {
				continue
			}
			if o, e2 := observe.New([]byte(cand.ManifestPath), observe.ExtManifestMalformed,
				map[string]any{"reason": err.Error()},
				observe.SrcExtmap, observe.High, nowNS); e2 == nil {
				res.Observations = append(res.Observations, o)
			}
			continue
		}

		ext := Extension{
			ManifestPath: cand.ManifestPath,
			Type:         man.Type,
			Name:         man.Name,
			Version:      man.Version,
			Author:       man.Author,
			Layout:       man.MapLayout(cand.ManifestPath),
			Legacy:       man.Legacy,
			ElementKey:   manifest.ExtensionKey(man.Type, cand.ManifestPath, man),
			ClientAdmin:  manifest.ClientIsAdmin(cand.ManifestPath),
		}
		if man.Type == manifest.Plugin {
			g, _ := manifest.PluginGroupElement(cand.ManifestPath)
			ext.Group = g
		}
		res.Extensions = append(res.Extensions, ext)

		conf := observe.High
		if man.Legacy {
			conf = observe.Medium
		}
		if o, err := observe.New([]byte(cand.ManifestPath), observe.ExtDiscovered, map[string]any{
			"type":    string(man.Type),
			"name":    man.Name,
			"version": man.Version,
			"author":  man.Author,
			"roots":   ext.Layout.Roots,
			"legacy":  man.Legacy,
		}, observe.SrcExtmap, conf, nowNS); err == nil {
			res.Observations = append(res.Observations, o)
		}
	}
	return res
}
