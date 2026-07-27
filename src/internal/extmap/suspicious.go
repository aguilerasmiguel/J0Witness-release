package extmap

import (
	"j0witness/internal/manifest"
	"j0witness/internal/observe"
)

// DetectSuspicious aplica el criterio operativo cerrado de FR-132/J0W-EXT-004
// (no umbral difuso — Principio VI): un manifiesto es sospechoso cuando declara
// una ruta que, tras el mapeo declarado→instalado, cae FUERA de todas las
// raíces de instalación de su tipo. Editar el manifiesto para legitimar un
// archivo plantado en `images/`, la raíz del sitio, u otro destino ajeno a la
// extensión produce exactamente eso. Una declaración legítima multi-raíz
// (site + admin + media) no dispara, porque cada ruta cae en una raíz propia.
func DetectSuspicious(exts []Extension, nowNS int64) []observe.Observation {
	var obs []observe.Observation
	for _, ext := range exts {
		for _, d := range ext.Layout.Declarations {
			if !ext.Layout.InRoots(d.Path) {
				extID := ext.Name
				if extID == "" {
					extID = ext.ManifestPath
				}
				if o, err := observe.New([]byte(ext.ManifestPath), observe.ExtManifestSuspicious,
					map[string]any{
						"extension":        extID,
						"declared_path":    d.Path,
						"outside_roots":    true,
						"declaration_kind": kindName(d.Kind),
					}, observe.SrcExtmap, observe.High, nowNS); err == nil {
					obs = append(obs, o)
				}
			}
		}
	}
	return obs
}

func kindName(k manifest.DeclKind) string {
	if k == manifest.DeclFolder {
		return "folder"
	}
	return "file"
}
