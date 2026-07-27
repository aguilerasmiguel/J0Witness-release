package extmap

import (
	"sort"

	"j0witness/internal/inventory"
	"j0witness/internal/manifest"
	"j0witness/internal/observe"
)

// VerifyExtensions compara los archivos instalados de cada extensión
// (componente) contra su baseline oficial cacheado (obtenido vía lookup),
// SOLO cuando la versión instalada coincide con la del baseline (Principio
// VI: sin esa correspondencia exacta no hay comparación posible, y no se
// emite ninguna observación). Emite ext_file_verified / ext_file_modified /
// ext_official_missing, en orden determinista: las rutas del baseline se
// ordenan antes de recorrerlas (Principio IV — nunca se itera un map
// directamente para producir salida).
// isVerifiableType indica si el tipo de extensión participa en la
// verificación contra baseline (los 5 tipos con clave de elemento estable).
func isVerifiableType(t manifest.Type) bool {
	switch t {
	case manifest.Component, manifest.Module, manifest.Plugin, manifest.Template, manifest.Library:
		return true
	}
	return false
}

func VerifyExtensions(exts []Extension, entries []inventory.Entry,
	lookup func(element, version string) (files map[string]string, source string, ok bool), nowNS int64) []observe.Observation {

	installed := map[string]string{}
	for _, e := range entries {
		if e.Type == "file" {
			installed[e.PathDisplay] = e.SHA256
		}
	}

	var obs []observe.Observation
	for _, ext := range exts {
		if !isVerifiableType(ext.Type) {
			continue
		}
		element := ext.ElementKey
		baseline, source, ok := lookup(element, ext.Version)
		if !ok {
			continue // sin baseline o versión distinta → no verificable, no se compara
		}

		// Orden estable: nunca se recorre el map directamente para emitir.
		paths := make([]string, 0, len(baseline))
		for p := range baseline {
			paths = append(paths, p)
		}
		sort.Strings(paths)

		add := func(p string, typ observe.Type, ev map[string]any) {
			ev["extension"] = element
			ev["verification_source"] = source
			if o, err := observe.New([]byte(p), typ, ev, observe.SrcExtmap, observe.High, nowNS); err == nil {
				obs = append(obs, o)
			}
		}
		for _, p := range paths {
			officialSHA := baseline[p]
			gotSHA, present := installed[p]
			switch {
			case !present:
				add(p, observe.ExtOfficialMissing, map[string]any{})
			case gotSHA == officialSHA:
				add(p, observe.ExtFileVerified, map[string]any{"executable": isExecutable(p)})
			default:
				add(p, observe.ExtFileModified, map[string]any{"executable": isExecutable(p)})
			}
		}
	}
	return obs
}
