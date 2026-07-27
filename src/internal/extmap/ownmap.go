package extmap

import (
	"sort"
	"strings"

	"j0witness/internal/inventory"
	"j0witness/internal/manifest"
	"j0witness/internal/observe"
)

// executableExts son las extensiones que el servidor puede ejecutar (misma
// lista que corediff; un ejecutable no declarado es la señal de máxima
// prioridad).
var executableExts = map[string]bool{
	".php": true, ".phar": true, ".phtml": true, ".php3": true, ".php4": true,
	".php5": true, ".php7": true, ".pht": true,
}

func isExecutable(rel string) bool {
	i := strings.LastIndexByte(rel, '.')
	if i < 0 {
		return false
	}
	return executableExts[strings.ToLower(rel[i:])]
}

// BuildOwnership construye el mapa de propiedad y emite las observaciones de
// propiedad, no-declarados, ausentes y conflictos. Consume las extensiones
// descubiertas y las entradas del inventario (no re-recorre).
//
// flagFolderExecs (opt-in, C1 revisada): cuando es true, un ejecutable dentro
// de una carpeta declarada pero no enumerado individualmente se emite como
// ext_owns_folder_exec (→ J0W-EXT-002 medium). Por defecto (false) esos
// archivos se tratan como poseídos silenciosos, porque los componentes reales
// declaran carpetas llenas de PHP legítimo y marcarlos todos violaría SC-100 y
// el Principio VI (falso positivo no caracterizado → opt-in).
func BuildOwnership(exts []Extension, entries []inventory.Entry, flagFolderExecs bool, nowNS int64) []observe.Observation {
	var obs []observe.Observation
	add := func(o observe.Observation, err error) {
		if err == nil {
			obs = append(obs, o)
		}
	}

	// Índice de archivos del árbol (orden estable ya garantizado por la 001).
	files := make([]string, 0, len(entries))
	present := map[string]bool{}
	for _, e := range entries {
		if e.Type == "file" {
			p := string(e.RelPath)
			files = append(files, p)
			present[p] = true
		}
	}

	// owners[path] = extensiones que la reclaman, con la especificidad de la
	// reclamación (exacta vs por carpeta) para resolver conflictos (Principio II).
	owners := map[string][]claim{}

	for _, ext := range exts {
		extID := ext.Name
		if extID == "" {
			extID = ext.ManifestPath
		}
		// La identidad para detectar conflictos es el manifiesto (único),
		// no el nombre declarado (dos extensiones distintas pueden declarar
		// el mismo nombre).
		ownerID := ext.ManifestPath

		// El propio manifiesto es parte de la extensión: se atribuye (si no,
		// quedaría como file_unexpected → J0W-CORE-004).
		add(observe.New([]byte(ext.ManifestPath), observe.ExtOwnsPath,
			map[string]any{"extension": extID, "declaration": "manifest", "executable": isExecutable(ext.ManifestPath)},
			observe.SrcExtmap, observe.High, nowNS))

		// 1) Recorremos el árbol de la extensión (sus raíces) y clasificamos
		//    cada archivo presente: declarado / declarado-en-carpeta-exec / no
		//    declarado.
		for _, p := range files {
			if !ext.Layout.InRoots(p) {
				continue
			}
			if p == ext.ManifestPath {
				continue // el propio manifiesto no es "contenido" sospechoso
			}
			owned, viaFolder := ext.Layout.Owns(p)
			switch {
			case owned && !viaFolder:
				owners[p] = append(owners[p], claim{ownerID, false})
				add(observe.New([]byte(p), observe.ExtOwnsPath,
					map[string]any{"extension": extID, "declaration": "file", "executable": isExecutable(p)},
					observe.SrcExtmap, observe.High, nowNS))
			case owned && viaFolder && isExecutable(p) && flagFolderExecs:
				// C1 opt-in: ejecutable dentro de carpeta declarada, no
				// enumerado. Solo con --flag-folder-execs (alta FP en real).
				add(observe.New([]byte(p), observe.ExtOwnsFolderExec,
					map[string]any{"extension": extID, "folder_declared": true},
					observe.SrcExtmap, observe.High, nowNS))
			case owned && viaFolder:
				// Por defecto: poseído silencioso (contenido normal de una
				// carpeta declarada, ejecutable o no).
				owners[p] = append(owners[p], claim{ownerID, true})
				add(observe.New([]byte(p), observe.ExtOwnsPath,
					map[string]any{"extension": extID, "declaration": "folder", "executable": isExecutable(p)},
					observe.SrcExtmap, observe.High, nowNS))
			default:
				// Presente en el árbol de la extensión, no declarado.
				add(observe.New([]byte(p), observe.ExtUndeclared,
					map[string]any{"extension": extID, "executable": isExecutable(p)},
					observe.SrcExtmap, observe.High, nowNS))
			}
		}

		// 1b) Traducciones <languages>: viven en la carpeta de idioma compartida,
		// FUERA de las raíces de la extensión, así que no las cubre el barrido
		// anterior. Se atribuyen por ruta exacta (declaración de máxima
		// especificidad): un .ini de idioma presente y declarado es de esta
		// extensión, no de la extensión "propietaria" de la carpeta (D2).
		for _, lf := range ext.Layout.LanguageFiles {
			if !present[lf] {
				continue // traducción opcional ausente: sin señal
			}
			owners[lf] = append(owners[lf], claim{ownerID, false})
			add(observe.New([]byte(lf), observe.ExtOwnsPath,
				map[string]any{"extension": extID, "declaration": "language", "executable": isExecutable(lf)},
				observe.SrcExtmap, observe.High, nowNS))
		}

		// 2) Declaraciones exactas (filename) que la extensión promete pero no
		//    están en el árbol (FR-122: declarado-ausente).
		for _, d := range ext.Layout.Declarations {
			if d.Kind == manifest.DeclFile && !present[d.Path] {
				add(observe.New([]byte(d.Path), observe.ExtDeclaredMissing,
					map[string]any{"extension": extID},
					observe.SrcExtmap, observe.Medium, nowNS))
			}
		}
	}

	// 3) Conflictos: rutas reclamadas por más de una extensión. La declaración
	// exacta (file/language) es MÁS ESPECÍFICA que la de carpeta: si algún
	// propietario reclama por ruta exacta, los que solo la contienen por carpeta
	// quedan subordinados y no cuentan como conflicto (el archivo de idioma que
	// una extensión declara vive en la carpeta que el pack de idioma posee por
	// completo, y es de la extensión, no del pack). Solo hay conflicto entre
	// reclamaciones de la misma especificidad efectiva.
	conflictPaths := make([]string, 0)
	effective := map[string][]string{}
	for p, cs := range owners {
		effective[p] = resolveOwners(cs)
		if len(effective[p]) > 1 {
			conflictPaths = append(conflictPaths, p)
		}
	}
	sort.Strings(conflictPaths)
	for _, p := range conflictPaths {
		add(observe.New([]byte(p), observe.ExtOwnershipConflict,
			map[string]any{"extensions": effective[p]},
			observe.SrcExtmap, observe.High, nowNS))
	}
	return obs
}

// claim es una reclamación de propiedad de una ruta: quién y con qué
// especificidad (exacta vs recursiva por carpeta).
type claim struct {
	owner     string
	viaFolder bool
}

// resolveOwners aplica la precedencia "exacto gana a carpeta": si hay alguna
// reclamación exacta, devuelve solo los propietarios exactos (dedup); si no,
// los propietarios por carpeta. Determinista (ordenado).
func resolveOwners(cs []claim) []string {
	var exact, folder []string
	for _, c := range cs {
		if c.viaFolder {
			folder = append(folder, c.owner)
		} else {
			exact = append(exact, c.owner)
		}
	}
	if len(exact) > 0 {
		return dedup(exact)
	}
	return dedup(folder)
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
