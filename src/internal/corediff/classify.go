package corediff

import (
	"sort"
	"strings"

	"j0witness/internal/baseline"
	"j0witness/internal/inventory"
	"j0witness/internal/observe"
)

// Input reúne lo que necesita la clasificación: el inventario ya adquirido
// (las capas posteriores consultan el inventario, no el filesystem — FR-001)
// y el baseline verificado.
type Input struct {
	Entries  []inventory.Entry // de EntriesByRun (orden estable)
	Manifest map[string]baseline.ManifestEntry
	Content  *baseline.Content // contenido original para diffs (puede ser nil)
	// Known es la tabla ruta→hashes del catálogo, ya indexada por el llamante.
	Known map[string][]string
	// ReadFile lee el contenido observado de una ruta relativa; el scan
	// inyecta un lector respaldado por safefs (solo lectura). Puede ser nil.
	ReadFile func(rel string) ([]byte, error)
	NowNS    int64
}

// Result es el resultado de la clasificación FR-030.
type Result struct {
	Identical    int
	Observations []observe.Observation
}

// Classify clasifica cada archivo frente al baseline: idéntico, modificado,
// ausente, ajeno a la distribución u obsoleto conocido (FR-030), con las
// distinciones de FR-032/033/034/035. Orden de salida estable.
func Classify(in Input) Result {
	var res Result
	add := func(o observe.Observation, err error) {
		if err == nil {
			res.Observations = append(res.Observations, o)
		}
	}

	manifestPaths := make([]string, 0, len(in.Manifest))
	for p := range in.Manifest {
		manifestPaths = append(manifestPaths, p)
	}
	sort.Strings(manifestPaths)
	core := coreDirs(manifestPaths)

	treeFiles := map[string]inventory.Entry{}
	for _, e := range in.Entries {
		if e.Type == "file" {
			treeFiles[string(e.RelPath)] = e
		}
	}

	// 1) Archivos del árbol frente al manifiesto (orden estable de entries).
	for _, e := range in.Entries {
		if e.Type != "file" || e.ReadError != "" {
			continue
		}
		rel := string(e.RelPath)
		want, inManifest := in.Manifest[rel]
		switch {
		case inManifest && want.SHA256 == e.SHA256:
			res.Identical++
		case inManifest:
			classifyModified(&res, add, rel, e, in)
		case IsExpectedMutable(rel):
			classifyMutable(add, rel, in)
		default:
			classifyForeign(&res, add, rel, e, in, core)
		}
	}

	// 2) Archivos del manifiesto ausentes del árbol (orden estable). El
	// directorio installation/ lo elimina el instalador de Joomla en toda
	// instalación legítima: si falta COMPLETO, se colapsa a una única
	// observación esperada; si está parcialmente presente, cada ausencia
	// cuenta (los restos de installation/ son sospechosos).
	installerPresent := false
	for p := range treeFiles {
		if strings.HasPrefix(p, installerDir) {
			installerPresent = true
			break
		}
	}
	// Rutas ausentes (excluyendo installation/ si está completo, que va aparte).
	present := map[string]bool{}
	for p := range treeFiles {
		present[p] = true
	}
	var missingNonInstaller []string
	installerMissing := 0
	for _, p := range manifestPaths {
		if _, ok := treeFiles[p]; ok {
			continue
		}
		if !installerPresent && strings.HasPrefix(p, installerDir) {
			installerMissing++
			continue
		}
		missingNonInstaller = append(missingNonInstaller, p)
	}
	// missingNonInstaller ya está ordenado (manifestPaths venía ordenado).

	subtrees, collapsed := CollapseMissingSubtrees(missingNonInstaller, present)
	// Individuales: los ausentes que NO cayeron en un subárbol colapsado (D5b).
	for _, p := range missingNonInstaller {
		if collapsed[p] {
			continue
		}
		add(observe.New([]byte(p), observe.FileMissing,
			map[string]any{
				"expected_sha256": in.Manifest[p].SHA256,
				"expected_size":   in.Manifest[p].Size,
				"missing_class":   ClassifyMissing(p),
			},
			observe.SrcCorediff, observe.High, in.NowNS))
	}
	// Una observación colapsada por subárbol.
	for _, st := range subtrees {
		add(observe.New([]byte(st.Dir), observe.FileMissing,
			map[string]any{
				"subtree_collapsed": true,
				"files_missing":     st.Count,
				"missing_class":     st.Class,
				"sample":            st.Sample,
			},
			observe.SrcCorediff, observe.High, in.NowNS))
	}
	if installerMissing > 0 {
		add(observe.New([]byte(strings.TrimSuffix(installerDir, "/")), observe.FileMissing,
			map[string]any{"expected_post_install": true, "files_missing": installerMissing},
			observe.SrcCorediff, observe.High, in.NowNS))
	}
	return res
}

// installerDir es el directorio que el instalador de Joomla elimina al
// completar la instalación.
const installerDir = "installation/"

// classifyModified analiza un archivo cuyo hash difiere del baseline.
func classifyModified(res *Result, add func(observe.Observation, error), rel string, e inventory.Entry, in Input) {
	original, haveContent := in.Content.Get(rel)
	if haveContent {
		observed := readObserved(in, rel)
		if observed != nil && EOLOnly(original, observed) {
			add(observe.New(e.RelPath, observe.EOLNormalization,
				map[string]any{"baseline_sha256": in.Manifest[rel].SHA256, "observed_sha256": e.SHA256},
				observe.SrcCorediff, observe.High, in.NowNS))
			return
		}
		if observed != nil && IsTextType(e.MagicType) {
			d := DiffText(original, observed)
			add(observe.New(e.RelPath, observe.FileModified, map[string]any{
				"baseline_sha256": in.Manifest[rel].SHA256,
				"observed_sha256": e.SHA256,
				"degree":          d.Degree(),
				"lines_added":     d.LinesAdded,
				"lines_removed":   d.LinesRemoved,
				"hunks":           d.Hunks,
				"injection":       d.Injection,
				"executable":      IsExecutable(rel),
				"binary":          false,
			}, observe.SrcCorediff, observe.High, in.NowNS))
			return
		}
	}
	// Sin contenido original o binario: modificación constatada por hash.
	add(observe.New(e.RelPath, observe.FileModified, map[string]any{
		"baseline_sha256":      in.Manifest[rel].SHA256,
		"observed_sha256":      e.SHA256,
		"degree":               1.0,
		"binary_or_no_content": true,
		"executable":           IsExecutable(rel),
		"binary":               !IsTextType(e.MagicType),
	}, observe.SrcCorediff, observe.Medium, in.NowNS))
}

// classifyMutable trata los archivos cuya modificación es esperable (FR-034):
// verificación estructural, nunca de hash. La evidencia se construye SIN
// valores (FR-047, barrera 1: redacción por construcción).
func classifyMutable(add func(observe.Observation, error), rel string, in Input) {
	observed := readObserved(in, rel)
	if observed == nil {
		return
	}
	switch rel {
	case "configuration.php":
		s := InspectConfig(observed)
		add(observe.New([]byte(rel), observe.ConfigStructure, map[string]any{
			"file":           rel,
			"has_class":      s.HasClass,
			"keys_present":   s.KeysPresent,
			"sensitive_seen": s.SensitiveSeen,
			"anomalies":      s.Anomalies,
		}, observe.SrcCorediff, observe.High, in.NowNS))
	case "robots.txt":
		add(observe.New([]byte(rel), observe.ConfigStructure, map[string]any{
			"file": rel, "anomalies": []string{},
		}, observe.SrcCorediff, observe.High, in.NowNS))
	}
}

// classifyForeign trata archivos que la distribución no contiene.
func classifyForeign(res *Result, add func(observe.Observation, error), rel string, e inventory.Entry, in Input, core map[string]bool) {
	switch CheckObsolete(rel, e.SHA256, in.Known) {
	case ObsoleteKnownHash:
		add(observe.New(e.RelPath, observe.FileObsoleteKnown, map[string]any{
			"hash_matches_history": true, "sha256": e.SHA256,
		}, observe.SrcCorediff, observe.High, in.NowNS))
		return
	case ObsoleteUnknownHash:
		add(observe.New(e.RelPath, observe.FileObsoleteKnown, map[string]any{
			"hash_matches_history": false, "sha256": e.SHA256,
			"executable": IsExecutable(rel),
			"binary":     !IsTextType(e.MagicType),
		}, observe.SrcCorediff, observe.High, in.NowNS))
		return
	}
	executable := IsExecutable(rel)
	forbidden := executable && InForbiddenExecDir(rel)
	// Solo leemos la cabecera en la ruta crítica (ejecutable en zona de
	// escritura): reconocer un artefacto de runtime de Joomla evita un falso
	// crítico. readObserved lee vía el lector diferido inyectado (safefs).
	runtimeArtifact := false
	if forbidden {
		runtimeArtifact = IsJoomlaRuntimeArtifact(rel, readObserved(in, rel))
	}
	add(observe.New(e.RelPath, observe.FileUnexpected, map[string]any{
		"sha256":            e.SHA256,
		"magic":             e.MagicType,
		"executable":        executable,
		"in_core_dir":       InCoreDir(rel, core),
		"in_forbidden_exec": forbidden,
		"runtime_artifact":  runtimeArtifact,
	}, observe.SrcCorediff, observe.High, in.NowNS))
}

// readObserved lee el contenido observado de una ruta consultando el lector
// diferido inyectado en Input (el inventario guarda hashes, no contenidos).
func readObserved(in Input, rel string) []byte {
	if in.ReadFile == nil {
		return nil
	}
	b, err := in.ReadFile(rel)
	if err != nil {
		return nil
	}
	return b
}
