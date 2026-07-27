package corediff

import (
	"path"
	"strings"
)

// expectedAbsentDefaults son archivos de plantilla/doc que la distribución de
// Joomla incluye y que los sitios configurados borran o renombran de rutina
// (htaccess.txt→.htaccess, robots.txt.dist→robots.txt): su ausencia es normal.
var expectedAbsentDefaults = map[string]bool{
	"LICENSE.txt":     true,
	"README.txt":      true,
	"htaccess.txt":    true,
	"web.config.txt":  true,
	"robots.txt.dist": true,
}

// inertAssetExts son extensiones de asset estático (imagen ráster / fuente) cuya
// ausencia no es señal de manipulación.
var inertAssetExts = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true,
	".ico": true, ".bmp": true, ".woff": true, ".woff2": true, ".ttf": true,
	".eot": true, ".otf": true,
}

// inMissingRuntimeDir: directorios de runtime donde un baseline-ausente es benigno.
// = cacheLogDirs (de execdir.go) + tmp/. OJO: NO writableDirs (ese incluye images/,
// que debe ir a inert_asset/low).
func inMissingRuntimeDir(rel string) bool {
	if rel == "tmp" || strings.HasPrefix(rel, "tmp/") {
		return true
	}
	for _, d := range cacheLogDirs {
		if strings.HasPrefix(rel, d+"/") {
			return true
		}
	}
	return false
}

// ClassifyMissing — ver doc de interfaz. Precedencia: ejecutable > ausencia-esperada
// > asset-inerte > "".
func ClassifyMissing(rel string) string {
	if IsExecutable(rel) {
		return "executable"
	}
	if expectedAbsentDefaults[path.Base(rel)] || inMissingRuntimeDir(rel) {
		return "expected_absent"
	}
	if strings.HasPrefix(rel, "images/") || strings.HasPrefix(rel, "media/") ||
		inertAssetExts[strings.ToLower(path.Ext(rel))] {
		return "inert_asset"
	}
	return ""
}
