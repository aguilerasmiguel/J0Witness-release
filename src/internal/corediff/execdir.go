package corediff

import (
	"path"
	"strings"
)

// writableDirs son los directorios de escritura conocidos de una instalación
// Joomla: la distribución no coloca ningún ejecutable en ellos, así que un
// PHP ahí es hallazgo de máxima severidad (FR-035).
var writableDirs = []string{
	"images", "cache", "tmp", "logs",
	"administrator/cache", "administrator/logs",
	"media/cache",
}

// executableExts son extensiones que el servidor puede ejecutar.
var executableExts = map[string]bool{
	".php": true, ".phar": true, ".phtml": true, ".php3": true, ".php4": true,
	".php5": true, ".php7": true, ".pht": true,
}

// IsExecutable informa de si el nombre apunta a un ejecutable del servidor.
func IsExecutable(rel string) bool {
	return executableExts[strings.ToLower(path.Ext(rel))]
}

// InForbiddenExecDir informa de si la ruta cae en un directorio de escritura
// donde la distribución no coloca ejecutables.
func InForbiddenExecDir(rel string) bool {
	for _, d := range writableDirs {
		if strings.HasPrefix(rel, d+"/") {
			return true
		}
	}
	return false
}

// IsWritablePath informa de si rel cae bajo un directorio de escritura conocido
// de Joomla (images/, media/, cache/, tmp/, logs/, administrator/cache, …). Solo
// por ruta (sin contenido); usado por la capa de deriva para segregar el churn.
func IsWritablePath(rel string) bool {
	for _, w := range writableDirs {
		if rel == w || strings.HasPrefix(rel, w+"/") {
			return true
		}
	}
	return false
}

// coreDirs deriva del manifiesto los directorios de primer nivel que posee la
// distribución (excluyendo los de escritura): un archivo ajeno ahí es
// J0W-CORE-004.
func coreDirs(manifestPaths []string) map[string]bool {
	dirs := map[string]bool{}
	for _, p := range manifestPaths {
		if i := strings.IndexByte(p, '/'); i > 0 {
			dirs[p[:i]] = true
		}
	}
	for _, w := range writableDirs {
		if i := strings.IndexByte(w, '/'); i < 0 {
			delete(dirs, w)
		}
	}
	return dirs
}

// InCoreDir informa de si la ruta cae bajo un directorio del core (según el
// manifiesto) fuera de las zonas de escritura.
func InCoreDir(rel string, core map[string]bool) bool {
	if InForbiddenExecDir(rel) {
		return false
	}
	i := strings.IndexByte(rel, '/')
	if i <= 0 {
		return true // raíz de la instalación: territorio de la distribución
	}
	return core[rel[:i]]
}

// cacheLogDirs son los directorios de escritura donde Joomla SÍ genera
// ejecutables propios (caché compilada, logs con guarda). Subconjunto de
// writableDirs: images/ y tmp/ quedan fuera a propósito.
var cacheLogDirs = []string{
	"cache", "logs", "administrator/cache", "administrator/logs", "media/cache",
}

// runtimeGuards son las cabeceras con que Joomla marca sus artefactos de
// caché/logs para que no sean legibles por web (ya sin el "<?php" inicial,
// que se comprueba y descarta aparte: Joomla separa la apertura PHP de la
// guarda con un espacio en unos artefactos y con un salto de línea en
// otros, p.ej. autoload_psr4.php). Conjunto cerrado (Principio VI).
var runtimeGuards = []string{
	`die(`,
	`defined('_JEXEC') or die`,
}

// IsJoomlaRuntimeArtifact reconoce los ejecutables que el propio Joomla genera
// en sus directorios de caché y logs: la ruta cae en cacheLogDirs Y la cabecera
// (tras descartar la racha inicial de comentarios '#'/espacio en blanco, en
// los primeros 256 bytes) empieza por una guarda conocida. Los logs reales de
// Joomla son ficheros de comentarios '#' orientados a línea cuya guarda va en
// la segunda línea ("#\n#<?php die(...)"), no en la primera como en caché
// compilada ("#<?php die(...)"); recortar toda la racha de '#'/blancos
// iniciales alcanza la guarda "<?php" en ambos casos manteniendo el ámbito a
// caché/logs y sin tocar el conjunto cerrado de guardas admitidas. Es un
// superconjunto del recorte de un solo '#' anterior: todo lo que reconocía
// antes lo sigue reconociendo. Reconocerlos evita 30 falsos críticos por
// instalación.
//
// Residuo aceptado (declarado en la spec): un webshell que prefije una guarda y
// viva en caché/logs también supera esta comprobación; por eso el llamante
// DEGRADA a info pero no suprime, y el cierre real es el análisis de contenido
// de la feature 003.
func IsJoomlaRuntimeArtifact(rel string, head []byte) bool {
	inDir := false
	for _, d := range cacheLogDirs {
		if strings.HasPrefix(rel, d+"/") {
			inDir = true
			break
		}
	}
	if !inDir {
		return false
	}
	s := string(head)
	if len(s) > 256 {
		s = s[:256]
	}
	s = strings.TrimLeft(s, "#\n\r\t ")
	if !strings.HasPrefix(s, "<?php") {
		return false
	}
	s = strings.TrimSpace(strings.TrimPrefix(s, "<?php"))
	for _, g := range runtimeGuards {
		if strings.HasPrefix(s, g) {
			return true
		}
	}
	return false
}
