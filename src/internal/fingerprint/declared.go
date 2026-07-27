package fingerprint

import (
	"fmt"
	"os"
	"regexp"
)

// Fuentes de la versión declarada. Solo alimentan el hallazgo de discrepancia
// (FR-012); jamás la votación.
var (
	majorRe = regexp.MustCompile(`MAJOR_VERSION\s*=\s*(\d+)`)
	minorRe = regexp.MustCompile(`MINOR_VERSION\s*=\s*(\d+)`)
	patchRe = regexp.MustCompile(`PATCH_VERSION\s*=\s*(\d+)`)
	// Joomla 3.x declara RELEASE ('3.10') + DEV_LEVEL ('12').
	releaseRe  = regexp.MustCompile(`RELEASE\s*=\s*'(\d+\.\d+)'`)
	devLevelRe = regexp.MustCompile(`DEV_LEVEL\s*=\s*'?(\d+)'?`)
	xmlRe      = regexp.MustCompile(`<version>\s*([0-9.]+)\s*</version>`)
)

// declaredSources en orden de preferencia.
var declaredSources = []string{
	"libraries/src/Version.php",
	"administrator/manifests/files/joomla.xml",
	"libraries/cms/version/version.php", // 3.x antiguas
}

// Opener abre una ruta relativa de solo lectura. *safefs.FS la satisface
// directamente; layout.RealizingOpener también (mismo método,
// estructuralmente idéntico) — este paquete no importa layout a propósito
// (fase 2d, Task 6, fix round 1: antes Declared exigía *safefs.FS y abría
// cada src literal tal cual; "administrator/manifests/files/joomla.xml" es
// canónico, así que en un árbol con admin renombrado era inalcanzable y la
// detección de versión declarada quedaba silenciosamente en "" para esa
// fuente — enmascarado en minicms solo porque libraries/src/Version.php
// gana primero, pero árboles reales que dependen de joomla.xml no tendrían
// esa suerte).
type Opener interface {
	Open(rel string) (*os.File, error)
}

// Declared lee la versión que la instalación dice tener. Tolerante a
// manipulación: cualquier fallo de parseo devuelve "" (se declara, no se
// adivina). Lectura vía fsys (normalmente respaldado por safefs), jamás se
// evalúa el PHP (Principio IX).
func Declared(fsys Opener) string {
	for _, src := range declaredSources {
		f, err := fsys.Open(src)
		if err != nil {
			continue
		}
		buf := make([]byte, 64*1024)
		n, _ := f.Read(buf)
		f.Close()
		content := buf[:n]
		if v := parseDeclared(content); v != "" {
			return v
		}
	}
	return ""
}

func parseDeclared(content []byte) string {
	if maj := majorRe.FindSubmatch(content); maj != nil {
		if min := minorRe.FindSubmatch(content); min != nil {
			if pat := patchRe.FindSubmatch(content); pat != nil {
				return fmt.Sprintf("%s.%s.%s", maj[1], min[1], pat[1])
			}
		}
	}
	if rel := releaseRe.FindSubmatch(content); rel != nil {
		if dev := devLevelRe.FindSubmatch(content); dev != nil {
			return fmt.Sprintf("%s.%s", rel[1], dev[1])
		}
	}
	if m := xmlRe.FindSubmatch(content); m != nil {
		return string(m[1])
	}
	return ""
}
