package safefs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrPreflight identifica fallos de las condiciones del Principio I; el CLI
// los mapea a PREFLIGHT_FAILED (exit 3).
var ErrPreflight = errors.New("preflight")

// Preflight verifica, antes de tocar nada, que se pueden garantizar las
// condiciones del Principio I: el objetivo existe, es un directorio legible y
// no se solapa con el workdir ni con el directorio de caché.
func Preflight(target string, stateDirs ...string) error {
	tAbs, err := resolve(target)
	if err != nil {
		return fmt.Errorf("%w: objetivo inaccesible: %v", ErrPreflight, err)
	}
	info, err := os.Stat(tAbs)
	if err != nil {
		return fmt.Errorf("%w: objetivo inaccesible: %v", ErrPreflight, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: el objetivo no es un directorio: %s", ErrPreflight, target)
	}
	if _, err := os.ReadDir(tAbs); err != nil {
		return fmt.Errorf("%w: el objetivo no es legible: %v", ErrPreflight, err)
	}
	for _, sd := range stateDirs {
		if sd == "" {
			continue
		}
		sAbs, err := resolve(sd)
		if err != nil {
			// El workdir puede no existir aún: resolvemos su ancestro.
			sAbs = absClean(sd)
		}
		if contains(tAbs, sAbs) {
			return fmt.Errorf("%w: el directorio de estado %s está dentro del objetivo %s (Principio I)", ErrPreflight, sd, target)
		}
		if contains(sAbs, tAbs) {
			return fmt.Errorf("%w: el objetivo %s está dentro del directorio de estado %s (Principio I)", ErrPreflight, target, sd)
		}
	}
	return nil
}

// resolve devuelve la ruta absoluta con symlinks resueltos si existe; si no
// existe, resuelve el ancestro existente más profundo y reancla el resto.
func resolve(p string) (string, error) {
	abs := absClean(p)
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r, nil
	}
	dir, base := filepath.Split(abs)
	dir = strings.TrimSuffix(dir, string(filepath.Separator))
	if dir == "" || dir == abs {
		return abs, os.ErrNotExist
	}
	parent, err := resolve(dir)
	if err != nil {
		return abs, err
	}
	return filepath.Join(parent, base), nil
}

func absClean(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return filepath.Clean(abs)
}

// contains informa de si child está dentro de parent (o son iguales).
func contains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
