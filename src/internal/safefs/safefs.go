// Package safefs es la única puerta de acceso al árbol objetivo (Principio I:
// evidencia inmutable). Expone exclusivamente operaciones de lectura; ningún
// otro paquete abre archivos del objetivo directamente.
package safefs

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// FS da acceso de solo lectura a un árbol enraizado en Root.
type FS struct {
	Root string
	// noatimeFailed recuerda que O_NOATIME fue rechazado (sin privilegio);
	// se degrada silenciosamente a apertura normal (Principio I).
	noatimeFailed bool
}

// New crea un FS de solo lectura sobre root (debe ser absoluta).
func New(root string) (*FS, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	return &FS{Root: abs}, nil
}

// Open abre un archivo del árbol en modo estrictamente lectura, intentando
// O_NOATIME para no alterar el atime cuando el privilegio lo permite.
func (f *FS) Open(rel string) (*os.File, error) {
	full := filepath.Join(f.Root, rel)
	if !f.noatimeFailed {
		file, err := os.OpenFile(full, os.O_RDONLY|syscall.O_NOATIME, 0) //nolint:forbidigo // única apertura legítima del objetivo, flags solo lectura
		if err == nil {
			return file, nil
		}
		if pe, ok := err.(*os.PathError); ok && pe.Err == syscall.EPERM {
			// Sin privilegio para O_NOATIME (solo el propietario o root):
			// degradación silenciosa, recordada para el resto del escaneo.
			f.noatimeFailed = true
		} else {
			return nil, err
		}
	}
	return os.OpenFile(full, os.O_RDONLY, 0) //nolint:forbidigo // solo lectura
}

// Lstat devuelve los atributos de la entrada sin seguir enlaces simbólicos.
func (f *FS) Lstat(rel string) (fs.FileInfo, error) {
	return os.Lstat(filepath.Join(f.Root, rel))
}

// ReadDir lista un directorio del árbol sin ordenar (el llamante ordena para
// garantizar determinismo).
func (f *FS) ReadDir(rel string) ([]os.DirEntry, error) {
	return os.ReadDir(filepath.Join(f.Root, rel))
}

// Readlink devuelve el destino de un enlace simbólico.
func (f *FS) Readlink(rel string) (string, error) {
	return os.Readlink(filepath.Join(f.Root, rel))
}

// RawStat expone el stat crudo del sistema (ctime, inode, nlink...) sin capas
// intermedias (Principio III).
func RawStat(info fs.FileInfo) (*syscall.Stat_t, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	return st, ok
}
