// Package acquire implementa L0: recorrido único del árbol, stat completo,
// hashes y tipo real (Principio III: adquisición máxima, análisis diferido).
package acquire

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"j0witness/internal/observe"
	"j0witness/internal/safefs"
)

// Item es una entrada descubierta por el walker con su stat crudo.
type Item struct {
	RelPath       string // los strings de Go transportan bytes arbitrarios
	Type          string // file | dir | symlink | other
	Size          int64
	MtimeNS       int64
	CtimeNS       int64
	AtimeNS       int64
	UID           uint32
	GID           uint32
	Mode          uint32
	Inode         uint64
	Nlink         uint64
	SymlinkTarget string
	ReadError     string // motivo si no se pudo stat-ear (FR-007)
	HardlinkDup   bool   // inode ya visto: no se re-procesa
	SymlinkOut    bool   // apunta fuera del árbol
	NonUTF8       bool
}

// Walk recorre el árbol una única vez (FR-001), de forma iterativa (sin
// recursión: aguanta profundidad extrema, FR-052), en orden determinista por
// nombre. No sigue enlaces simbólicos jamás.
func Walk(fsys *safefs.FS) []Item {
	var out []Item
	seen := map[[2]uint64]string{} // (dev,ino) → primera ruta (nlink>1)
	stack := []string{""}

	for len(stack) > 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		des, err := fsys.ReadDir(dir)
		if err != nil {
			if dir != "" {
				out = append(out, Item{RelPath: dir, Type: "dir", ReadError: err.Error()})
			}
			continue
		}
		names := make([]string, 0, len(des))
		for _, de := range des {
			names = append(names, de.Name())
		}
		sort.Strings(names)

		// Apilamos en orden inverso para procesar en orden lexicográfico.
		var subdirs []string
		for _, name := range names {
			rel := name
			if dir != "" {
				rel = dir + "/" + name
			}
			it := statItem(fsys, rel)
			if it.Type == "dir" && it.ReadError == "" {
				subdirs = append(subdirs, rel)
			}
			if it.Type == "file" && it.Nlink > 1 {
				key := [2]uint64{it.Inode, it.Nlink}
				if first, ok := seen[key]; ok && sameInode(fsys, first, rel) {
					it.HardlinkDup = true
				} else {
					seen[key] = rel
				}
			}
			if it.Type == "symlink" {
				it.SymlinkOut = linksOutOfTree(fsys.Root, rel, it.SymlinkTarget)
			}
			if !utf8.ValidString(rel) || strings.ContainsAny(rel, "\n\r") {
				it.NonUTF8 = true
			}
			out = append(out, it)
		}
		for i := len(subdirs) - 1; i >= 0; i-- {
			stack = append(stack, subdirs[i])
		}
	}
	return out
}

func statItem(fsys *safefs.FS, rel string) Item {
	it := Item{RelPath: rel}
	info, err := fsys.Lstat(rel)
	if err != nil {
		it.Type = "other"
		it.ReadError = err.Error()
		return it
	}
	mode := info.Mode()
	switch {
	case mode.IsRegular():
		it.Type = "file"
	case mode.IsDir():
		it.Type = "dir"
	case mode&fs.ModeSymlink != 0:
		it.Type = "symlink"
	default:
		it.Type = "other"
	}
	it.Size = info.Size()
	if st, ok := safefs.RawStat(info); ok {
		it.MtimeNS = st.Mtim.Nano()
		it.CtimeNS = st.Ctim.Nano()
		it.AtimeNS = st.Atim.Nano()
		it.UID = st.Uid
		it.GID = st.Gid
		it.Mode = uint32(st.Mode)
		it.Inode = st.Ino
		it.Nlink = uint64(st.Nlink)
	}
	if it.Type == "symlink" {
		if target, err := fsys.Readlink(rel); err == nil {
			it.SymlinkTarget = target
		}
	}
	return it
}

// sameInode confirma que dos rutas comparten inode real (evita colisión del
// mapa por clave compuesta).
func sameInode(fsys *safefs.FS, a, b string) bool {
	ia, err1 := fsys.Lstat(a)
	ib, err2 := fsys.Lstat(b)
	if err1 != nil || err2 != nil {
		return false
	}
	sa, oka := safefs.RawStat(ia)
	sb, okb := safefs.RawStat(ib)
	return oka && okb && sa.Ino == sb.Ino && sa.Dev == sb.Dev
}

// linksOutOfTree resuelve el destino del enlace relativo a su directorio y
// comprueba si queda fuera de la raíz.
func linksOutOfTree(root, rel, target string) bool {
	if target == "" {
		return false
	}
	var resolved string
	if filepath.IsAbs(target) {
		resolved = filepath.Clean(target)
	} else {
		resolved = filepath.Clean(filepath.Join(root, filepath.Dir(rel), target))
	}
	relToRoot, err := filepath.Rel(root, resolved)
	if err != nil {
		return true
	}
	return relToRoot == ".." || strings.HasPrefix(relToRoot, ".."+string(filepath.Separator))
}

// WalkObservations deriva las observaciones de recorrido (Principio V: "no
// pude mirar" nunca es silencio).
func WalkObservations(items []Item, nowNS int64) []observe.Observation {
	var obs []observe.Observation
	add := func(o observe.Observation, err error) {
		if err == nil {
			obs = append(obs, o)
		}
	}
	for _, it := range items {
		p := []byte(it.RelPath)
		if it.ReadError != "" {
			add(observe.New(p, observe.ReadDenied, map[string]any{"reason": it.ReadError}, observe.SrcAcquire, observe.High, nowNS))
		}
		if it.SymlinkOut {
			add(observe.New(p, observe.SymlinkOutOfTree, map[string]any{"target": observe.DisplayPath([]byte(it.SymlinkTarget))}, observe.SrcAcquire, observe.High, nowNS))
		}
		if it.HardlinkDup {
			add(observe.New(p, observe.HardlinkCycle, map[string]any{"inode": it.Inode}, observe.SrcAcquire, observe.High, nowNS))
		}
		if it.NonUTF8 {
			add(observe.New(p, observe.NonUTF8Path, map[string]any{"display": observe.DisplayPath(p)}, observe.SrcAcquire, observe.High, nowNS))
		}
	}
	return obs
}
