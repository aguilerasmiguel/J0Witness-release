package layout

import (
	"os"
	"path/filepath"
	"testing"

	"j0witness/internal/safefs"
)

func mkTree(t *testing.T, dirs ...string) *safefs.FS {
	t.Helper()
	root := t.TempDir()
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fsys, err := safefs.New(root)
	if err != nil {
		t.Fatal(err)
	}
	return fsys
}

func TestDetectAdmin_Standard(t *testing.T) {
	fsys := mkTree(t,
		"administrator/components",
		"administrator/manifests",
		"administrator/includes",
	)
	res := DetectAdmin(fsys)
	if !res.Standard {
		t.Fatalf("esperaba Standard=true, obtuve %+v", res)
	}
	if res.AdminDirFound != "" {
		t.Fatalf("esperaba AdminDirFound vacío en árbol estándar, obtuve %q", res.AdminDirFound)
	}
}

func TestDetectAdmin_Renamed(t *testing.T) {
	fsys := mkTree(t,
		"panel/components",
		"panel/manifests",
		"panel/includes",
		"components", // raíz de sitio conocida: no debe confundirse con el admin
		"modules",
	)
	res := DetectAdmin(fsys)
	if res.Standard {
		t.Fatalf("esperaba Standard=false, obtuve %+v", res)
	}
	if res.AdminDirFound != "panel" {
		t.Fatalf("esperaba AdminDirFound=%q, obtuve %q", "panel", res.AdminDirFound)
	}
}

func TestDetectAdmin_NoSkeletonAnywhere(t *testing.T) {
	fsys := mkTree(t,
		"components",
		"modules",
		"templates",
	)
	res := DetectAdmin(fsys)
	if res.Standard {
		t.Fatalf("esperaba Standard=false, obtuve %+v", res)
	}
	if res.AdminDirFound != "" {
		t.Fatalf("esperaba AdminDirFound vacío, obtuve %q", res.AdminDirFound)
	}
}

func TestDetectAdmin_DeterministicOrderPicksFirstAlphabetically(t *testing.T) {
	// Dos candidatos con esqueleto completo: debe elegir el primero en orden
	// alfabético (Principio IV: determinismo, sin depender de orden de disco).
	fsys := mkTree(t,
		"zzz/components", "zzz/manifests", "zzz/includes",
		"aaa/components", "aaa/manifests", "aaa/includes",
	)
	res := DetectAdmin(fsys)
	if res.Standard {
		t.Fatalf("esperaba Standard=false, obtuve %+v", res)
	}
	if res.AdminDirFound != "aaa" {
		t.Fatalf("esperaba AdminDirFound=%q (orden determinista), obtuve %q", "aaa", res.AdminDirFound)
	}
}

func TestDetectAdmin_EmptyTree(t *testing.T) {
	fsys := mkTree(t)
	res := DetectAdmin(fsys)
	if res.Standard {
		t.Fatalf("esperaba Standard=false en árbol vacío, obtuve %+v", res)
	}
	if res.AdminDirFound != "" {
		t.Fatalf("esperaba AdminDirFound vacío, obtuve %q", res.AdminDirFound)
	}
}
