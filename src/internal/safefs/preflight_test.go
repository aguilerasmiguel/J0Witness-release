package safefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// T007: rechazo si objetivo ⊆ workdir o workdir ⊆ objetivo, resolviendo
// symlinks; objetivo inexistente o ilegible → ErrPreflight.
func TestPreflightOverlap(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "site")
	inside := filepath.Join(target, "work")
	outside := filepath.Join(root, "work")
	for _, d := range []string{target, inside, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name    string
		target  string
		state   string
		wantErr bool
	}{
		{"disjuntos", target, outside, false},
		{"workdir dentro del objetivo", target, inside, true},
		{"objetivo dentro del workdir", inside, target, true},
		{"iguales", target, target, true},
		{"workdir inexistente fuera", target, filepath.Join(root, "nuevo", "estado"), false},
		{"workdir inexistente dentro", target, filepath.Join(target, "nuevo"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Preflight(c.target, c.state)
			if c.wantErr && !errors.Is(err, ErrPreflight) {
				t.Fatalf("esperaba ErrPreflight, obtuve %v", err)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("no esperaba error: %v", err)
			}
		})
	}
}

func TestPreflightSymlinkResolution(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "site")
	if err := os.MkdirAll(filepath.Join(target, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	// workdir apuntando por symlink dentro del objetivo → rechazo.
	if err := Preflight(target, filepath.Join(link, "sub")); !errors.Is(err, ErrPreflight) {
		t.Fatalf("symlink no resuelto: %v", err)
	}
}

func TestPreflightMissingTarget(t *testing.T) {
	if err := Preflight(filepath.Join(t.TempDir(), "no-existe")); !errors.Is(err, ErrPreflight) {
		t.Fatal("objetivo inexistente debe fallar preflight")
	}
}
