package acquire

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// T013: SHA-256 siempre, TLSH bajo umbral, magic bytes, omisiones registradas.
func TestHashFilesSmallAndLarge(t *testing.T) {
	dir := t.TempDir()
	small := []byte("<?php echo 'hola mundo, esto supera los cincuenta bytes del minimo tlsh'; ?>")
	os.WriteFile(filepath.Join(dir, "small.php"), small, 0o644)
	big := make([]byte, 4096)
	for i := range big {
		big[i] = byte(i % 251)
	}
	os.WriteFile(filepath.Join(dir, "big.bin"), big, 0o644)
	os.WriteFile(filepath.Join(dir, "tiny.txt"), []byte("x"), 0o644)

	fsys := newFS(t, dir)
	items := Walk(fsys)
	res := HashFiles(fsys, items, 4, 1024) // umbral 1KB → big.bin va por streaming

	s := res["small.php"]
	wantSmall := sha256.Sum256(small)
	if s.SHA256 != hex.EncodeToString(wantSmall[:]) {
		t.Fatalf("sha small: %s", s.SHA256)
	}
	if s.TLSH == "" {
		t.Fatal("small.php debería tener TLSH")
	}
	if s.MagicType == "" {
		t.Fatal("small.php sin magic type")
	}

	b := res["big.bin"]
	wantBig := sha256.Sum256(big)
	if b.SHA256 != hex.EncodeToString(wantBig[:]) {
		t.Fatalf("sha big por streaming incorrecto: %s", b.SHA256)
	}
	if b.TLSH != "" || b.TLSHSkipped != "above-threshold" {
		t.Fatalf("big.bin: tlsh=%q skipped=%q", b.TLSH, b.TLSHSkipped)
	}

	tiny := res["tiny.txt"]
	if tiny.TLSHSkipped != "below-min-size" {
		t.Fatalf("tiny: %q", tiny.TLSHSkipped)
	}
}

// FR-005 / corpus type-mismatch: un .gif con PHP dentro es discrepancia.
func TestMagicMismatch(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "img.gif"), []byte("<?php system($_GET['c']); ?> mas relleno para pasar el minimo"), 0o644)
	fsys := newFS(t, dir)
	res := HashFiles(fsys, Walk(fsys), 1, 1<<20)
	r := res["img.gif"]
	if r == nil || !r.MagicMismatch() {
		t.Fatalf("discrepancia magic/extensión no detectada: %+v", r)
	}
}

// FR-007: archivo sin permiso de lectura → error registrado, nunca silencio.
func TestUnreadableFileRecorded(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignora permisos")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "oculto.php")
	os.WriteFile(p, []byte("x"), 0o644)
	os.Chmod(p, 0o000)
	defer os.Chmod(p, 0o644)
	fsys := newFS(t, dir)
	res := HashFiles(fsys, Walk(fsys), 1, 1<<20)
	if r := res["oculto.php"]; r == nil || r.ReadError == "" {
		t.Fatalf("lectura denegada sin registrar: %+v", res["oculto.php"])
	}
}
