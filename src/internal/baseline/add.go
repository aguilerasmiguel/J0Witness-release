package baseline

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"j0witness/internal/inventory"
	"j0witness/internal/observe"
)

// Add incorpora un paquete oficial aportado por el usuario (FR-022): verifica
// su SHA-256 contra el catálogo (FR-021), deriva el manifiesto ruta→hash, lo
// persiste y retiene el paquete en el caché (los diffs de texto necesitan el
// contenido original, FR-031). Rechaza paquetes cuyo hash no figura en el
// catálogo.
func Add(cat *Catalog, store *inventory.Store, pkgPath, cacheDir string) (version string, manifestSHA string, err error) {
	raw, err := os.ReadFile(pkgPath)
	if err != nil {
		return "", "", fmt.Errorf("leyendo paquete: %w", err)
	}
	sum := sha256.Sum256(raw)
	pkgSHA := hex.EncodeToString(sum[:])
	rel, ok := cat.FindByPackageSHA(pkgSHA)
	if !ok {
		return "", "", fmt.Errorf("el hash del paquete (%s) no figura en el catálogo: no puede usarse como verdad de referencia (Principio VIII)", pkgSHA)
	}

	files, manifestSHA, err := manifestFromZip(raw)
	if err != nil {
		return "", "", fmt.Errorf("derivando manifiesto de %s: %w", rel.Version, err)
	}
	if _, err := store.SaveBaseline(cat.CMS, rel.Version, pkgSHA, manifestSHA, "local-add", time.Now().UnixNano(), files); err != nil {
		return "", "", err
	}
	if cacheDir != "" {
		if err := os.MkdirAll(filepath.Join(cacheDir, "packages"), 0o755); err != nil {
			return "", "", err
		}
		if err := os.WriteFile(packagePath(cacheDir, rel.Version), raw, 0o644); err != nil {
			return "", "", err
		}
	}
	return rel.Version, manifestSHA, nil
}

func packagePath(cacheDir, version string) string {
	return filepath.Join(cacheDir, "packages", version+".zip")
}

// Content da acceso al contenido original de un baseline cacheado.
type Content struct {
	files map[string][]byte
}

// OpenContent carga en memoria índice→contenido del paquete cacheado de una
// versión (los paquetes minicms/joomla caben con holgura; el acceso es de
// solo lectura sobre el caché, jamás sobre el objetivo).
func OpenContent(cacheDir, version, wantSHA string) (*Content, error) {
	raw, err := os.ReadFile(packagePath(cacheDir, version))
	if err != nil {
		return nil, fmt.Errorf("paquete de %s no está en caché: %w", version, err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); wantSHA != "" && got != wantSHA {
		return nil, fmt.Errorf("%w: %s esperado %s, hay %s", ErrPackageMismatch, version, wantSHA, got)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, err
	}
	c := &Content{files: map[string][]byte{}}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		c.files[f.Name] = b
	}
	return c, nil
}

// Get devuelve el contenido original de una ruta del baseline.
func (c *Content) Get(rel string) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	b, ok := c.files[rel]
	return b, ok
}

// manifestFromZip extrae ruta→hash de un paquete zip, en orden estable, y
// calcula el hash del manifiesto completo.
func manifestFromZip(raw []byte) ([]inventory.Entry, string, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, "", err
	}
	var files []inventory.Entry
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, "", err
		}
		h := sha256.New()
		n, err := io.Copy(h, rc)
		rc.Close()
		if err != nil {
			return nil, "", err
		}
		files = append(files, inventory.Entry{
			RelPath:     []byte(f.Name),
			PathDisplay: observe.DisplayPath([]byte(f.Name)),
			SHA256:      hex.EncodeToString(h.Sum(nil)),
			Size:        n,
		})
	}
	sort.Slice(files, func(i, j int) bool { return bytes.Compare(files[i].RelPath, files[j].RelPath) < 0 })
	return files, manifestSHA(files), nil
}

// manifestSHA canonicaliza ruta→hash en un único hash de manifiesto: ordena
// por RelPath y concatena "sha  ruta\n" (Size no participa: sólo identidad de
// contenido y ubicación). Compartida por manifestFromZip y Verify para que la
// re-derivación en la verificación sea byte-idéntica a la que Add persistió.
func manifestSHA(files []inventory.Entry) string {
	sorted := append([]inventory.Entry(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i].RelPath, sorted[j].RelPath) < 0 })
	mh := sha256.New()
	for _, f := range sorted {
		fmt.Fprintf(mh, "%s  %s\n", f.SHA256, f.RelPath)
	}
	return hex.EncodeToString(mh.Sum(nil))
}

// Manifest carga el manifiesto de un baseline ya incorporado como mapa
// ruta→(sha256, size).
type ManifestEntry struct {
	SHA256 string
	Size   int64
}

func Manifest(store *inventory.Store, cms, version string) (map[string]ManifestEntry, error) {
	id, _, _, _, err := store.FindBaseline(cms, version)
	if err != nil {
		return nil, err
	}
	files, err := store.BaselineFiles(id)
	if err != nil {
		return nil, err
	}
	out := make(map[string]ManifestEntry, len(files))
	for _, f := range files {
		out[string(f.RelPath)] = ManifestEntry{SHA256: f.SHA256, Size: f.Size}
	}
	return out, nil
}
