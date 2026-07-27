package baseline

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"j0witness/internal/inventory"
)

// joomlaDownloadURL es la vía canónica de los paquetes oficiales (R5).
func joomlaDownloadURL(version string) string {
	return fmt.Sprintf(
		"https://github.com/joomla/joomla-cms/releases/download/%s/Joomla_%s-Stable-Full_Package.zip",
		version, version)
}

// Fetch descarga el paquete oficial de una release, lo verifica contra el
// catálogo y lo incorpora. El cliente HTTP de los baselines del CORE se
// construye AQUÍ; el de los baselines de EXTENSIÓN, en extbaseline.Fetch.
// Cada ruta de red es opt-in (--allow-network) y se enumera en stderr antes
// de tocarla (Principio VIII, FR-023).
func Fetch(stderr io.Writer, cat *Catalog, store *inventory.Store, rel Release, cacheDir string) (string, string, error) {
	url := joomlaDownloadURL(rel.Version)
	fmt.Fprintf(stderr, "j0witness: network-fetch url=%s expected_sha256=%s\n", url, rel.PackageSHA256)

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", "", fmt.Errorf("descargando %s: %w", rel.Version, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("descarga de %s: HTTP %d", rel.Version, resp.StatusCode)
	}
	// El caché puede no existir todavía: fetch es lo primero que ejecuta un
	// usuario nuevo, y Add solo crea el subdirectorio packages/ más adelante.
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", "", fmt.Errorf("creando el caché %s: %w", cacheDir, err)
	}
	tmp, err := os.CreateTemp(cacheDir, "fetch-*.zip")
	if err != nil {
		return "", "", err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return "", "", err
	}
	tmp.Close()
	// Add verifica el sha256 contra el catálogo antes de aceptar nada.
	return Add(cat, store, tmpPath, cacheDir)
}
