package extbaseline

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"j0witness/internal/inventory"
	"j0witness/internal/manifest"
)

const maxBody = 64 << 20 // tope anti-DoS para XML y paquete

// Fetch resuelve y descarga el paquete oficial de una extensión (identidad y
// raíces reales en target, resueltas por el llamante vía
// readInstalledExtension) vía su update server, y cachea su baseline (source
// "updateserver") bajo target.ElementKey. Un ÚNICO cliente HTTP, construido
// aquí y solo aquí (Principio VIII). El caller ya comprobó --allow-network.
// installedVersion acota la comparación a la versión real. site es la ruta
// del sitio (la misma que recibió readInstalledExtension): Fetch no la usa
// para localizar nada — target ya trae todo lo necesario — pero SÍ la
// necesita para armar sugerencias `extension add <elemento> <sitio>
// <paquete.zip>` correctas (add es de 3 argumentos desde fase 2c).
func Fetch(stderr io.Writer, store *inventory.Store, target manifest.InstallTarget, site, updateURL, installedVersion string) (string, int, error) {
	element := target.ElementKey
	client := &http.Client{Timeout: 5 * time.Minute}

	fmt.Fprintf(stderr, "j0witness: network-fetch url=%s (update xml de %s)\n", updateURL, element)
	xmlRaw, err := get(client, updateURL)
	if err != nil {
		return "", 0, fmt.Errorf("descargando update xml: %w", err)
	}
	entries, err := ParseUpdates(xmlRaw)
	if err != nil {
		return "", 0, err
	}
	entry, err := ResolveUpdate(entries, element, installedVersion)
	if err != nil {
		if errors.Is(err, ErrNoMatchingVersion) {
			return "", 0, fmt.Errorf("el update server no ofrece la versión instalada (%s) de %s; aporta el paquete con: j0witness extension add %s %s <paquete.zip>", installedVersion, element, element, site)
		}
		return "", 0, fmt.Errorf("%w; usa: j0witness extension add %s %s <paquete.zip>", err, element, site)
	}
	if entry.DownloadURL == "" {
		return "", 0, fmt.Errorf("la entrada de %s %s no trae URL de descarga; usa: j0witness extension add %s %s <paquete.zip>", element, installedVersion, element, site)
	}

	fmt.Fprintf(stderr, "j0witness: network-fetch url=%s (paquete de %s %s)\n", entry.DownloadURL, element, installedVersion)
	pkg, err := get(client, entry.DownloadURL)
	if err != nil {
		return "", 0, fmt.Errorf("descargando el paquete (¿requiere clave de suscripción?): %w; usa: j0witness extension add %s %s <paquete.zip>", err, element, site)
	}
	// Verifica el sha256 del paquete si el XML lo declara.
	if entry.SHA256 != "" {
		sum := sha256Hex(pkg)
		if sum != entry.SHA256 {
			return "", 0, fmt.Errorf("el paquete descargado de %s no coincide con el sha256 del update server (esperado %s, hay %s); usa: j0witness extension add %s %s <paquete.zip>", element, entry.SHA256, sum, element, site)
		}
	}

	version, files, pkgSHA, err := SimulateExtension(target, pkg)
	if err != nil {
		return "", 0, err
	}
	if version != installedVersion {
		return "", 0, fmt.Errorf("el paquete declara versión %s, no la instalada %s; usa: j0witness extension add %s %s <paquete.zip>", version, installedVersion, element, site)
	}
	entriesDB := make([]inventory.Entry, 0, len(files))
	for installed, sha := range files {
		entriesDB = append(entriesDB, inventory.Entry{RelPath: []byte(installed), PathDisplay: installed, SHA256: sha, Type: "file"})
	}
	if _, err := store.SaveExtensionBaseline(element, version, pkgSHA, "updateserver", time.Now().UnixNano(), entriesDB); err != nil {
		return "", 0, err
	}
	return version, len(entriesDB), nil
}

func get(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// Falla en voz alta ante una respuesta sobredimensionada en vez de
	// truncarla en silencio (mismo patrón que manifest.Parse y acquire/hash.go):
	// lee un byte de más y compara contra el tope real.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBody {
		return nil, fmt.Errorf("la respuesta de %s excede el tope de %d bytes", url, maxBody)
	}
	return data, nil
}
