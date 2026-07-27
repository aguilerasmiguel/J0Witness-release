package extbaseline

import (
	"fmt"
	"os"
	"time"

	"j0witness/internal/inventory"
	"j0witness/internal/manifest"
)

// Add lee el paquete de una extensión ya instalada (identidad y raíces reales
// en target, resueltas por el llamante vía readInstalledExtension), simula su
// instalación y cachea su baseline (source "package") bajo target.ElementKey.
// Offline; el admin avala que el paquete es el oficial.
//
// installedVersion es la versión detectada en el árbol instalado; se acepta
// por simetría con Fetch y para uso informativo del llamante, pero Add NO la
// exige como gate: a diferencia de Fetch (donde el paquete llega de la red y
// una versión distinta a la instalada es la señal de que el update server
// respondió con algo inesperado), aquí el operador entrega el paquete a mano y
// lo avala explícitamente, sea cual sea la versión que declare — incluida una
// versión que aún no está instalada (cachear baselines por adelantado) o que
// ya no lo está (el recipe de corpus "versión no coincidente" depende de
// exactamente esto: cachear un baseline bajo una versión que NUNCA calzará
// con la instalada, para comprobar que VerifyExtensions no compara nada en
// ese caso, Principio VI). El baseline se guarda bajo la versión que el
// PAQUETE declara (simVersion), no bajo installedVersion.
func Add(store *inventory.Store, target manifest.InstallTarget, installedVersion, pkgPath string) (string, int, error) {
	raw, err := os.ReadFile(pkgPath)
	if err != nil {
		return "", 0, fmt.Errorf("leyendo paquete: %w", err)
	}
	simVersion, files, pkgSHA, err := SimulateExtension(target, raw)
	if err != nil {
		return "", 0, err
	}
	entries := make([]inventory.Entry, 0, len(files))
	for installed, sha := range files {
		entries = append(entries, inventory.Entry{
			RelPath: []byte(installed), PathDisplay: installed, SHA256: sha, Type: "file",
		})
	}
	if _, err := store.SaveExtensionBaseline(target.ElementKey, simVersion, pkgSHA, "package", time.Now().UnixNano(), entries); err != nil {
		return "", 0, err
	}
	return simVersion, len(entries), nil
}
