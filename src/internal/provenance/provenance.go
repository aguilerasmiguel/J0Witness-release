// Package provenance reúne los metadatos que hacen reproducible y defendible
// un informe (Principio IV) y el modelo de amenaza declarado (Principio VII).
package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// Version la fija el build via -ldflags; "dev" fuera de release.
var Version = "dev"

// ThreatModel declara bajo qué supuesto son válidas las conclusiones.
type ThreatModel string

const (
	// ModelPrimary: atacante con privilegios del usuario del servidor web,
	// sin root. Bajo este modelo ctime es un ancla temporal fiable.
	ModelPrimary ThreatModel = "webserver-user-no-root"
	// ModelDegraded: se detectaron indicadores fuera del modelo primario;
	// la confianza de los hallazgos temporales queda degradada.
	ModelDegraded ThreatModel = "degraded-system-level-indicators"
)

// Provenance es el bloque de procedencia del informe.
type Provenance struct {
	ToolVersion    string
	ToolHash       string
	Invocation     []string
	ThreatModel    ThreatModel
	CatalogVersion string
	RulesetVersion string
	NetworkUsed    bool
}

// SelfHash calcula el SHA-256 del binario en ejecución. Si no puede leerse
// (p.ej. plataformas sin /proc), devuelve "unknown" en lugar de fallar: la
// procedencia degradada se declara, no se inventa.
func SelfHash() string {
	exe, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	f, err := os.Open(exe)
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(h.Sum(nil))
}
