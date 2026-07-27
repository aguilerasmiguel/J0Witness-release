package provenance

// Principio VII: cuando se detectan indicadores fuera del modelo primario
// (manipulación del reloj / timestomping), J0Witness lo declara y degrada la
// confianza de los hallazgos temporales en lugar de seguir afirmando.

// ThreatIndicator es un indicador de salida del modelo de amenaza.
type ThreatIndicator struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
}

// clockSlackNS tolera desajustes normales de metadatos (2 s).
const clockSlackNS = 2_000_000_000

// TimestampAnomaly evalúa un stat crudo: bajo el modelo primario (atacante
// sin root) ctime no puede fijarse a voluntad, así que mtime posterior a
// ctime con margen indica manipulación explícita de timestamps.
func TimestampAnomaly(mtimeNS, ctimeNS int64) bool {
	return mtimeNS > ctimeNS+clockSlackNS
}

// Assess decide el modelo declarable: si hay indicadores de manipulación
// temporal, el modelo pasa a degradado.
func Assess(anomalies []ThreatIndicator) ThreatModel {
	if len(anomalies) > 0 {
		return ModelDegraded
	}
	return ModelPrimary
}
