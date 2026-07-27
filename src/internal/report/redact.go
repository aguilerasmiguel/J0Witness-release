package report

import "regexp"

// Barrera 2 de FR-047. La barrera 1 es estructural: la evidencia de
// configuration.php se construye sin valores (corediff.InspectConfig solo
// captura nombres de clave). Esta segunda barrera pasa por el redactor TODO
// el documento serializado antes de emitirlo, por si cualquier ruta de código
// futura arrastrara un valor de configuración a un extracto de evidencia.

// configValueRe captura asignaciones de propiedades sensibles de JConfig con
// su valor entrecomillado. Los delimitadores admiten la forma JSON-escapada
// (\" dentro de un documento ya serializado) además de la literal.
var configValueRe = regexp.MustCompile(
	`(?i)((?:public|var)\s+\$(?:password|secret|user|db|host|smtppass|smtpuser|ftp_pass|ftp_user|log_path|tmp_path)\s*=\s*)(\\?['"])((?:[^'"\\]|\\[^'"])*)(\\?['"])`)

// Redacted es la marca que sustituye a todo valor sensible.
const Redacted = "[REDACTED]"

// Redact aplica la barrera 2 sobre el documento serializado.
func Redact(doc []byte) []byte {
	return configValueRe.ReplaceAll(doc, []byte("${1}${2}"+Redacted+"${4}"))
}
