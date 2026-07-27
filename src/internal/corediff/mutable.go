package corediff

import (
	"regexp"
	"sort"
	"strings"
)

// expectedMutable son archivos cuya modificación es esperable en toda
// instalación: se verifica su estructura, no su hash (FR-034).
var expectedMutable = map[string]bool{
	"configuration.php": true,
	".htaccess":         true,
	"robots.txt":        true,
}

// IsExpectedMutable informa de si la ruta se trata estructuralmente.
func IsExpectedMutable(rel string) bool { return expectedMutable[rel] }

// configKeyRe extrae SOLO los nombres de propiedad de configuration.php.
// Deliberadamente no captura los valores: la redacción ocurre por
// construcción, antes de que exista ninguna observación (FR-047, barrera 1).
var configKeyRe = regexp.MustCompile(`(?m)^\s*(?:public|var)\s+\$(\w+)`)

// sensitiveKeys son las claves cuyo valor jamás puede aparecer en ninguna
// salida; se registran solo como presentes.
var sensitiveKeys = map[string]bool{
	"password": true, "secret": true, "user": true, "db": true, "host": true,
	"smtppass": true, "smtpuser": true, "ftp_pass": true, "ftp_user": true,
	"log_path": true, "tmp_path": true,
}

// ConfigStructure es el resultado estructural de configuration.php. Contiene
// exclusivamente forma, nunca valores.
type ConfigStructure struct {
	HasClass      bool     `json:"has_class"`
	KeysPresent   []string `json:"keys_present"`
	SensitiveSeen []string `json:"sensitive_seen"` // claves sensibles presentes (solo el nombre)
	Anomalies     []string `json:"anomalies,omitempty"`
}

// InspectConfig verifica la estructura de configuration.php sin volcar ningún
// valor (Clarificación C5).
func InspectConfig(content []byte) ConfigStructure {
	s := ConfigStructure{HasClass: strings.Contains(string(content), "class JConfig")}
	seen := map[string]bool{}
	for _, m := range configKeyRe.FindAllStringSubmatch(string(content), -1) {
		key := m[1]
		if seen[key] {
			continue
		}
		seen[key] = true
		s.KeysPresent = append(s.KeysPresent, key)
		if sensitiveKeys[strings.ToLower(key)] {
			s.SensitiveSeen = append(s.SensitiveSeen, key)
		}
	}
	sort.Strings(s.KeysPresent)
	sort.Strings(s.SensitiveSeen)
	if !s.HasClass {
		s.Anomalies = append(s.Anomalies, "missing_jconfig_class")
	}
	if suspicious := suspiciousInConfig(content); len(suspicious) > 0 {
		s.Anomalies = append(s.Anomalies, suspicious...)
	}
	return s
}

// suspiciousInConfig detecta construcciones que no pintan nada en un archivo
// de configuración (código ejecutable dinámico).
func suspiciousInConfig(content []byte) []string {
	var out []string
	l := strings.ToLower(string(content))
	for _, frag := range []string{"eval(", "base64_decode", "system(", "shell_exec", "include ", "require "} {
		if strings.Contains(l, frag) {
			out = append(out, "suspicious_fragment:"+strings.TrimRight(frag, "( "))
		}
	}
	sort.Strings(out)
	return out
}
