package finding

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrSuppressions envuelve cualquier fallo al cargar/parsear el archivo de
// exclusiones (--exclusions inválido o ilegible). Es un error de uso (FR-045):
// los llamadores deben poder distinguirlo con errors.Is para mapearlo a
// ExitUsageError, no a un error interno.
var ErrSuppressions = errors.New("exclusiones inválidas")

// Suppression es una entrada del archivo de exclusiones declarativo (FR-045):
// el motivo es obligatorio y lo suprimido queda reflejado en el informe.
type Suppression struct {
	Rule    string   `yaml:"rule" json:"rule_id"`
	Path    string   `yaml:"path" json:"path_glob"`
	Reason  string   `yaml:"reason" json:"reason"`
	Matched []string `yaml:"-" json:"matched_findings"`
}

// LoadSuppressions parsea el archivo de exclusiones. Cada entrada exige
// motivo; sin motivo, el archivo entero se rechaza: suprimir sin explicar es
// "aceptar y olvidar" (Principio VI).
func LoadSuppressions(pathFile string) ([]*Suppression, error) {
	if pathFile == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(pathFile)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSuppressions, err)
	}
	var sups []*Suppression
	if err := yaml.Unmarshal(raw, &sups); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSuppressions, err)
	}
	for i, s := range sups {
		if strings.TrimSpace(s.Reason) == "" {
			return nil, fmt.Errorf("%w: exclusión %d (%s %s): el motivo es obligatorio (FR-045)", ErrSuppressions, i+1, s.Rule, s.Path)
		}
		if s.Rule == "" || s.Path == "" {
			return nil, fmt.Errorf("%w: exclusión %d: rule y path son obligatorios", ErrSuppressions, i+1)
		}
	}
	return sups, nil
}

// Apply marca los hallazgos suprimidos y anota qué capturó cada supresión.
func Apply(findings []Finding, sups []*Suppression) []Finding {
	for i := range findings {
		for _, s := range sups {
			if s.Rule == findings[i].RuleID && globMatch(s.Path, findings[i].Subject) {
				findings[i].SuppressedBy = s
				s.Matched = append(s.Matched, findings[i].ID)
				break
			}
		}
	}
	return findings
}

// globMatch: '*' no cruza '/', '**' sí; sin comodines exige igualdad exacta.
func globMatch(pattern, subject string) bool {
	if strings.Contains(pattern, "**") {
		prefix := strings.SplitN(pattern, "**", 2)[0]
		return strings.HasPrefix(subject, prefix)
	}
	ok, err := path.Match(pattern, subject)
	return err == nil && ok
}
