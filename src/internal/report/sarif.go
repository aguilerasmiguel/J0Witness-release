package report

import (
	"encoding/json"
	"fmt"
	"sort"
)

// RenderSARIF es una proyección derivada del documento JSON canónico: se genera
// DESDE el JSON ya emitido, nunca desde el análisis (Principio X). Función PURA
// y DETERMINISTA del informe: mismo JSON → mismos bytes SARIF 2.1.0.
//
// El renderizador NO introduce prosa en lenguaje natural: message.text une la
// prosa YA RESUELTA (observed/rationale) con puntuación neutra, así que el SARIF
// hereda el idioma del informe (i18n-free). alternative_hypothesis/compared_to
// van a properties, no al mensaje.
func RenderSARIF(canonical []byte) ([]byte, error) {
	var r Report
	if err := json.Unmarshal(canonical, &r); err != nil {
		return nil, fmt.Errorf("el documento canónico no parsea: %w", err)
	}

	// rules[]: uno por rule_id presente, ORDENADO por id (determinismo). El
	// security-severity a nivel de regla = el numérico de la severidad más alta
	// entre sus instancias en este run (GitHub ordena la regla por su peor
	// hallazgo). La severidad por-hallazgo (con degradación) vive en el result.
	ruleMax := map[string]float64{}
	for _, f := range r.Findings {
		if n := secSevNum(f.Severity); n > ruleMax[f.RuleID] {
			ruleMax[f.RuleID] = n
		}
	}
	ids := make([]string, 0, len(ruleMax))
	for id := range ruleMax {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ruleIndex := make(map[string]int, len(ids))
	rules := make([]sarifRule, len(ids))
	for i, id := range ids {
		ruleIndex[id] = i
		rules[i] = sarifRule{
			ID: id, Name: id,
			Properties: map[string]any{"security-severity": ssStr(ruleMax[id])},
		}
	}

	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		text := f.Observed
		if f.Rationale != "" {
			text += " — " + f.Rationale
		}
		props := map[string]any{
			"j0w_severity":      f.Severity,
			"j0w_confidence":    f.Confidence,
			"security-severity": securitySeverity(f.Severity),
		}
		if f.BaseSeverity != "" {
			props["j0w_base_severity"] = f.BaseSeverity
		}
		if f.Alternative != "" {
			props["j0w_alternative_hypothesis"] = f.Alternative
		}
		if f.ComparedTo != "" {
			props["j0w_compared_to"] = f.ComparedTo
		}
		phys := sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.Subject}}
		if line, ok := f.Evidence["line"].(float64); ok && line > 0 {
			phys.Region = &sarifRegion{StartLine: int(line)}
		}
		results = append(results, sarifResult{
			RuleID:              f.RuleID,
			RuleIndex:           ruleIndex[f.RuleID],
			Level:               sarifLevel(f.Severity),
			Message:             sarifMessage{Text: text},
			Locations:           []sarifLocation{{PhysicalLocation: phys}},
			PartialFingerprints: map[string]string{"j0witnessFindingId/v1": f.ID},
			Properties:          props,
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:            "J0Witness",
				Version:         r.Provenance.ToolVersion,
				SemanticVersion: r.Provenance.ToolVersion,
				InformationURI:  "https://github.com/aguilerasmiguel/J0Witness",
				Rules:           rules,
			}},
			Results: results,
			Invocations: []sarifInvocation{{
				ExecutionSuccessful: true, // SARIF sólo se renderiza tras construir el informe con éxito; los códigos de salida aquí son 0/1 (OK limpio u OK-con-hallazgos); errores de preflight/uso/baseline/interno abortan antes.
				ExitCode:            r.Summary.ExitCode,
				EndTimeUTC:          r.Run.FinishedAt,
			}},
		}},
	}
	return CanonicalMarshal(log)
}

// sarifLevel mapea la severidad J0W (5 niveles) al level SARIF (3 niveles).
// Función PURA de la severidad (sin acoplar a --fail-on).
func sarifLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default: // low, info
		return "note"
	}
}

// secSevNum devuelve el numérico security-severity (convención GitHub) de una
// severidad, para comparar y elegir el máximo por regla.
func secSevNum(sev string) float64 {
	switch sev {
	case "critical":
		return 9.0
	case "high":
		return 7.0
	case "medium":
		return 5.0
	case "low":
		return 3.0
	default: // info
		return 1.0
	}
}

func securitySeverity(sev string) string { return ssStr(secSevNum(sev)) }

// ssStr formatea el numérico con un decimal (determinista, estable).
func ssStr(n float64) string { return fmt.Sprintf("%.1f", n) }

// --- structs SARIF 2.1.0 (mínimos y suficientes) ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}
type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine"`
}
type sarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	ExitCode            int    `json:"exitCode"`
	EndTimeUTC          string `json:"endTimeUtc,omitempty"`
}
