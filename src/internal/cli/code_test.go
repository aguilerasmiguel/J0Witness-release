package cli

import "testing"

func TestCodeDetectors(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{
		"code-obfuscated-eval", "code-input-sink", "code-preg-e",
		"code-benign-decode", "code-sink-literal", "code-in-comment",
		"code-escapeshell-sanitized", "code-proc-open-env",
	} {
		t.Run(name, func(t *testing.T) {
			r, exit, doc, stderr := h.scanCase(t, name)
			assertExpectations(t, r, exit, doc, stderr)
		})
	}
}

// El positivo CODE-001 marca flagged_by_code en la red (cierre de anestesia).
func TestCodeFlagsUnverifiedExec(t *testing.T) {
	h := newHarness(t)
	_, _, doc, _ := h.scanCase(t, "code-obfuscated-eval")
	if !contains(string(doc), `"flagged_by_code": true`) {
		t.Fatalf("la entrada de la red debe marcarse flagged_by_code: %s", doc)
	}
	if !contains(string(doc), `"code_analysis"`) {
		t.Fatalf("falta cobertura code_analysis")
	}
}
