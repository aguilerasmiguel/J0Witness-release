package cli

import (
	"encoding/json"
	"testing"
)

// TestExtVerificationCorpus (fase 2a, Task 6): las 5 recetas del corpus de
// verificación de extensiones (verificado/troyano/inerte/versión/ausente).
// Cada subtest usa un harness NUEVO (state.sqlite propio) para que el
// baseline cacheado por una receta nunca se filtre a otra — crítico para
// ext-version-mismatch, que depende de que la versión correcta NO esté
// cacheada.
func TestExtVerificationCorpus(t *testing.T) {
	for _, name := range []string{
		"ext-verified",
		"ext-trojan",
		"ext-modified-inert",
		"ext-version-mismatch",
		"ext-official-missing",
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			r, exit, doc, stderr := h.scanCase(t, name)
			assertExpectations(t, r, exit, doc, stderr)
		})
	}
}

// parsedVerificationReport es el subconjunto del informe que interesa a las
// aserciones extra de verificación de extensiones.
type parsedVerificationReport struct {
	Extensions []struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Verified bool   `json:"verified"`
	} `json:"extensions"`
	Coverage struct {
		Attribution struct {
			UnverifiedExecutables struct {
				Files []struct {
					Path string `json:"path"`
				} `json:"files"`
			} `json:"unverified_executables"`
		} `json:"attribution"`
	} `json:"coverage"`
}

// TestExtVerifiedMarksExtensionAndShrinksUnverified (fase 2a, Task 6):
// además del contrato genérico (assertExpectations), ext-verified debe dejar
// com_labext con verified:true y sus ejecutables atribuidos (router.php,
// labext.php, Controller.php, Model.php, Dispatcher.php) FUERA de
// unverified_executables — ya se compararon byte a byte contra el paquete
// oficial.
func TestExtVerifiedMarksExtensionAndShrinksUnverified(t *testing.T) {
	h := newHarness(t)
	r, exit, doc, stderr := h.scanCase(t, "ext-verified")
	assertExpectations(t, r, exit, doc, stderr)

	var rep parsedVerificationReport
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatalf("informe no parsea: %v\n%s", err, doc)
	}

	var found bool
	for _, e := range rep.Extensions {
		if e.Name != "com_labext" {
			continue
		}
		found = true
		if e.Type != "component" {
			t.Errorf("com_labext: type=%q, esperaba component", e.Type)
		}
		if !e.Verified {
			t.Error("com_labext: verified debe ser true (baseline cacheado, misma versión)")
		}
	}
	if !found {
		t.Fatalf("com_labext no aparece en coverage.extensions: %+v", rep.Extensions)
	}

	executables := []string{
		"components/com_labext/router.php",
		"components/com_labext/src/Controller.php",
		"components/com_labext/src/Model.php",
		"administrator/components/com_labext/labext.php",
		"administrator/components/com_labext/src/Dispatcher.php",
	}
	for _, want := range executables {
		for _, f := range rep.Coverage.Attribution.UnverifiedExecutables.Files {
			if f.Path == want {
				t.Errorf("%s sigue en unverified_executables tras verificarse contra el paquete oficial", want)
			}
		}
	}
}

// TestExtTrojanFileCritical (fase 2a, Task 6): además del contrato genérico,
// confirma explícitamente que la ruta troyanizada lleva J0W-EXT-008 en
// severidad critical (no solo >= algo): un ejecutable con contenido distinto
// al del paquete oficial es una modificación efectiva, la máxima severidad.
func TestExtTrojanFileCritical(t *testing.T) {
	h := newHarness(t)
	r, exit, doc, stderr := h.scanCase(t, "ext-trojan")
	assertExpectations(t, r, exit, doc, stderr)

	p := parseReport(t, doc)
	const subject = "components/com_labext/router.php"
	var got string
	for _, f := range p.Findings {
		if f.RuleID == "J0W-EXT-008" && f.Subject == subject {
			got = f.Severity
		}
	}
	if got != "critical" {
		t.Fatalf("J0W-EXT-008 en %s: severity=%q, esperaba critical\ninforme: %s", subject, got, doc)
	}
}
