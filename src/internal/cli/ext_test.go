package cli

import (
	"encoding/json"
	"testing"
)

// T106/T107 (US1, SC-100): extensión legítima → sus archivos atribuidos, cero
// hallazgos >= medium; los J0W-CORE-004 que producía desaparecen.
func TestExtLegitAttribution(t *testing.T) {
	h := newHarness(t)
	r, exit, doc, stderr := h.scanCase(t, "ext-legit")
	assertExpectations(t, r, exit, doc, stderr)

	p := parseReport(t, doc)
	for _, f := range p.Findings {
		if sevRank[f.Severity] >= sevRank["medium"] {
			t.Errorf("extensión legítima con hallazgo >= medium: %s %s (%s)", f.RuleID, f.Subject, f.Severity)
		}
	}
	// El inventario y el resumen de atribución reflejan la extensión.
	var rep struct {
		Extensions []struct {
			Name          string `json:"name"`
			Type          string `json:"type"`
			Verified      bool   `json:"verified"`
			FilesDeclared int    `json:"files_declared"`
		} `json:"extensions"`
		Coverage struct {
			Attribution struct {
				FilesAttributed      int  `json:"files_attributed"`
				ThirdPartyExtensions int  `json:"third_party_extensions"`
				IntegrityVerified    bool `json:"integrity_verified"`
			} `json:"attribution"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Extensions) != 1 || rep.Extensions[0].Name != "com_labext" || rep.Extensions[0].Type != "component" {
		t.Fatalf("inventario de extensiones: %+v", rep.Extensions)
	}
	if rep.Extensions[0].Verified {
		t.Fatal("la 002 no verifica integridad: verified debe ser false")
	}
	if rep.Extensions[0].FilesDeclared == 0 {
		t.Fatal("la extensión legítima debe tener archivos declarados")
	}
	if rep.Coverage.Attribution.FilesAttributed == 0 || rep.Coverage.Attribution.ThirdPartyExtensions != 1 {
		t.Fatalf("resumen de atribución: %+v", rep.Coverage.Attribution)
	}
	if rep.Coverage.Attribution.IntegrityVerified {
		t.Fatal("integrity_verified debe ser false (C3)")
	}
}

// D1 (regresión, SC-100): un componente cuyo `<name>` de display difiere de su
// directorio (Fancy Component → com_dispname) atribuye todos sus archivos. Con
// la raíz derivada del display, ninguno casaría y saldrían como J0W-CORE-004
// falsos — el patrón real de SP Page Builder → com_sppagebuilder.
func TestExtDisplayNameAttribution(t *testing.T) {
	h := newHarness(t)
	r, exit, doc, stderr := h.scanCase(t, "ext-display-name")
	assertExpectations(t, r, exit, doc, stderr)

	p := parseReport(t, doc)
	for _, f := range p.Findings {
		if f.RuleID == "J0W-CORE-004" {
			t.Errorf("archivo del componente sin atribuir (raíz mal derivada del display): %s", f.Subject)
		}
	}
	var rep struct {
		Extensions []struct {
			Name          string `json:"name"`
			FilesDeclared int    `json:"files_declared"`
		} `json:"extensions"`
		Coverage struct {
			Attribution struct {
				FilesAttributed int `json:"files_attributed"`
			} `json:"attribution"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatal(err)
	}
	// El inventario conserva el nombre de display; la atribución usa el directorio.
	if len(rep.Extensions) != 1 || rep.Extensions[0].Name != "Fancy Component" {
		t.Fatalf("inventario de extensiones: %+v", rep.Extensions)
	}
	if rep.Coverage.Attribution.FilesAttributed == 0 {
		t.Fatal("los archivos del componente deben quedar atribuidos")
	}
}

// D2 (regresión, SC-100): librería por <libraryname>, pack de idioma y
// traducción compartida quedan atribuidos dentro de directorios del core; cero
// J0W-CORE-004 y cero conflictos por las traducciones.
func TestExtD2LibraryLanguage(t *testing.T) {
	h := newHarness(t)
	r, exit, doc, stderr := h.scanCase(t, "ext-d2-library-language")
	assertExpectations(t, r, exit, doc, stderr)

	p := parseReport(t, doc)
	for _, f := range p.Findings {
		switch f.RuleID {
		case "J0W-CORE-004":
			t.Errorf("archivo del core sin atribuir (D2): %s", f.Subject)
		case "J0W-EXT-006":
			t.Errorf("conflicto de propiedad espurio por traducción compartida: %s", f.Subject)
		}
	}
}

// D3 (regresión): el script de instalación declarado por <scriptfile> queda
// atribuido (no J0W-EXT-001), pero sigue visible como ejecutable sin verificar
// en la red unverified_executables (matiz anestesia).
func TestExtScriptFile(t *testing.T) {
	h := newHarness(t)
	r, exit, doc, stderr := h.scanCase(t, "ext-scriptfile")
	assertExpectations(t, r, exit, doc, stderr)

	script := "administrator/components/com_scripted/installer.script.php"
	p := parseReport(t, doc)
	for _, f := range p.Findings {
		if f.RuleID == "J0W-EXT-001" && f.Subject == script {
			t.Errorf("el scriptfile declarado no debe salir como ejecutable no declarado")
		}
	}
	// Sigue enumerado como ejecutable atribuido sin verificar.
	var rep struct {
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
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range rep.Coverage.Attribution.UnverifiedExecutables.Files {
		if f.Path == script {
			found = true
		}
	}
	if !found {
		t.Error("el scriptfile atribuido debe permanecer visible en unverified_executables")
	}
}

// T114 (US2, SC-102): webshell no declarado → J0W-EXT-001 high; router.php
// legítimo no genera J0W-CORE-004.
func TestExtWebshell(t *testing.T) {
	h := newHarness(t)
	r, exit, doc, stderr := h.scanCase(t, "ext-webshell")
	assertExpectations(t, r, exit, doc, stderr)
}

// T114 (C1): ejecutable en carpeta declarada → J0W-EXT-002 medium.
func TestExtWebshellInFolder(t *testing.T) {
	h := newHarness(t)
	r, exit, doc, stderr := h.scanCase(t, "ext-webshell-in-folder")
	assertExpectations(t, r, exit, doc, stderr)
}

// T118 (US4): manifiesto manipulado y corrupto.
func TestExtManifestCases(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{"ext-manifest-tampered", "ext-manifest-corrupt"} {
		t.Run(name, func(t *testing.T) {
			r, exit, doc, stderr := h.scanCase(t, name)
			assertExpectations(t, r, exit, doc, stderr)
		})
	}
}
