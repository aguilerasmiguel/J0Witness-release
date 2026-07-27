package extbaseline

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAndResolveUpdates(t *testing.T) {
	// Esquema real (SP Page Builder): un <update> con element/version/downloads/sha256.
	raw := []byte(`<?xml version="1.0"?>
<updates>
  <update>
    <name>SP Page Builder</name>
    <element>com_sppagebuilder</element>
    <type>component</type>
    <version>6.7.0</version>
    <downloads>
      <downloadurl type="full" format="zip">https://example.test/spb-6.7.0.zip</downloadurl>
    </downloads>
    <sha256>abc123</sha256>
    <sha384>def</sha384>
    <sha512>ghi</sha512>
  </update>
</updates>`)
	ents, err := ParseUpdates(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Element != "com_sppagebuilder" || ents[0].Version != "6.7.0" ||
		ents[0].DownloadURL != "https://example.test/spb-6.7.0.zip" || ents[0].SHA256 != "abc123" {
		t.Fatalf("entrada: %+v", ents)
	}
	// Resuelve por (element, version).
	if e, err := ResolveUpdate(ents, "com_sppagebuilder", "6.7.0"); err != nil || e.DownloadURL == "" {
		t.Fatalf("no resolvió la versión instalada: %+v, err=%v", e, err)
	}
	// Versión distinta → no resuelve (fase 2b no baja peras por manzanas).
	if _, err := ResolveUpdate(ents, "com_sppagebuilder", "6.8.0"); !errors.Is(err, ErrNoMatchingVersion) {
		t.Fatalf("no debe resolver una versión distinta: err=%v", err)
	}
	// Versión instalada vacía → nunca debe casar, ni siquiera contra una entrada
	// cuya <version> también viniera vacía (comodín prohibido, Principio VI).
	emptyVersionEnts := []UpdateEntry{{Element: "com_sppagebuilder", Version: ""}}
	if _, err := ResolveUpdate(emptyVersionEnts, "com_sppagebuilder", ""); !errors.Is(err, ErrNoMatchingVersion) {
		t.Fatalf("no debe resolver cuando la versión instalada está vacía: err=%v", err)
	}
	// XXE: una entidad externa no se resuelve (no filtra el archivo local).
	evil := []byte(`<?xml version="1.0"?><!DOCTYPE u [<!ENTITY x SYSTEM "file:///etc/passwd">]><updates><update><version>&x;</version></update></updates>`)
	if es, _ := ParseUpdates(evil); len(es) == 1 && strings.Contains(es[0].Version, "root:") {
		t.Fatal("XXE: se resolvió una entidad externa")
	}
}

// TestParseUpdatesPrefersFullDownload verifica el desempate: si hay varias
// <downloadurl> y una NO es type="full" apareciendo ANTES que la type="full",
// ParseUpdates debe quedarse con la type="full" (no con la primera del XML).
func TestParseUpdatesPrefersFullDownload(t *testing.T) {
	raw := []byte(`<?xml version="1.0"?>
<updates>
  <update>
    <element>com_sppagebuilder</element>
    <version>6.7.0</version>
    <downloads>
      <downloadurl type="diff" format="zip">https://example.test/spb-6.7.0-diff.zip</downloadurl>
      <downloadurl type="full" format="zip">https://example.test/spb-6.7.0-full.zip</downloadurl>
    </downloads>
  </update>
</updates>`)
	ents, err := ParseUpdates(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].DownloadURL != "https://example.test/spb-6.7.0-full.zip" {
		t.Fatalf("no prefirió el downloadurl type=\"full\": %+v", ents)
	}
}

// TestResolveUpdateAmbiguousDownloadURL: dos entradas de la MISMA versión con
// DownloadURL DISTINTA (típicamente <targetplatform> distintos, p.ej. J3 vs
// J4/J5) son ambiguas: elegir la primera cachearía el paquete de la
// plataforma equivocada como si fuera la línea base real → falso positivo
// J0W-EXT-008 (Principio VI). ResolveUpdate debe fallar ruidosamente en vez
// de adivinar.
func TestResolveUpdateAmbiguousDownloadURL(t *testing.T) {
	ents := []UpdateEntry{
		{Element: "com_sppagebuilder", Version: "6.7.0", DownloadURL: "https://example.test/j3.zip"},
		{Element: "com_sppagebuilder", Version: "6.7.0", DownloadURL: "https://example.test/j4.zip"},
	}
	e, err := ResolveUpdate(ents, "com_sppagebuilder", "6.7.0")
	if err == nil {
		t.Fatal("se esperaba error de ambigüedad")
	}
	if errors.Is(err, ErrNoMatchingVersion) {
		t.Fatalf("el error de ambigüedad no debe ser ErrNoMatchingVersion: %v", err)
	}
	if !strings.Contains(err.Error(), "ambig") && !strings.Contains(err.Error(), "distintos") {
		t.Fatalf("el mensaje de error debería mencionar la ambigüedad: %v", err)
	}
	if (e != UpdateEntry{}) {
		t.Fatalf("la entrada devuelta debería ser cero ante ambigüedad: %+v", e)
	}
}

// TestResolveUpdateNoFalseAmbiguityOnDuplicateURL: dos entradas de la misma
// versión con la MISMA DownloadURL no son una ambigüedad real (listados
// duplicados benignos); ResolveUpdate no debe fallar en falso.
func TestResolveUpdateNoFalseAmbiguityOnDuplicateURL(t *testing.T) {
	ents := []UpdateEntry{
		{Element: "com_sppagebuilder", Version: "6.7.0", DownloadURL: "https://example.test/full.zip"},
		{Element: "com_sppagebuilder", Version: "6.7.0", DownloadURL: "https://example.test/full.zip"},
	}
	e, err := ResolveUpdate(ents, "com_sppagebuilder", "6.7.0")
	if err != nil {
		t.Fatalf("no debía fallar ante duplicados benignos con la misma URL: %v", err)
	}
	if e.DownloadURL != "https://example.test/full.zip" {
		t.Fatalf("entrada inesperada: %+v", e)
	}
}
