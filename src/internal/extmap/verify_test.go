package extmap

import (
	"testing"

	"j0witness/internal/inventory"
	"j0witness/internal/manifest"
	"j0witness/internal/observe"
)

// TestVerifyExtensions (Task 4, fase 2a): compara los archivos instalados de un
// componente contra su baseline oficial cacheado (via lookup), SOLO cuando la
// versión declarada coincide con la del baseline (Principio VI).
func TestVerifyExtensions(t *testing.T) {
	// Componente com_labext instalado con 2 archivos (uno íntegro, uno
	// modificado); el baseline oficial declara además un tercero ausente.
	ext := Extension{
		ManifestPath: "administrator/components/com_labext/labext.xml",
		Type:         manifest.Component, Name: "Lab Ext", Version: "1.0.0",
		ElementKey: "com_labext",
	}
	inst := []inventory.Entry{
		{RelPath: []byte("components/com_labext/router.php"), PathDisplay: "components/com_labext/router.php", SHA256: "GOOD", Type: "file"},
		{RelPath: []byte("components/com_labext/webshell.php"), PathDisplay: "components/com_labext/webshell.php", SHA256: "TROYANO", Type: "file"},
		// (declarado por el paquete pero ausente: components/com_labext/missing.php)
	}
	baseline := map[string]string{
		"components/com_labext/router.php":   "GOOD",    // coincide → verified
		"components/com_labext/webshell.php": "OFICIAL", // difiere → modified
		"components/com_labext/missing.php":  "X",       // ausente → official_missing
	}
	lookup := func(element, version string) (map[string]string, string, bool) {
		if element == "com_labext" && version == "1.0.0" {
			return baseline, "package", true
		}
		return nil, "", false
	}
	obs := VerifyExtensions([]Extension{ext}, inst, lookup, 1)
	got := map[observe.Type]string{}
	for _, o := range obs {
		got[o.Type] = o.SubjectDisplay
	}
	if got[observe.ExtFileModified] != "components/com_labext/webshell.php" {
		t.Fatalf("modificado: %v", got)
	}
	if _, ok := got[observe.ExtFileVerified]; !ok {
		t.Fatalf("falta verified: %v", got)
	}
	if got[observe.ExtOfficialMissing] != "components/com_labext/missing.php" {
		t.Fatalf("ausente: %v", got)
	}

	// Versión distinta a la del baseline cacheado → no verificable, cero
	// observaciones (Principio VI: sin baseline aplicable, no se compara).
	if o := VerifyExtensions([]Extension{{ManifestPath: ext.ManifestPath, Type: manifest.Component, Version: "9.9.9"}}, inst, lookup, 1); len(o) != 0 {
		t.Fatalf("versión distinta no debe verificar: %v", o)
	}
}

// TestVerifyExtensionsPlugin (fase 2c, Task 3): un tipo distinto de componente
// (plugin) también se verifica ahora, usando ElementKey ("group/element") en
// vez de estar restringido a manifest.Component. Con el filtro previo
// (ext.Type != manifest.Component) este caso se saltaba en silencio.
func TestVerifyExtensionsPlugin(t *testing.T) {
	ext := Extension{
		ManifestPath: "plugins/system/foo/foo.xml",
		Type:         manifest.Plugin, Name: "Foo Plugin", Version: "1.0",
		ElementKey: "system/foo",
	}
	inst := []inventory.Entry{
		{RelPath: []byte("plugins/system/foo/foo.php"), PathDisplay: "plugins/system/foo/foo.php", SHA256: "GOOD", Type: "file"},
	}
	baseline := map[string]string{
		"plugins/system/foo/foo.php": "GOOD",
	}
	lookup := func(element, version string) (map[string]string, string, bool) {
		if element == "system/foo" && version == "1.0" {
			return baseline, "package", true
		}
		return nil, "", false
	}
	obs := VerifyExtensions([]Extension{ext}, inst, lookup, 1)
	found := false
	for _, o := range obs {
		if o.Type == observe.ExtFileVerified && o.SubjectDisplay == "plugins/system/foo/foo.php" {
			found = true
		}
	}
	if !found {
		t.Fatalf("esperaba ext_file_verified para el plugin, obs=%v", obs)
	}
}
