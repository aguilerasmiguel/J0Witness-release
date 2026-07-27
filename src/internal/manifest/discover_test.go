package manifest

import "testing"

// T105: patrones de descubrimiento por tipo (R1).
func TestDiscoverCandidates(t *testing.T) {
	paths := []string{
		"administrator/components/com_labext/com_labext.xml",
		"administrator/components/com_labext/config.xml",   // también raíz de admin → candidato
		"administrator/components/com_labext/src/deep.xml", // anidado → NO
		"modules/mod_x/mod_x.xml",
		"administrator/modules/mod_y/mod_y.xml",
		"plugins/system/foo/foo.xml",
		"templates/mytpl/templateDetails.xml",
		"administrator/manifests/libraries/mylib.xml",
		"administrator/manifests/packages/pkg_z.xml",
		"components/com_labext/router.php", // no XML
		"random/file.xml",                  // no encaja patrón
	}
	cands := DiscoverCandidates(paths)
	byPath := map[string]Type{}
	for _, c := range cands {
		byPath[c.ManifestPath] = c.ExpectedType
	}
	if byPath["administrator/components/com_labext/com_labext.xml"] != Component {
		t.Error("manifiesto de componente no descubierto")
	}
	if _, ok := byPath["administrator/components/com_labext/src/deep.xml"]; ok {
		t.Error("un .xml anidado en el componente no debe ser candidato")
	}
	if byPath["modules/mod_x/mod_x.xml"] != Module ||
		byPath["administrator/modules/mod_y/mod_y.xml"] != Module {
		t.Error("módulos no descubiertos")
	}
	if byPath["plugins/system/foo/foo.xml"] != Plugin {
		t.Error("plugin no descubierto")
	}
	if byPath["templates/mytpl/templateDetails.xml"] != Template {
		t.Error("plantilla no descubierta")
	}
	if byPath["administrator/manifests/libraries/mylib.xml"] != Library {
		t.Error("biblioteca no descubierta")
	}
	if byPath["administrator/manifests/packages/pkg_z.xml"] != Package {
		t.Error("paquete no descubierto")
	}
	if _, ok := byPath["random/file.xml"]; ok {
		t.Error("un .xml fuera de patrón no debe ser candidato")
	}
}

// D2: manifiesto de librería en un subdirectorio de manifests/libraries y
// manifiestos de idioma install.xml en las tres carpetas de idioma.
func TestDiscoverLibraryNestedAndLanguages(t *testing.T) {
	paths := []string{
		"administrator/manifests/libraries/eshiol/J2xml.xml", // anidado → sí
		"administrator/manifests/libraries/joomla.xml",       // un nivel → sí
		"administrator/language/es-ES/install.xml",
		"language/es-ES/install.xml",
		"api/language/es-ES/install.xml",
		"administrator/language/es-ES/langmetadata.xml", // metafile, no install → NO
		"administrator/language/es-ES/es-ES.com_content.ini",
	}
	byPath := map[string]Type{}
	for _, c := range DiscoverCandidates(paths) {
		byPath[c.ManifestPath] = c.ExpectedType
	}
	if byPath["administrator/manifests/libraries/eshiol/J2xml.xml"] != Library {
		t.Error("librería anidada no descubierta")
	}
	if byPath["administrator/manifests/libraries/joomla.xml"] != Library {
		t.Error("librería de un nivel no descubierta")
	}
	for _, p := range []string{
		"administrator/language/es-ES/install.xml",
		"language/es-ES/install.xml",
		"api/language/es-ES/install.xml",
	} {
		if byPath[p] != Language {
			t.Errorf("manifiesto de idioma no descubierto: %s", p)
		}
	}
	if _, ok := byPath["administrator/language/es-ES/langmetadata.xml"]; ok {
		t.Error("langmetadata.xml (metafile) no debe ser candidato de instalación")
	}
}

func TestComponentName(t *testing.T) {
	if ComponentName("administrator/components/com_labext/com_labext.xml") != "com_labext" {
		t.Fatal("ComponentName incorrecto")
	}
}
