package manifest

import (
	"sort"
	"strings"
	"testing"
)

// T104: el mapeo declarado→instalado de un componente produce las tres raíces
// reales (FR-113) y traduce carpetas/archivos a sus ubicaciones instaladas.
func TestMapLayoutComponent(t *testing.T) {
	const xml = `<extension type="component">
	<name>com_labext</name>
	<files folder="site"><filename>router.php</filename><folder>src</folder></files>
	<media destination="com_labext" folder="media"><folder>js</folder></media>
	<administration><files folder="admin"><filename>labext.php</filename><folder>src</folder></files></administration>
</extension>`
	m, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	l := m.MapLayout("administrator/components/com_labext/com_labext.xml")

	// FR-113: tres raíces.
	wantRoots := []string{"administrator/components/com_labext", "components/com_labext", "media/com_labext"}
	got := append([]string{}, l.Roots...)
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(wantRoots, ",") {
		t.Fatalf("raíces: %v, quiere %v", got, wantRoots)
	}

	// Declaraciones concretas mapeadas.
	cases := map[string]struct {
		owned     bool
		viaFolder bool
	}{
		"components/com_labext/router.php":                {true, false}, // filename exacto
		"components/com_labext/src/Controller.php":        {true, true},  // dentro de folder declarado
		"media/com_labext/js/app.js":                      {true, true},  // media folder
		"administrator/components/com_labext/labext.php":  {true, false},
		"administrator/components/com_labext/src/Any.php": {true, true},
		"components/com_labext/rogue.php":                 {false, false}, // no declarado
	}
	for p, want := range cases {
		owned, viaFolder := l.Owns(p)
		if owned != want.owned || viaFolder != want.viaFolder {
			t.Errorf("Owns(%s) = (%v,%v), quiere (%v,%v)", p, owned, viaFolder, want.owned, want.viaFolder)
		}
	}
}

// D1: la raíz de un componente se deriva del directorio del manifiesto
// (com_sppagebuilder), no del `<name>` de display ("SP Page Builder"). Con el
// nombre de display, ninguna raíz casaba y todos los archivos del componente
// salían como file_unexpected → J0W-CORE-004 falsos.
func TestMapLayoutComponentNameFromDir(t *testing.T) {
	const xml = `<extension type="component">
	<name>SP Page Builder</name>
	<files folder="site"><filename>router.php</filename><folder>src</folder></files>
	<media folder="media"><folder>js</folder></media>
	<administration><files folder="admin"><filename>sppagebuilder.php</filename><folder>src</folder></files></administration>
</extension>`
	m, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	l := m.MapLayout("administrator/components/com_sppagebuilder/sppagebuilder.xml")

	wantRoots := []string{
		"administrator/components/com_sppagebuilder",
		"components/com_sppagebuilder",
		"media/com_sppagebuilder",
	}
	got := append([]string{}, l.Roots...)
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(wantRoots, ",") {
		t.Fatalf("raíces: %v, quiere %v (deben derivar del directorio com_sppagebuilder, no de \"SP Page Builder\")", got, wantRoots)
	}

	// Un archivo real del componente queda atribuido (no J0W-CORE-004).
	for _, p := range []string{
		"components/com_sppagebuilder/router.php",
		"components/com_sppagebuilder/src/Controller.php",
		"administrator/components/com_sppagebuilder/sppagebuilder.php",
		"media/com_sppagebuilder/js/app.js",
	} {
		if owned, _ := l.Owns(p); !owned {
			t.Errorf("Owns(%s) = false; el archivo del componente debe quedar atribuido", p)
		}
	}
}

// T104: la raíz de un módulo es el directorio de su manifiesto.
func TestMapLayoutModule(t *testing.T) {
	const xml = `<extension type="module"><name>mod_x</name><files><filename>mod_x.php</filename><folder>tmpl</folder></files></extension>`
	m, _ := Parse(strings.NewReader(xml))
	l := m.MapLayout("modules/mod_x/mod_x.xml")
	if !l.InRoots("modules/mod_x/mod_x.php") {
		t.Fatal("la raíz del módulo debe ser su directorio")
	}
	if owned, _ := l.Owns("modules/mod_x/tmpl/default.php"); !owned {
		t.Fatal("archivo dentro de carpeta declarada del módulo no poseído")
	}
}

// D3: <scriptfile> se declara como archivo exacto en el directorio del
// manifiesto (dentro de las raíces), no como ejecutable no declarado.
func TestMapLayoutScriptFile(t *testing.T) {
	const xml = `<extension type="component">
	<name>SP Page Builder</name>
	<scriptfile>installer.script.php</scriptfile>
	<administration><files folder="admin"><filename>x.php</filename></files></administration>
</extension>`
	m, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	l := m.MapLayout("administrator/components/com_sppagebuilder/sppagebuilder.xml")
	sf := "administrator/components/com_sppagebuilder/installer.script.php"
	owned, viaFolder := l.Owns(sf)
	if !owned || viaFolder {
		t.Fatalf("el scriptfile debe quedar declarado como archivo exacto: owned=%v viaFolder=%v", owned, viaFolder)
	}
	if !l.InRoots(sf) {
		t.Fatal("el scriptfile debe caer dentro de las raíces (no sospechoso)")
	}
}

// D2: la raíz de una librería se deriva de <libraryname> (libraries/eshiol/J2xml),
// no de <name> ("J2XML"); el manifiesto vive en un subdirectorio de manifests.
func TestMapLayoutLibraryByLibraryname(t *testing.T) {
	const xml = `<extension type="library">
	<name>J2XML</name>
	<libraryname>eshiol/J2xml</libraryname>
	<files><filename>Exporter.php</filename><folder>Table</folder></files>
</extension>`
	m, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	l := m.MapLayout("administrator/manifests/libraries/eshiol/J2xml.xml")
	if len(l.Roots) != 1 || l.Roots[0] != "libraries/eshiol/J2xml" {
		t.Fatalf("raíces: %v, quiere [libraries/eshiol/J2xml]", l.Roots)
	}
	for _, p := range []string{"libraries/eshiol/J2xml/Exporter.php", "libraries/eshiol/J2xml/Table/Category.php"} {
		if owned, _ := l.Owns(p); !owned {
			t.Errorf("Owns(%s) = false; debe atribuirse", p)
		}
	}
}

// D2: una extensión de idioma posee todo el directorio de su manifiesto.
func TestMapLayoutLanguagePack(t *testing.T) {
	const xml = `<extension client="administrator" type="language">
	<name>Spanish (es-ES)</name>
	<files><folder>/</folder><filename file="meta">install.xml</filename></files>
</extension>`
	m, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	l := m.MapLayout("administrator/language/es-ES/install.xml")
	if !l.InRoots("administrator/language/es-ES/es-ES.com_content.ini") {
		t.Fatal("el pack de idioma debe cubrir su directorio")
	}
	if owned, viaFolder := l.Owns("administrator/language/es-ES/es-ES.com_content.ini"); !owned || !viaFolder {
		t.Fatalf("un archivo del pack debe quedar poseído por carpeta: owned=%v viaFolder=%v", owned, viaFolder)
	}
}

// D2: las traducciones <languages> se resuelven a la carpeta de idioma
// compartida (site → language/, admin → administrator/language/) y van en
// LanguageFiles, no en Declarations (fuera de las raíces de la extensión).
func TestMapLayoutLanguageFiles(t *testing.T) {
	const xml = `<extension type="component">
	<name>SP Page Builder</name>
	<languages folder="language/site"><language tag="en-GB">en-GB/en-GB.com_sppagebuilder.ini</language></languages>
	<administration>
		<languages folder="language/admin"><language tag="en-GB">en-GB/en-GB.com_sppagebuilder.sys.ini</language></languages>
	</administration>
</extension>`
	m, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	l := m.MapLayout("administrator/components/com_sppagebuilder/sppagebuilder.xml")
	want := map[string]bool{
		"language/en-GB/en-GB.com_sppagebuilder.ini":                   true,
		"administrator/language/en-GB/en-GB.com_sppagebuilder.sys.ini": true,
	}
	got := map[string]bool{}
	for _, p := range l.LanguageFiles {
		got[p] = true
	}
	for p := range want {
		if !got[p] {
			t.Errorf("LanguageFiles no incluye %s (tiene %v)", p, l.LanguageFiles)
		}
	}
	// No deben aparecer como Declarations (evitar J0W-EXT-004 por estar fuera de raíces).
	for _, d := range l.Declarations {
		if want[d.Path] {
			t.Errorf("la traducción %s no debe estar en Declarations", d.Path)
		}
	}
}

// T104: una declaración que escapa de la raíz se conserva resuelta (fuera de
// la raíz) para que DetectSuspicious la detecte; no se ancla ni se oculta.
func TestCleanJoinEscapePreserved(t *testing.T) {
	got := cleanJoin("components/com_x", "../../images/planted.php")
	if strings.HasPrefix(got, "components/com_x") {
		t.Fatalf("la declaración que escapa no debe anclarse a la raíz: %s", got)
	}
	if got != "images/planted.php" {
		t.Fatalf("resolución inesperada: %s", got)
	}
}
