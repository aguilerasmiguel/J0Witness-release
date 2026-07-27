package extmap

import (
	"io"
	"strings"
	"testing"

	"j0witness/internal/inventory"
	"j0witness/internal/lab"
	"j0witness/internal/observe"
)

// entriesFromPaths construye entradas de inventario tipo file.
func entriesFromPaths(paths ...string) []inventory.Entry {
	out := make([]inventory.Entry, 0, len(paths))
	for _, p := range paths {
		out = append(out, inventory.Entry{RelPath: []byte(p), PathDisplay: p, Type: "file"})
	}
	return out
}

// labextTree devuelve las entradas de una instalación con com_labext, más un
// reader de manifiestos respaldado por su contenido conocido.
func labextTree(extra ...string) ([]inventory.Entry, manifestReader) {
	paths := append([]string{}, lab.LabExtDeclaredPaths()...)
	paths = append(paths, lab.LabExtManifestPath())
	paths = append(paths, extra...)
	entries := entriesFromPaths(paths...)
	read := func(rel string) (io.ReadCloser, error) {
		content := labExtManifestFor(rel)
		return io.NopCloser(strings.NewReader(content)), nil
	}
	return entries, read
}

func labExtManifestFor(rel string) string {
	if rel == lab.LabExtManifestPath() {
		return `<extension type="component"><name>com_labext</name><version>2.3.1</version>
			<files folder="site"><filename>router.php</filename><folder>src</folder></files>
			<media destination="com_labext" folder="media"><folder>js</folder></media>
			<administration><files folder="admin"><filename>labext.php</filename><filename>config.xml</filename><folder>src</folder></files></administration>
			</extension>`
	}
	return "<config/>"
}

// T108: descubrimiento de com_labext, con core-bundled omitido.
func TestDiscoverLabExt(t *testing.T) {
	entries, read := labextTree()
	disc := Discover(entries, read, func(string) bool { return false }, 1)
	if len(disc.Extensions) != 1 {
		t.Fatalf("esperaba 1 extensión, hay %d", len(disc.Extensions))
	}
	e := disc.Extensions[0]
	if e.Name != "com_labext" || e.Version != "2.3.1" {
		t.Fatalf("metadatos: %+v", e)
	}
	// Las tres raíces (FR-113).
	if len(e.Layout.Roots) != 3 {
		t.Fatalf("raíces: %v", e.Layout.Roots)
	}
}

// T109 (C2): un manifiesto en el baseline del core se omite.
func TestDiscoverCoreBundled(t *testing.T) {
	entries, read := labextTree()
	disc := Discover(entries, read, func(p string) bool { return p == lab.LabExtManifestPath() }, 1)
	if len(disc.Extensions) != 0 {
		t.Fatal("la extensión de serie debe omitirse del mapa de terceros")
	}
	if len(disc.CoreBundled) != 1 {
		t.Fatalf("core-bundled: %v", disc.CoreBundled)
	}
}

// T110/T115: mapa de propiedad — declarados atribuidos, no-declarado ejecutable
// detectado, manifiesto atribuido.
func TestBuildOwnership(t *testing.T) {
	entries, read := labextTree("components/com_labext/evil.php")
	disc := Discover(entries, read, func(string) bool { return false }, 1)
	obs := BuildOwnership(disc.Extensions, entries, false, 1)

	var owns, undeclaredExec int
	manifestOwned := false
	for _, o := range obs {
		switch o.Type {
		case observe.ExtOwnsPath:
			owns++
			if o.SubjectDisplay == lab.LabExtManifestPath() {
				manifestOwned = true
			}
		case observe.ExtUndeclared:
			if strings.Contains(o.EvidenceJSON, `"executable":true`) {
				undeclaredExec++
			}
		}
	}
	if !manifestOwned {
		t.Error("el propio manifiesto debe quedar atribuido a su extensión")
	}
	if owns == 0 {
		t.Error("los archivos declarados deben atribuirse")
	}
	if undeclaredExec != 1 {
		t.Fatalf("el ejecutable no declarado debe detectarse una vez, hay %d", undeclaredExec)
	}
}

// T121/G1 (FR-111): dos extensiones que declaran la misma ruta → conflicto sin
// colapsar (Principio II). Test unitario del detector.
func TestOwnershipConflict(t *testing.T) {
	// Dos componentes distintos (com_a, com_b) que declaran, cada uno, el mismo
	// destino de media com_shared con el archivo lib.php → ambos reclaman
	// media/com_shared/lib.php (un layout de paquete mal formado o una
	// suplantación). La raíz de cada componente deriva de su directorio (D1),
	// pero el destino de media es explícito y ambos apuntan al mismo.
	shared := "media/com_shared/lib.php"
	read := func(rel string) (io.ReadCloser, error) {
		switch rel {
		case "administrator/components/com_a/com_a.xml":
			return io.NopCloser(strings.NewReader(
				`<extension type="component"><name>Componente A</name>
				<media destination="com_shared" folder="media"><filename>lib.php</filename></media></extension>`)), nil
		case "administrator/components/com_b/com_b.xml":
			return io.NopCloser(strings.NewReader(
				`<extension type="component"><name>Componente B</name>
				<media destination="com_shared" folder="media"><filename>lib.php</filename></media></extension>`)), nil
		}
		return io.NopCloser(strings.NewReader("<config/>")), nil
	}
	entries := entriesFromPaths(
		"administrator/components/com_a/com_a.xml",
		"administrator/components/com_b/com_b.xml",
		shared,
	)
	disc := Discover(entries, read, func(string) bool { return false }, 1)
	// Ambos manifiestos declaran el mismo destino de media com_shared → ambos
	// poseen media/com_shared/lib.php.
	obs := BuildOwnership(disc.Extensions, entries, false, 1)
	conflicts := 0
	for _, o := range obs {
		if o.Type == observe.ExtOwnershipConflict {
			conflicts++
		}
	}
	if conflicts == 0 {
		t.Fatal("dos extensiones reclamando la misma ruta deben producir conflicto")
	}
}

// D2: un pack de idioma posee toda su carpeta (por <folder>), y un componente
// declara un .ini concreto dentro de ella (por <languages>). La declaración
// exacta gana: el .ini se atribuye al componente, sin conflicto de propiedad,
// y sin J0W-CORE-004. Un .ini que solo posee el pack queda atribuido al pack.
func TestLanguageFileBeatsFolder(t *testing.T) {
	langManifest := "administrator/language/es-XX/install.xml"
	comManifest := "administrator/components/com_foo/foo.xml"
	sharedIni := "administrator/language/es-XX/es-XX.com_foo.ini"   // pack (folder) + com_foo (language)
	packIni := "administrator/language/es-XX/es-XX.com_content.ini" // solo pack (folder)

	read := func(rel string) (io.ReadCloser, error) {
		switch rel {
		case langManifest:
			return io.NopCloser(strings.NewReader(
				`<extension client="administrator" type="language"><name>Synthetic (es-XX)</name>
				<files><folder>/</folder></files></extension>`)), nil
		case comManifest:
			return io.NopCloser(strings.NewReader(
				`<extension type="component"><name>Foo Component</name>
				<administration><languages folder="language/admin">
					<language tag="es-XX">es-XX/es-XX.com_foo.ini</language>
				</languages></administration></extension>`)), nil
		}
		return io.NopCloser(strings.NewReader("<config/>")), nil
	}
	entries := entriesFromPaths(langManifest, comManifest, sharedIni, packIni)
	disc := Discover(entries, read, func(string) bool { return false }, 1)
	if len(disc.Extensions) != 2 {
		t.Fatalf("esperaba 2 extensiones (pack + componente), hay %d", len(disc.Extensions))
	}
	obs := BuildOwnership(disc.Extensions, entries, false, 1)

	conflicts := map[string]bool{}
	ownedBy := map[string][]string{}
	for _, o := range obs {
		switch o.Type {
		case observe.ExtOwnershipConflict:
			conflicts[o.SubjectDisplay] = true
		case observe.ExtOwnsPath:
			ownedBy[o.SubjectDisplay] = append(ownedBy[o.SubjectDisplay], o.EvidenceJSON)
		}
	}
	if conflicts[sharedIni] {
		t.Error("la traducción declarada no debe generar conflicto (exacto gana a carpeta)")
	}
	if len(ownedBy[sharedIni]) == 0 {
		t.Error("la traducción compartida debe quedar atribuida (no J0W-CORE-004)")
	}
	if !strings.Contains(strings.Join(ownedBy[sharedIni], " "), `"declaration":"language"`) {
		t.Errorf("la traducción debe atribuirse por declaración language: %v", ownedBy[sharedIni])
	}
	if len(ownedBy[packIni]) == 0 {
		t.Error("el .ini propio del pack debe quedar atribuido por carpeta")
	}
}

// T119 (FR-132): declaración fuera de las raíces del tipo → sospechosa.
func TestDetectSuspicious(t *testing.T) {
	// Manifiesto que declara un archivo en images/ (fuera de las raíces del
	// componente).
	read := func(rel string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(
			`<extension type="component"><name>com_evil</name>
			<files folder="site"><filename>../../images/planted.php</filename></files>
			</extension>`)), nil
	}
	entries := entriesFromPaths("administrator/components/com_evil/com_evil.xml", "images/planted.php")
	disc := Discover(entries, read, func(string) bool { return false }, 1)
	obs := DetectSuspicious(disc.Extensions, 1)
	if len(obs) == 0 {
		t.Fatal("una declaración fuera de las raíces del tipo debe ser sospechosa")
	}
	// Una declaración legítima multi-raíz NO dispara.
	entries2, read2 := labextTree()
	disc2 := Discover(entries2, read2, func(string) bool { return false }, 1)
	if obs2 := DetectSuspicious(disc2.Extensions, 1); len(obs2) != 0 {
		t.Fatalf("una extensión legítima no debe ser sospechosa: %d", len(obs2))
	}
}
