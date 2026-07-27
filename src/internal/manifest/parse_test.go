package manifest

import (
	"strings"
	"testing"
)

// T103: parseo de un manifiesto de componente moderno.
func TestParseComponent(t *testing.T) {
	const xml = `<?xml version="1.0"?>
<extension type="component" method="upgrade">
	<name>com_labext</name>
	<author>Lab Author</author>
	<version>2.3.1</version>
	<files folder="site">
		<filename>router.php</filename>
		<folder>src</folder>
	</files>
	<media destination="com_labext" folder="media"><folder>js</folder></media>
	<administration>
		<files folder="admin">
			<filename>labext.php</filename>
			<folder>src</folder>
		</files>
	</administration>
</extension>`
	m, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != Component || m.Name != "com_labext" || m.Version != "2.3.1" || m.Author != "Lab Author" {
		t.Fatalf("metadatos: %+v", m)
	}
	if len(m.Site.Filenames) != 1 || m.Site.Filenames[0] != "router.php" {
		t.Fatalf("site filenames: %v", m.Site.Filenames)
	}
	if len(m.Site.Folders) != 1 || m.Site.Folders[0] != "src" {
		t.Fatalf("site folders: %v", m.Site.Folders)
	}
	if len(m.Admin.Filenames) != 1 || len(m.Admin.Folders) != 1 {
		t.Fatalf("admin: %+v", m.Admin)
	}
	if len(m.Media) != 1 || m.Media[0].Dest != "com_labext" {
		t.Fatalf("media: %+v", m.Media)
	}
}

// D2: una librería declara su raíz por <libraryname> (no por <name>) y sus
// traducciones por <languages> (site y admin).
func TestParseLibraryAndLanguages(t *testing.T) {
	const xml = `<?xml version="1.0"?>
<extension type="library" method="upgrade">
	<name>J2XML</name>
	<libraryname>eshiol/J2xml</libraryname>
	<files><filename>Exporter.php</filename><folder>Table</folder></files>
	<languages folder="language">
		<language tag="en-GB">en-GB/en-GB.lib_j2xml.ini</language>
		<language tag="en-GB">en-GB/en-GB.lib_j2xml.sys.ini</language>
	</languages>
</extension>`
	m, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != Library || m.LibraryName != "eshiol/J2xml" {
		t.Fatalf("librería: type=%v libraryname=%q", m.Type, m.LibraryName)
	}
	if len(m.LangDecls) != 2 || m.LangDecls[0].Tag != "en-GB" || m.LangDecls[0].Base != "en-GB.lib_j2xml.ini" {
		t.Fatalf("lang decls: %+v", m.LangDecls)
	}
}

// D2: un componente puede declarar traducciones de site y de admin.
func TestParseComponentAdminLanguages(t *testing.T) {
	const xml = `<?xml version="1.0"?>
<extension type="component">
	<name>SP Page Builder</name>
	<languages folder="language/site"><language tag="en-GB">en-GB/en-GB.com_sppagebuilder.ini</language></languages>
	<administration>
		<files folder="admin"><filename>x.php</filename></files>
		<languages folder="language/admin">
			<language tag="en-GB">en-GB/en-GB.com_sppagebuilder.ini</language>
			<language tag="en-GB">en-GB/en-GB.com_sppagebuilder.sys.ini</language>
		</languages>
	</administration>
</extension>`
	m, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	// 1 de site + 2 de admin, unificadas.
	if len(m.LangDecls) != 3 {
		t.Fatalf("lang decls: %+v", m.LangDecls)
	}
	bases := map[string]bool{}
	for _, ld := range m.LangDecls {
		bases[ld.Base] = true
	}
	if !bases["en-GB.com_sppagebuilder.ini"] || !bases["en-GB.com_sppagebuilder.sys.ini"] {
		t.Fatalf("bases: %+v", m.LangDecls)
	}
}

// D2: el formato alterno `language/<tag>.<x>.ini` (Helix, profileimage) también
// resuelve al basename y tag correctos.
func TestParseLanguagesAltFormat(t *testing.T) {
	const xml = `<?xml version="1.0"?>
<extension type="plugin" group="system">
	<name>System - Helix</name>
	<languages>
		<language tag="en-GB">language/en-GB.plg_system_helixultimate.ini</language>
	</languages>
</extension>`
	m, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.LangDecls) != 1 || m.LangDecls[0].Tag != "en-GB" || m.LangDecls[0].Base != "en-GB.plg_system_helixultimate.ini" {
		t.Fatalf("alt format: %+v", m.LangDecls)
	}
}

// D3: <scriptfile> se lee como archivo del script de instalación.
func TestParseScriptFile(t *testing.T) {
	const xml = `<?xml version="1.0"?>
<extension type="component">
	<name>SP Page Builder</name>
	<scriptfile>installer.script.php</scriptfile>
	<administration><files folder="admin"><filename>x.php</filename></files></administration>
</extension>`
	m, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	if m.ScriptFile != "installer.script.php" {
		t.Fatalf("scriptfile=%q", m.ScriptFile)
	}
}

// T103: XML malformado devuelve error, nunca panic.
func TestParseMalformed(t *testing.T) {
	_, err := Parse(strings.NewReader(`<extension type="component"><name>rota`))
	if err == nil {
		t.Fatal("XML malformado debe devolver error")
	}
}

// T103: manifiesto legacy 1.5 como mejor esfuerzo.
func TestParseLegacy(t *testing.T) {
	const xml = `<?xml version="1.0"?>
<install type="component" version="1.5">
	<name>com_old</name>
	<version>1.0</version>
	<files>
		<filename>admin.old.php</filename>
	</files>
</install>`
	m, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Legacy || m.Type != Component || m.Name != "com_old" {
		t.Fatalf("legacy: %+v", m)
	}
}

// T103: XXE — una entidad externa no se resuelve (no filtra el archivo local).
func TestParseNoXXE(t *testing.T) {
	const evil = `<?xml version="1.0"?>
<!DOCTYPE extension [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<extension type="component"><name>&xxe;</name><version>1.0</version></extension>`
	m, err := Parse(strings.NewReader(evil))
	// Go rechaza la entidad no definida en su tabla (Entity vacío) → error, o
	// la deja sin resolver. En ningún caso lee /etc/passwd.
	if err == nil && strings.Contains(m.Name, "root:") {
		t.Fatal("XXE: se resolvió una entidad externa")
	}
}

// T103: tope de tamaño anti-DoS.
func TestParseSizeLimit(t *testing.T) {
	big := "<extension type=\"component\"><name>x</name>" + strings.Repeat(" ", MaxSize) + "</extension>"
	if _, err := Parse(strings.NewReader(big)); err == nil {
		t.Fatal("un manifiesto por encima del tope debe rechazarse")
	}
}

// fase 2b: parseo de <updateservers><server>URL</server></updateservers>.
func TestParseUpdateServers(t *testing.T) {
	const xml = `<?xml version="1.0"?>
<extension type="component">
	<name>SP Page Builder</name>
	<version>6.7.0</version>
	<updateservers>
		<server type="extension" priority="1" name="SP Page Builder">https://www.joomshaper.com/updates/com-sp-page-builder-pro-next.xml</server>
	</updateservers>
</extension>`
	m, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.UpdateServers) != 1 || m.UpdateServers[0] != "https://www.joomshaper.com/updates/com-sp-page-builder-pro-next.xml" {
		t.Fatalf("update servers: %v", m.UpdateServers)
	}
}
