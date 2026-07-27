package extbaseline

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"

	"j0witness/internal/manifest"
)

// sortedKeys devuelve las claves de un mapa ordenadas (orden determinista al
// construir el zip de prueba).
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// pkgContent lee del zip de prueba el contenido de name, para comparar contra
// el hash producido por SimulateComponent.
func pkgContent(t *testing.T, pkg []byte, name string) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			b, err := io.ReadAll(rc)
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
	}
	t.Fatalf("no está en el zip de prueba: %s", name)
	return ""
}

func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	// orden determinista
	for _, name := range sortedKeys(files) {
		fw, _ := w.Create(name)
		fw.Write([]byte(files[name]))
	}
	w.Close()
	return buf.Bytes()
}

func TestSimulateComponent(t *testing.T) {
	manifest := `<?xml version="1.0"?>
<extension type="component">
	<name>Lab Ext</name>
	<version>2.3.1</version>
	<scriptfile>script.php</scriptfile>
	<files folder="site"><filename>router.php</filename><folder>src</folder></files>
	<media folder="media" destination="com_labext"><folder>js</folder></media>
	<administration><files folder="admin"><filename>labext.php</filename></files></administration>
</extension>`
	pkg := buildZip(t, map[string]string{
		"labext.xml":         manifest,
		"script.php":         "<?php // installer\n",
		"site/router.php":    "<?php // router\n",
		"site/src/Model.php": "<?php // model\n",
		"admin/labext.php":   "<?php // admin\n",
		"media/js/app.js":    "// front\n",
	})
	version, files, pkgSHA, err := SimulateComponent("com_labext", pkg)
	if err != nil {
		t.Fatal(err)
	}
	if version != "2.3.1" {
		t.Fatalf("version=%q", version)
	}
	sumPkg := sha256.Sum256(pkg)
	if pkgSHA != hex.EncodeToString(sumPkg[:]) {
		t.Fatalf("pkgSHA no coincide con sha256(pkgRaw): %s", pkgSHA)
	}
	want := map[string]string{
		"administrator/components/com_labext/labext.xml": "labext.xml",
		"administrator/components/com_labext/script.php": "script.php",
		"administrator/components/com_labext/labext.php": "admin/labext.php",
		"components/com_labext/router.php":               "site/router.php",
		"components/com_labext/src/Model.php":            "site/src/Model.php",
		"media/com_labext/js/app.js":                     "media/js/app.js",
	}
	if len(files) != len(want) {
		t.Fatalf("rutas: %v", files)
	}
	for installed, src := range want {
		h, ok := files[installed]
		if !ok {
			t.Fatalf("falta ruta instalada %s (tengo %v)", installed, files)
		}
		sum := sha256.Sum256([]byte(pkgContent(t, pkg, src)))
		if h != hex.EncodeToString(sum[:]) {
			t.Fatalf("hash de %s no coincide con el contenido del paquete", installed)
		}
	}
}

// TestSimulateComponentAmbiguousManifest: dos manifiestos de componente en la
// raíz del paquete son una ambigüedad genuina (¿cuál instala el instalador?);
// para una línea base forense, eso debe fallar de forma explícita y NUNCA
// resolverse eligiendo uno al azar según el orden de iteración de un mapa
// (Principio IV: determinismo).
func TestSimulateComponentAmbiguousManifest(t *testing.T) {
	manA := `<?xml version="1.0"?>
<extension type="component">
	<name>A</name>
	<version>1.0.0</version>
</extension>`
	manB := `<?xml version="1.0"?>
<extension type="component">
	<name>B</name>
	<version>2.0.0</version>
</extension>`
	pkg := buildZip(t, map[string]string{
		"a.xml": manA,
		"b.xml": manB,
	})
	_, _, _, err := SimulateComponent("com_x", pkg)
	if err == nil {
		t.Fatal("se esperaba error por manifiestos de componente ambiguos en la raíz")
	}
	if !strings.Contains(err.Error(), "múltiples manifiestos de componente") {
		t.Fatalf("error inesperado: %v", err)
	}
	if !strings.Contains(err.Error(), "a.xml") || !strings.Contains(err.Error(), "b.xml") {
		t.Fatalf("el error debería nombrar ambos manifiestos candidatos: %v", err)
	}
}

// TestSimulateComponentManifestNotAtRoot: un paquete cuyo único manifiesto de
// componente está anidado (no en la raíz del paquete) no es instalable como
// componente vía el mapeo raíz→administración; debe fallar con el error de
// "no hay manifiesto en la raíz", no inventar una ruta.
func TestSimulateComponentManifestNotAtRoot(t *testing.T) {
	man := `<?xml version="1.0"?>
<extension type="component">
	<name>Anidado</name>
	<version>1.0.0</version>
</extension>`
	pkg := buildZip(t, map[string]string{
		"sub/manifest.xml": man,
	})
	_, _, _, err := SimulateComponent("com_x", pkg)
	if err == nil {
		t.Fatal("se esperaba error: manifiesto no está en la raíz del paquete")
	}
	if !strings.Contains(err.Error(), "no contiene un manifiesto de componente en la raíz") {
		t.Fatalf("error inesperado: %v", err)
	}
}

// TestSimulateComponentMediaDestFallback: `<media folder="media">` SIN
// `destination=` debe caer al elemento de destino (element), no quedar sin
// mapear (arista antes no cubierta por ningún test).
func TestSimulateComponentMediaDestFallback(t *testing.T) {
	man := `<?xml version="1.0"?>
<extension type="component">
	<name>MediaFallback</name>
	<version>1.0.0</version>
	<media folder="media"><folder>js</folder></media>
</extension>`
	pkg := buildZip(t, map[string]string{
		"manifest.xml":    man,
		"media/js/app.js": "// front\n",
	})
	_, files, _, err := SimulateComponent("com_foo", pkg)
	if err != nil {
		t.Fatal(err)
	}
	h, ok := files["media/com_foo/js/app.js"]
	if !ok {
		t.Fatalf("falta la ruta de media con destino por defecto al elemento (tengo %v)", files)
	}
	sum := sha256.Sum256([]byte("// front\n"))
	if h != hex.EncodeToString(sum[:]) {
		t.Fatal("hash de media/com_foo/js/app.js no coincide")
	}
}

// TestSimulateComponentZipBombEntryCount: un paquete con más entradas que
// maxPkgEntries debe fallar ruidosamente ANTES de leer su contenido (anti
// zip-bomb, Principio IX), en vez de agotar memoria o tiempo. Se usa el tope
// de NÚMERO de entradas (no el de bytes descomprimidos) porque es el que se
// puede probar de forma rápida y determinista sin asignar cientos de MiB.
func TestSimulateComponentZipBombEntryCount(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for i := 0; i < maxPkgEntries+1; i++ {
		fw, err := w.Create(fmt.Sprintf("f%d.txt", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := SimulateComponent("com_bomb", buf.Bytes())
	if err == nil {
		t.Fatal("se esperaba error por exceso de entradas (posible zip bomb)")
	}
	if !strings.Contains(err.Error(), "zip bomb") && !strings.Contains(err.Error(), "demasiados archivos") {
		t.Fatalf("error inesperado: %v", err)
	}
}

// TestSimulateComponentPathCollision: si dos orígenes del paquete (aquí: el
// manifiesto de raíz y un archivo declarado dentro de la carpeta admin con el
// mismo nombre base) mapean a la MISMA ruta instalada con contenido
// DISTINTO, la línea base sería ambigua para esa ruta — debe fallar. Si el
// contenido es idéntico (mismo hash), es inofensivo (idempotente) y no debe
// fallar.
func TestSimulateComponentPathCollision(t *testing.T) {
	man := `<?xml version="1.0"?>
<extension type="component">
	<name>Coll</name>
	<version>1.0.0</version>
	<administration><files folder="admin"><filename>manifest.xml</filename></files></administration>
</extension>`

	t.Run("contenido distinto → error de colisión", func(t *testing.T) {
		pkg := buildZip(t, map[string]string{
			"manifest.xml":       man,
			"admin/manifest.xml": "contenido distinto del manifiesto\n",
		})
		_, _, _, err := SimulateComponent("com_coll", pkg)
		if err == nil {
			t.Fatal("se esperaba error de colisión de ruta instalada")
		}
		if !strings.Contains(err.Error(), "colisión de ruta instalada") {
			t.Fatalf("error inesperado: %v", err)
		}
	})

	t.Run("mismo contenido → idempotente, sin error", func(t *testing.T) {
		pkg := buildZip(t, map[string]string{
			"manifest.xml":       man,
			"admin/manifest.xml": man, // bytes idénticos al manifiesto de raíz
		})
		_, files, _, err := SimulateComponent("com_coll", pkg)
		if err != nil {
			t.Fatalf("colisión con el mismo contenido no debería fallar: %v", err)
		}
		want := "administrator/components/com_coll/manifest.xml"
		h, ok := files[want]
		if !ok {
			t.Fatalf("falta la ruta %s (tengo %v)", want, files)
		}
		sum := sha256.Sum256([]byte(man))
		if h != hex.EncodeToString(sum[:]) {
			t.Fatal("hash de la ruta colisionada (idéntica) no coincide")
		}
	})
}

// wantFiles compara files contra el mapa de ruta instalada→ruta de origen en
// el paquete (usa pkgContent para calcular el sha256 esperado), y falla si
// sobra o falta alguna ruta (Principio VI: ni de más ni de menos).
func wantFiles(t *testing.T, pkg []byte, files map[string]string, want map[string]string) {
	t.Helper()
	if len(files) != len(want) {
		t.Fatalf("rutas instaladas = %v, se esperaban %v", sortedKeys(files), func() []string {
			ks := make([]string, 0, len(want))
			for k := range want {
				ks = append(ks, k)
			}
			sort.Strings(ks)
			return ks
		}())
	}
	for installed, src := range want {
		h, ok := files[installed]
		if !ok {
			t.Fatalf("falta ruta instalada %s (tengo %v)", installed, sortedKeys(files))
		}
		sum := sha256.Sum256([]byte(pkgContent(t, pkg, src)))
		if h != hex.EncodeToString(sum[:]) {
			t.Fatalf("hash de %s no coincide con el contenido del paquete (%s)", installed, src)
		}
	}
}

// TestSimulateExtensionFlatPlugin: paquete de PLUGIN en layout PLANO (sin
// folder= en <files>): el manifiesto declara <filename>/<folder> relativos a
// la raíz del propio paquete, no a una subcarpeta "site"/"admin". Este layout
// es igual de real que el de folder= (muchos plugins de terceros lo usan) y
// SimulateComponent (2a) no lo soportaba: solo sabía mapear folder=.
func TestSimulateExtensionFlatPlugin(t *testing.T) {
	man := `<?xml version="1.0"?>
<extension type="plugin" group="system"><name>foo</name><version>1.0</version><files><filename>foo.php</filename><folder>tmpl</folder></files></extension>`
	pkg := buildZip(t, map[string]string{
		"foo.xml":          man,
		"foo.php":          "<?php // plugin\n",
		"tmpl/default.php": "<?php // tmpl\n",
	})
	target := manifest.InstallTarget{
		Type: manifest.Plugin, ElementKey: "system/foo",
		FilesRoot: "plugins/system/foo", ManifestDir: "plugins/system/foo", MediaBase: "media",
	}
	v, files, _, err := SimulateExtension(target, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if v != "1.0" {
		t.Fatalf("version=%q", v)
	}
	wantFiles(t, pkg, files, map[string]string{
		"plugins/system/foo/foo.xml":          "foo.xml",
		"plugins/system/foo/foo.php":          "foo.php",
		"plugins/system/foo/tmpl/default.php": "tmpl/default.php",
	})
}

// TestSimulateExtensionFolderModule: paquete de MÓDULO en layout con
// folder= (el otro layout que soporta SimulateExtension): todo lo que hay
// bajo la carpeta declarada se mapea, sin enumerar archivo por archivo.
func TestSimulateExtensionFolderModule(t *testing.T) {
	man := `<?xml version="1.0"?>
<extension type="module"><name>mod_synth</name><version>1.2.0</version><files folder="mod"><filename>mod_synth.php</filename><folder>tmpl</folder></files></extension>`
	pkg := buildZip(t, map[string]string{
		"mod_synth.xml":        man,
		"mod/mod_synth.php":    "<?php // module entry\n",
		"mod/tmpl/default.php": "<?php // module tmpl\n",
	})
	target := manifest.InstallTarget{
		Type: manifest.Module, ElementKey: "mod_synth",
		FilesRoot: "modules/mod_synth", ManifestDir: "modules/mod_synth",
		MediaBase: "media", MediaFallback: "mod_synth",
	}
	v, files, _, err := SimulateExtension(target, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if v != "1.2.0" {
		t.Fatalf("version=%q", v)
	}
	wantFiles(t, pkg, files, map[string]string{
		"modules/mod_synth/mod_synth.xml":    "mod_synth.xml",
		"modules/mod_synth/mod_synth.php":    "mod/mod_synth.php",
		"modules/mod_synth/tmpl/default.php": "mod/tmpl/default.php",
	})
}

// TestSimulateExtensionLibrary: paquete de LIBRERÍA, donde FilesRoot
// (libraries/vendor/synthlib) y ManifestDir (administrator/manifests/libraries)
// difieren radicalmente — a diferencia de componente/módulo/plugin/plantilla,
// donde ManifestDir suele coincidir con (o derivarse de) FilesRoot/AdminFilesRoot.
func TestSimulateExtensionLibrary(t *testing.T) {
	man := `<?xml version="1.0"?>
<extension type="library"><libraryname>vendor/synthlib</libraryname><name>Synth Lib</name><version>3.0.0</version><files folder="lib"><folder>src</folder></files></extension>`
	pkg := buildZip(t, map[string]string{
		"synthlib.xml":     man,
		"lib/src/Core.php": "<?php // lib core\n",
	})
	target := manifest.InstallTarget{
		Type: manifest.Library, ElementKey: "vendor/synthlib",
		FilesRoot: "libraries/vendor/synthlib", ManifestDir: "administrator/manifests/libraries",
		MediaBase: "media", MediaFallback: "Synth Lib",
	}
	v, files, _, err := SimulateExtension(target, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if v != "3.0.0" {
		t.Fatalf("version=%q", v)
	}
	wantFiles(t, pkg, files, map[string]string{
		"administrator/manifests/libraries/synthlib.xml": "synthlib.xml",
		"libraries/vendor/synthlib/src/Core.php":         "lib/src/Core.php",
	})
}

// TestSimulateExtensionWrongType: si target.Type no coincide con el tipo que
// declara el manifiesto del paquete (p.ej. se pide instalar como plugin un
// paquete que en realidad es un módulo), no hay manifiesto candidato del tipo
// esperado en la raíz: falla explícitamente, nunca se instala "lo que haya".
func TestSimulateExtensionWrongType(t *testing.T) {
	man := `<?xml version="1.0"?>
<extension type="module"><name>mod_x</name><version>1.0.0</version></extension>`
	pkg := buildZip(t, map[string]string{"mod_x.xml": man})
	target := manifest.InstallTarget{
		Type: manifest.Plugin, ElementKey: "system/x",
		FilesRoot: "plugins/system/x", ManifestDir: "plugins/system/x",
	}
	_, _, _, err := SimulateExtension(target, pkg)
	if err == nil {
		t.Fatal("se esperaba error: el manifiesto del paquete no es del tipo esperado (plugin)")
	}
	if !strings.Contains(err.Error(), "no contiene un manifiesto de plugin en la raíz") {
		t.Fatalf("error inesperado: %v", err)
	}
}
