package extbaseline

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"j0witness/internal/inventory"
	"j0witness/internal/lab"
	"j0witness/internal/manifest"
)

// testComponentTarget construye el InstallTarget de un componente igual que
// SimulateComponent (formulaico desde element): estos tests ejercitan Fetch
// directamente (sin pasar por readInstalledExtension/CLI), así que arman a
// mano el target que la CLI le pasaría tras localizar el manifiesto instalado.
func testComponentTarget(element string) manifest.InstallTarget {
	return manifest.InstallTarget{
		Type:           manifest.Component,
		ElementKey:     element,
		FilesRoot:      "components/" + element,
		AdminFilesRoot: "administrator/components/" + element,
		MediaBase:      "media",
		MediaFallback:  element,
		ManifestDir:    "administrator/components/" + element,
	}
}

// openTestStore abre un Store efímero para el test (no hay helper exportado
// en el paquete inventory; Open(tmp) es el patrón que usa store_test.go).
func openTestStore(t *testing.T) *inventory.Store {
	t.Helper()
	s, err := inventory.Open(filepath.Join(t.TempDir(), "inv.sqlite"))
	if err != nil {
		t.Fatalf("abriendo store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestFetchHermetic(t *testing.T) {
	pkg := lab.LabExtPackage() // paquete oficial sintético de com_labext (versión 2.3.1)
	// Servidor loopback: /update.xml y /pkg.zip.
	var updateXML string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/update.xml":
			fmt.Fprint(w, updateXML)
		case "/pkg.zip":
			w.Write(pkg)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	updateXML = fmt.Sprintf(`<?xml version="1.0"?><updates><update>`+
		`<element>com_labext</element><version>2.3.1</version>`+
		`<downloads><downloadurl type="full" format="zip">%s/pkg.zip</downloadurl></downloads>`+
		`<sha256>%s</sha256>`+
		`</update></updates>`, srv.URL, sha256Hex(pkg))

	store := openTestStore(t)
	var stderr bytes.Buffer
	version, n, err := Fetch(&stderr, store, testComponentTarget("com_labext"), "/site", srv.URL+"/update.xml", "2.3.1")
	if err != nil {
		t.Fatalf("fetch: %v\n%s", err, stderr.String())
	}
	if version != "2.3.1" || n == 0 {
		t.Fatalf("version=%q n=%d", version, n)
	}
	// El baseline quedó cacheado con source "updateserver".
	id, _, src, err := store.FindExtensionBaseline("com_labext", "2.3.1")
	if err != nil || src != "updateserver" || id == 0 {
		t.Fatalf("baseline: %v src=%q", err, src)
	}
	// Enumeró la red en stderr antes de tocarla.
	if !bytes.Contains(stderr.Bytes(), []byte("network-fetch")) {
		t.Fatalf("no enumeró la red: %s", stderr.String())
	}

	// Versión distinta a la que sirve → error claro, sin cachear.
	if _, _, err := Fetch(&stderr, store, testComponentTarget("com_labext"), "/site", srv.URL+"/update.xml", "9.9.9"); err == nil {
		t.Fatal("versión no servida debe fallar")
	}
}

// TestFetchPaidPackageForbidden cubre el camino de "paquete de pago": el
// update server resuelve la versión pero la descarga del paquete devuelve 403
// (típico de extensiones comerciales sin clave de suscripción). Fetch debe
// fallar con un mensaje que sugiera `extension add`, sin cachear nada.
func TestFetchPaidPackageForbidden(t *testing.T) {
	pkg := lab.LabExtPackage()
	var updateXML string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/update.xml":
			fmt.Fprint(w, updateXML)
		case "/pkg.zip":
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	updateXML = fmt.Sprintf(`<?xml version="1.0"?><updates><update>`+
		`<element>com_labext</element><version>2.3.1</version>`+
		`<downloads><downloadurl type="full" format="zip">%s/pkg.zip</downloadurl></downloads>`+
		`<sha256>%s</sha256>`+
		`</update></updates>`, srv.URL, sha256Hex(pkg))

	store := openTestStore(t)
	var stderr bytes.Buffer
	_, _, err := Fetch(&stderr, store, testComponentTarget("com_labext"), "/site", srv.URL+"/update.xml", "2.3.1")
	if err == nil {
		t.Fatal("descarga con 403 debe fallar")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("extension add")) {
		t.Fatalf("el error debe sugerir `extension add`: %v", err)
	}
	if _, _, _, err := store.FindExtensionBaseline("com_labext", "2.3.1"); err == nil {
		t.Fatal("no debe haber quedado nada cacheado tras el 403")
	}
}

// TestFetchPackageVersionMismatch cubre el Principio VI: el update XML
// resuelve la versión instalada (2.3.1) y su sha256 declarado coincide con lo
// que de verdad sirve /pkg.zip, pero el PAQUETE en sí declara otra versión en
// su manifiesto (9.9.9) — como si el update server tuviera una entrada mal
// etiquetada o el paquete no correspondiera a la versión anunciada. Fetch debe
// fallar tras SimulateComponent, sin cachear nada, y su error debe sugerir
// `extension add`.
func TestFetchPackageVersionMismatch(t *testing.T) {
	pkg := lab.LabExtPackageWithVersion("9.9.9") // el paquete servido declara 9.9.9
	var updateXML string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/update.xml":
			fmt.Fprint(w, updateXML)
		case "/pkg.zip":
			w.Write(pkg)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	// El XML anuncia la versión INSTALADA (2.3.1) y el sha256 real del
	// paquete servido (para que la verificación de hash pase y el fallo se
	// deba exclusivamente a la discrepancia de versión tras simular).
	updateXML = fmt.Sprintf(`<?xml version="1.0"?><updates><update>`+
		`<element>com_labext</element><version>2.3.1</version>`+
		`<downloads><downloadurl type="full" format="zip">%s/pkg.zip</downloadurl></downloads>`+
		`<sha256>%s</sha256>`+
		`</update></updates>`, srv.URL, sha256Hex(pkg))

	store := openTestStore(t)
	var stderr bytes.Buffer
	_, _, err := Fetch(&stderr, store, testComponentTarget("com_labext"), "/site", srv.URL+"/update.xml", "2.3.1")
	if err == nil {
		t.Fatal("el paquete declara una versión distinta a la instalada; Fetch debe fallar")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("extension add")) {
		t.Fatalf("el error debe sugerir `extension add`: %v", err)
	}
	if _, _, _, err := store.FindExtensionBaseline("com_labext", "2.3.1"); err == nil {
		t.Fatal("no debe haber quedado nada cacheado tras la discrepancia de versión")
	}
}
