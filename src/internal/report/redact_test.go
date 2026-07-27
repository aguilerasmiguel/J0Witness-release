package report

import (
	"strings"
	"testing"
)

// T021 (unidad, barrera 2): el redactor elimina valores sensibles de
// cualquier documento serializado que los arrastre.
func TestRedactBarrier2(t *testing.T) {
	doc := []byte(`{"evidence":{"excerpt":"public $password = 'SECRETO_FILTRADO'; public $sitename = 'Mi Sitio'; var $secret = \"OTRA_CLAVE\";"}}`)
	out := string(Redact(doc))
	if strings.Contains(out, "SECRETO_FILTRADO") || strings.Contains(out, "OTRA_CLAVE") {
		t.Fatalf("valores sensibles sobreviven al redactor: %s", out)
	}
	if !strings.Contains(out, Redacted) {
		t.Fatal("falta la marca de redacción")
	}
	// Las claves no sensibles no se tocan.
	if !strings.Contains(out, "Mi Sitio") {
		t.Fatal("el redactor borró un valor no sensible")
	}
}
