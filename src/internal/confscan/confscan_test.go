package confscan

import (
	"encoding/json"
	"testing"

	"j0witness/internal/observe"
)

// evidence extrae la evidencia JSON de una observación (imita deriveOne en
// internal/finding/derive.go).
func evidence(o observe.Observation) map[string]any {
	var ev map[string]any
	_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
	return ev
}

func classes(obs []observe.Observation) []string {
	var out []string
	for _, o := range obs {
		ev := evidence(o)
		out = append(out, ev["directive_class"].(string))
	}
	return out
}

func TestExecLoaderHtaccess(t *testing.T) {
	obs := Scan(".htaccess", []byte("php_value auto_prepend_file /tmp/shell.php\n"), 1)
	if len(obs) != 1 {
		t.Fatalf("obs=%d", len(obs))
	}
	ev := evidence(obs[0])
	if ev["directive_class"] != "exec_loader" {
		t.Fatalf("directive_class=%v", ev["directive_class"])
	}
	dir, _ := ev["directive"].(string)
	if dir == "" {
		t.Fatalf("directive vacío: %v", ev)
	}
	if ev["target"] != "/tmp/shell.php" {
		t.Fatalf("target=%v", ev["target"])
	}
}

func TestExecLoaderUserIni(t *testing.T) {
	obs := Scan("images/.user.ini", []byte("auto_prepend_file = /var/www/x.php\n"), 1)
	if len(obs) != 1 {
		t.Fatalf("obs=%d", len(obs))
	}
}

func TestExecLoaderCommentedIsClean(t *testing.T) { // NEGATIVO (anti-FP del substring)
	obs := Scan(".htaccess", []byte("# php_value auto_prepend_file /tmp/shell.php\n"), 1)
	if len(obs) != 0 {
		t.Fatalf("línea comentada no debe marcar: %d", len(obs))
	}
}

func TestHandlerWidenInertMedia(t *testing.T) { // .jpg → PHP: critical-grade
	obs := Scan("images/.htaccess", []byte("AddHandler application/x-httpd-php .jpg\n"), 1)
	if len(obs) != 1 {
		t.Fatalf("obs=%d", len(obs))
	}
	ev := evidence(obs[0])
	if ev["directive_class"] != "handler_widen" {
		t.Fatalf("directive_class=%v", ev["directive_class"])
	}
	if ev["inert_media"] != true {
		t.Fatalf("inert_media=%v", ev["inert_media"])
	}
	if ev["target"] != ".jpg" {
		t.Fatalf("target=%v", ev["target"])
	}
}

func TestAddTypePhp(t *testing.T) {
	obs := Scan(".htaccess", []byte("AddType application/x-httpd-php .png\n"), 1)
	if len(obs) != 1 {
		t.Fatal("AddType php debe marcar")
	}
}

func TestHandlerWidenPhpExtIsClean(t *testing.T) { // NEGATIVO: mapear .php→php no amplía nada
	obs := Scan(".htaccess", []byte("AddHandler application/x-httpd-php .php\n"), 1)
	if len(obs) != 0 {
		t.Fatalf(".php→php no debe marcar: %d", len(obs))
	}
}

func TestHandlerWidenCPanelPhpVariantsIsClean(t *testing.T) { // NEGATIVO: FP real de shared hosting (Principio VI)
	obs := Scan(".htaccess", []byte("AddHandler application/x-httpd-php .php .php5 .php4 .php3\n"), 1)
	if len(obs) != 0 {
		t.Fatalf(".php/.php5/.php4/.php3→php no debe marcar: %d (%v)", len(obs), classes(obs))
	}
}

func TestAddTypePhp5IsClean(t *testing.T) { // NEGATIVO: .php5 es PHP legítimo
	obs := Scan(".htaccess", []byte("AddType application/x-httpd-php .php5\n"), 1)
	if len(obs) != 0 {
		t.Fatalf("AddType .php5 no debe marcar: %d", len(obs))
	}
}

func TestWebConfigPhp5IsClean(t *testing.T) { // NEGATIVO: mismo criterio que Apache en web.config
	x := `<configuration><system.webServer><handlers><add name="x" path="*.php5" verb="*" modules="FastCgiModule" scriptProcessor="c:\php\php-cgi.exe"/></handlers></system.webServer></configuration>`
	obs := Scan("web.config", []byte(x), 1)
	if len(obs) != 0 {
		t.Fatalf("web.config .php5→php-cgi no debe marcar: %d", len(obs))
	}
}

func TestHandlerWidenNonPhpExtStillFlags(t *testing.T) { // confirma que .inc (no-PHP) sigue marcando
	obs := Scan(".htaccess", []byte("AddHandler application/x-httpd-php .inc\n"), 1)
	if len(obs) != 1 {
		t.Fatalf(".inc→php debe seguir marcando: %d", len(obs))
	}
}

func TestPhpSettingAllowUrlInclude(t *testing.T) {
	obs := Scan(".htaccess", []byte("php_flag allow_url_include on\n"), 1)
	if len(obs) != 1 {
		t.Fatal("allow_url_include on debe marcar")
	}
}

func TestPhpSettingDisableFunctionsEmptied(t *testing.T) {
	obs := Scan("x/.user.ini", []byte("disable_functions =\n"), 1)
	if len(obs) != 1 {
		t.Fatal("disable_functions vacío debe marcar")
	}
}

func TestDefaultJoomlaHtaccessIsClean(t *testing.T) { // NEGATIVO clave (anti-FP)
	def := "## No directory listings\n<IfModule mod_autoindex.c>\nIndexIgnore *\n</IfModule>\nOptions +FollowSymLinks\nRewriteEngine On\nRewriteCond %{REQUEST_URI} !^/index.php\nRewriteRule .* index.php [L]\n"
	obs := Scan(".htaccess", []byte(def), 1)
	if len(obs) != 0 {
		t.Fatalf("htaccess Joomla por defecto no debe marcar: %v", classes(obs))
	}
}

func TestWebConfigHandlerWiden(t *testing.T) {
	x := `<configuration><system.webServer><handlers><add name="x" path="*.jpg" verb="*" modules="FastCgiModule" scriptProcessor="c:\php\php-cgi.exe"/></handlers></system.webServer></configuration>`
	obs := Scan("web.config", []byte(x), 1)
	if len(obs) != 1 {
		t.Fatalf("web.config .jpg→php-cgi debe marcar: %d", len(obs))
	}
}

func TestNonConfigFileNotScanned(t *testing.T) {
	if IsConfigFile("index.php") {
		t.Fatal("index.php no es config")
	}
	if !IsConfigFile("a/b/.user.ini") {
		t.Fatal(".user.ini sí es config (cualquier dir)")
	}
}
