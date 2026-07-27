// Package confscan analiza los archivos de configuración del servidor
// (.htaccess, .user.ini, web.config) en busca de directivas que redirigen o
// amplían la ejecución de PHP. NUNCA ejecuta el archivo (Principio IX): lo
// parsea como texto (htaccess/user_ini) o XML XXE-safe (web.config).
// Determinista: emite observaciones en orden de aparición; no consulta el reloj.
package confscan

import (
	"encoding/xml"
	"path"
	"strings"

	"j0witness/internal/observe"
)

var configBasenames = map[string]string{
	".htaccess": "htaccess", ".user.ini": "user_ini", "web.config": "web_config",
}

// IsConfigFile informa de si rel es un archivo de config del servidor (por basename).
func IsConfigFile(rel string) bool {
	_, ok := configBasenames[path.Base(rel)]
	return ok
}

var inertMediaExt = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
	".ico": true, ".webp": true, ".svg": true, ".txt": true, ".pdf": true,
	".css": true, ".js": true, ".html": true, ".htm": true,
}

// phpExts son las extensiones PHP legítimas (incl. variantes cPanel/legacy
// .php3-.php7 y .phps de código fuente). Mapear cualquiera de ellas al motor
// PHP no "amplía" nada — es la config estándar de shared hosting
// (p.ej. "AddHandler application/x-httpd-php .php .php5 .php4 .php3").
// Compartido entre scanApache y scanWebConfig para evitar listas divergentes
// (Principio VI: un falso positivo es un defecto grave).
var phpExts = map[string]bool{
	".php": true, ".php3": true, ".php4": true, ".php5": true,
	".php7": true, ".phps": true, ".phtml": true, ".phar": true, ".pht": true,
}

type emitFn func(class, directive, target string, line int, extra map[string]any)

// Scan analiza src (contenido de rel) y emite observaciones config_directive_suspicious.
func Scan(rel string, src []byte, nowNS int64) []observe.Observation {
	format, ok := configBasenames[path.Base(rel)]
	if !ok {
		return nil
	}
	var out []observe.Observation
	emit := func(class, directive, target string, line int, extra map[string]any) {
		ev := map[string]any{
			"file": rel, "directive_class": class, "directive": directive,
			"target": target, "line": line, "format": format,
		}
		for k, v := range extra {
			ev[k] = v
		}
		if o, err := observe.New([]byte(rel), observe.ConfigDirective, ev, observe.SrcConfscan, observe.High, nowNS); err == nil {
			out = append(out, o)
		}
	}
	switch format {
	case "htaccess":
		scanApache(src, emit)
	case "user_ini":
		scanIni(src, emit)
	case "web_config":
		scanWebConfig(src, emit)
	}
	return out
}

// scanApache recorre líneas de .htaccess ignorando comentarios (#).
func scanApache(src []byte, emit emitFn) {
	for i, raw := range strings.Split(string(src), "\n") {
		line := i + 1
		t := strings.TrimSpace(raw)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		fields := strings.Fields(t)
		low := strings.ToLower(t)
		switch {
		// php_value/php_admin_value auto_prepend_file|auto_append_file <path>
		case (strings.HasPrefix(low, "php_value ") || strings.HasPrefix(low, "php_admin_value ")) &&
			(containsField(fields, "auto_prepend_file") || containsField(fields, "auto_append_file")):
			dir, target := prependDirective(fields)
			emit("exec_loader", dir, target, line, nil)
		// AddHandler <php-handler> .ext... / AddType application/x-httpd-php .ext / Action / SetHandler
		case strings.HasPrefix(low, "addhandler ") || strings.HasPrefix(low, "addtype ") ||
			strings.HasPrefix(low, "action ") || strings.HasPrefix(low, "sethandler "):
			if isPHPHandlerLine(low) {
				for _, ext := range extsIn(fields) {
					if phpExts[ext] {
						continue // mapear php→php no amplía nada
					}
					emit("handler_widen", fields[0], ext, line, map[string]any{"inert_media": inertMediaExt[ext]})
				}
			}
		// php_flag/php_value allow_url_include on|1 ; disable_functions vacío ; include_path
		case strings.HasPrefix(low, "php_flag ") || strings.HasPrefix(low, "php_value ") ||
			strings.HasPrefix(low, "php_admin_flag ") || strings.HasPrefix(low, "php_admin_value "):
			if class, dir, target, state := phpSetting(fields); class != "" {
				emit(class, dir, target, line, map[string]any{"state": state})
			}
		}
	}
}

// scanIni recorre .user.ini/php.ini ignorando comentarios (;).
func scanIni(src []byte, emit emitFn) {
	for i, raw := range strings.Split(string(src), "\n") {
		line := i + 1
		t := strings.TrimSpace(raw)
		if t == "" || strings.HasPrefix(t, ";") {
			continue
		}
		eq := strings.IndexByte(t, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(t[:eq]))
		val := strings.TrimSpace(t[eq+1:])
		switch key {
		case "auto_prepend_file", "auto_append_file":
			emit("exec_loader", key, val, line, nil)
		case "allow_url_include":
			if isOn(val) {
				emit("php_setting", key, "", line, map[string]any{"state": "on"})
			}
		case "disable_functions":
			if val == "" {
				emit("php_setting", key, "", line, map[string]any{"state": "empty"})
			}
		case "include_path":
			emit("php_setting", key, val, line, map[string]any{"state": "set"})
		}
	}
}

// scanWebConfig parsea web.config (XML XXE-safe) buscando <add> de <handlers>
// que mapee una extensión no-PHP a un procesador PHP.
func scanWebConfig(src []byte, emit emitFn) {
	type addElem struct {
		Path            string `xml:"path,attr"`
		ScriptProcessor string `xml:"scriptProcessor,attr"`
		Modules         string `xml:"modules,attr"`
	}
	dec := xml.NewDecoder(strings.NewReader(string(src)))
	dec.Strict = false
	dec.Entity = map[string]string{} // sin entidades → XXE off (Principio IX)
	line := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "add" {
			continue
		}
		var a addElem
		if dec.DecodeElement(&a, &se) != nil {
			continue
		}
		low := strings.ToLower(a.ScriptProcessor + " " + a.Modules)
		if !strings.Contains(low, "php") {
			continue
		}
		ext := extFromPath(a.Path) // "*.jpg" → ".jpg"
		if ext == "" || phpExts[ext] {
			continue
		}
		line++
		emit("handler_widen", "web.config:handlers", ext, line, map[string]any{"inert_media": inertMediaExt[ext]})
	}
}

// --- helpers ---

// containsField informa si name aparece como campo exacto (case-insensitive)
// en fields. Evita el falso positivo de substring (p.ej. "auto_prepend_file"
// dentro de un comentario ya se filtra antes; aquí evita matchear un valor
// que contenga la palabra como subcadena de otra cosa).
func containsField(fields []string, name string) bool {
	for _, f := range fields {
		if strings.EqualFold(f, name) {
			return true
		}
	}
	return false
}

// prependDirective localiza auto_prepend_file/auto_append_file en fields y
// devuelve (directiva, ruta-objetivo). fields[0] es la directiva Apache
// (php_value/php_admin_value); fields[1] es el nombre de la opción PHP;
// fields[2:] (si existe) es la ruta.
func prependDirective(fields []string) (directive, target string) {
	for i, f := range fields {
		lf := strings.ToLower(f)
		if lf == "auto_prepend_file" || lf == "auto_append_file" {
			directive = lf
			if i+1 < len(fields) {
				target = strings.Join(fields[i+1:], " ")
			}
			return
		}
	}
	return "", ""
}

// isPHPHandlerLine exige que la línea (ya en minúsculas) referencie el motor
// PHP: "x-httpd-php", "php-cgi", un token "php5"/"php7"/"php8", o (para
// SetHandler) el token exacto "php"/"php-script"/"application/x-httpd-php".
// No basta con ser un AddHandler/Action cualquiera (anti-FP).
func isPHPHandlerLine(low string) bool {
	if strings.Contains(low, "x-httpd-php") || strings.Contains(low, "php-cgi") {
		return true
	}
	fields := strings.Fields(low)
	for _, f := range fields {
		if f == "php5" || f == "php7" || f == "php8" ||
			strings.HasPrefix(f, "php5.") || strings.HasPrefix(f, "php7.") || strings.HasPrefix(f, "php8.") {
			return true
		}
	}
	if strings.HasPrefix(low, "sethandler ") {
		for _, f := range fields[1:] {
			if f == "php" || f == "php-script" || strings.Contains(f, "php") {
				return true
			}
		}
	}
	return false
}

// extsIn devuelve las extensiones .xxx presentes en fields (fields[1:], la
// directiva en fields[0] queda excluida), normalizadas a minúsculas.
func extsIn(fields []string) []string {
	var out []string
	if len(fields) == 0 {
		return out
	}
	for _, f := range fields[1:] {
		lf := strings.ToLower(f)
		if !strings.HasPrefix(lf, ".") {
			continue
		}
		// puede venir como ".jpg" o como parte de un mime-type; nos quedamos
		// solo con tokens que empiecen literalmente por "."
		out = append(out, lf)
	}
	return out
}

// phpSetting reconoce las directivas php_flag/php_value/php_admin_flag/
// php_admin_value de interés en fields (Apache: fields[0]=directiva,
// fields[1]=opción, fields[2]=valor). Devuelve class=="" si no aplica.
func phpSetting(fields []string) (class, directive, target, state string) {
	if len(fields) < 2 {
		return "", "", "", ""
	}
	opt := strings.ToLower(fields[1])
	val := ""
	if len(fields) > 2 {
		val = strings.Join(fields[2:], " ")
	}
	switch opt {
	case "allow_url_include":
		if isOn(val) {
			return "php_setting", opt, "", "on"
		}
	case "disable_functions":
		if val == "" {
			return "php_setting", opt, "", "empty"
		}
	case "include_path":
		return "php_setting", opt, val, "set"
	}
	return "", "", "", ""
}

// isOn informa si v (case-insensitive) es una activación reconocida: "on",
// "1", "true".
func isOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "1", "true":
		return true
	}
	return false
}

// extFromPath extrae la extensión (con punto, minúsculas) de un patrón de
// ruta IIS como "*.jpg" o "x.php". "" si no hay extensión reconocible.
func extFromPath(p string) string {
	p = strings.TrimSpace(p)
	i := strings.LastIndexByte(p, '.')
	if i < 0 || i == len(p)-1 {
		return ""
	}
	return strings.ToLower(p[i:])
}
