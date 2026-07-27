// Package codescan implementa L4: analiza el contenido de los ejecutables PHP
// (tokenizados como dato por internal/phpscan) y emite observaciones
// code_suspicious ante construcciones casi inequívocas de webshell/backdoor. No
// decide hallazgos: eso es de la capa de derivación (Principio II).
package codescan

import (
	"strings"

	"j0witness/internal/observe"
	"j0witness/internal/phpscan"
)

// Conjuntos de nombres (en minúsculas; PHP no distingue mayúsculas en nombres de
// función). Un sink es una función que ejecuta/interpreta su argumento.
var (
	execSinks = map[string]bool{ // ejecutan PHP a partir de una cadena
		"eval": true, "assert": true, "create_function": true,
	}
	shellSinks = map[string]bool{ // ejecutan comandos del sistema
		"system": true, "exec": true, "shell_exec": true, "passthru": true,
		"popen": true, "proc_open": true, "pcntl_exec": true,
	}
	decodeFuncs = map[string]bool{ // decodifican/inflan un payload
		"base64_decode": true, "gzinflate": true, "gzuncompress": true,
		"gzdecode": true, "str_rot13": true, "hex2bin": true, "convert_uudecode": true,
	}
	// superglobalNames es la fuente única de verdad (orden fijo, necesario para
	// que la búsqueda del "más a la izquierda" en superglobalInText sea
	// determinista — Principio IV: no se puede iterar un mapa para eso).
	// superglobals se deriva de superglobalNames para no mantener dos copias a
	// mano (drift risk: un nombre añadido a una y no a la otra rompe la
	// detección en silencio).
	superglobalNames = []string{
		"$_get", "$_post", "$_request", "$_cookie", "$_server", "$_files",
	}
	superglobals = func() map[string]bool {
		m := make(map[string]bool, len(superglobalNames))
		for _, n := range superglobalNames {
			m[n] = true
		}
		return m
	}()
	// escapeshellFuncs son las funciones de saneamiento de shell de PHP: una
	// superglobal envuelta en una llamada a alguna de estas dentro del primer
	// argumento de un sink queda exenta de CODE-002 (hallazgo 1b).
	escapeshellFuncs = map[string]bool{
		"escapeshellarg": true, "escapeshellcmd": true,
	}
)

// dangerousSinks = execSinks ∪ shellSinks (para CODE-002).
func isDangerousSink(name string) bool { return execSinks[name] || shellSinks[name] }

// finding es un hallazgo crudo del núcleo de detección (suspiciousFindings),
// previo tanto a envolverse en observación (Scan) como a reducirse a una
// lista de nombres de patrón (SuspiciousContent).
type finding struct {
	construct, sink, trigger, via string
	line                          int
}

// SuspiciousContent es el núcleo de detección de patrones sospechosos,
// reutilizable por consumidores que no necesitan observe.Observation (p.ej.
// internal/dbscan sobre el contenido de #__modules): tokeniza src (Principio
// IX: nunca se ejecuta) y devuelve los nombres de construct hallados, en
// orden de aparición. ok = len(patterns) > 0.
func SuspiciousContent(src []byte) (patterns []string, ok bool) {
	findings := suspiciousFindings(src)
	if len(findings) == 0 {
		return nil, false
	}
	patterns = make([]string, len(findings))
	for i, f := range findings {
		patterns[i] = f.construct
	}
	return patterns, true
}

// Scan tokeniza src y emite las observaciones code_suspicious de rel. nowNS es
// el instante del run (determinismo: no se consulta el reloj). Envuelve el
// núcleo de detección (suspiciousFindings, el mismo que usa SuspiciousContent)
// en observaciones con su evidencia completa.
func Scan(rel string, src []byte, nowNS int64) []observe.Observation {
	findings := suspiciousFindings(src)
	var obs []observe.Observation
	for _, f := range findings {
		ev := map[string]any{
			"construct": f.construct, "sink": f.sink, "trigger": f.trigger,
			"line": f.line, "executable": true,
		}
		if f.via != "" {
			ev["via"] = f.via
		}
		o, err := observe.New([]byte(rel), observe.CodeSuspicious, ev, observe.SrcCodescan, observe.High, nowNS)
		if err == nil {
			obs = append(obs, o)
		}
	}
	return obs
}

// suspiciousFindings tokeniza src y recorre los mismos chequeos que antes
// vivían dentro de Scan (CODE-001/002/003 inline + dataflow + backtick).
func suspiciousFindings(src []byte) []finding {
	toks := phpscan.Tokenize(src)
	var out []finding
	emit := func(construct, sink, trigger, via string, line int) {
		out = append(out, finding{construct, sink, trigger, via, line})
	}

	vars := map[string]varFact{}
	// braceDepth y namedFuncBodyDepths delimitan el CIERRE del ámbito: el
	// reinicio de `vars` al ENTRAR en una declaración con nombre (más abajo)
	// no basta, porque los hechos fijados dentro del cuerpo sobrevivían al
	// `}` de cierre y contaminaban el código top-level siguiente (una
	// variable de igual nombre pero de OTRO ámbito — FP de fuga de ámbito).
	// namedFuncBodyDepths es una pila de profundidades de llave: al abrir el
	// `{` que sigue a una declaración con nombre se apila braceDepth; al
	// cerrar exactamente esa llave se reinicia `vars` (vuelta al ámbito
	// envolvente limpio) y se desapila. expectFuncBrace enlaza la declaración
	// recién vista con SU `{` (puede haber tokens de por medio: parámetros ya
	// consumidos por namedFunctionDeclAt, pero el tipo de retorno también:
	// `function foo(): int {`). Las closures (`function(...)`) nunca activan
	// expectFuncBrace, así que su `{`/`}` solo ajustan braceDepth y jamás
	// apilan/desapilan ni disparan el reinicio.
	braceDepth := 0
	var namedFuncBodyDepths []int
	expectFuncBrace := false
	for idx := 0; idx < len(toks); idx++ {
		t := toks[idx]

		// Frontera de función: nuevo ámbito. Solo para DECLARACIONES con
		// nombre (`function foo(...)`, o con retorno por referencia
		// `function &foo(...)`), no para expresiones closure (`function(...)`
		// / `function &(...)`): una closure comparte el ámbito envolvente
		// (conservador; nested-scope real es un no-objetivo explícito), pero
		// SÍ debe seguir viendo — y no borrar — los hechos ya fijados, porque
		// el bucle re-recorre su cuerpo como si fuera top-level.
		if t.Kind == phpscan.Ident && lower(t.Text) == "function" &&
			!methodPrefixed(toks, idx) && namedFunctionDeclAt(toks, idx) {
			vars = map[string]varFact{}
			expectFuncBrace = true
			continue
		}

		// Llaves: rastrean la profundidad para saber cuándo el cuerpo de una
		// función NOMBRADA se cierra (vuelta al ámbito envolvente). Deben
		// verse aquí, ANTES de assignmentAt/callAt, porque un `{`/`}` desnudo
		// no es ni asignación ni llamada y de lo contrario caería sin
		// procesar en ningún otro chequeo.
		if t.Kind == phpscan.Punct && t.Text == "{" {
			braceDepth++
			if expectFuncBrace {
				namedFuncBodyDepths = append(namedFuncBodyDepths, braceDepth)
				expectFuncBrace = false
			}
			continue
		}
		if t.Kind == phpscan.Punct && t.Text == "}" {
			if n := len(namedFuncBodyDepths); n > 0 && braceDepth == namedFuncBodyDepths[n-1] {
				namedFuncBodyDepths = namedFuncBodyDepths[:n-1]
				vars = map[string]varFact{}
			}
			braceDepth--
			continue
		}
		// Declaración sin cuerpo (`abstract function foo();` / firma de
		// interfaz): termina en `;`, nunca abre `{`. Sin este chequeo,
		// expectFuncBrace quedaría pendiente y se ataría por error al
		// siguiente `{` que aparezca (de cualquier bloque, no necesariamente
		// una función), corrompiendo esa entrada de la pila. En PHP válido
		// nunca hay un `;` de nivel superior entre `function foo(...)` y su
		// `{` real (los valores por defecto de parámetros son expresiones,
		// sin `;`), así que este chequeo no afecta a ninguna declaración con
		// cuerpo real.
		if t.Kind == phpscan.Punct && t.Text == ";" {
			expectFuncBrace = false
		}

		// Asignación simple: $v = RHS ; → fija/limpia el hecho.
		if v, rhs, ok := assignmentAt(toks, idx); ok {
			vars[v] = factOf(rhs, vars)
			continue // el RHS se recorre en iteraciones siguientes (los inline lo ven)
		}

		// Llamada por variable: $v ( … ) con nombre dinámico → función dinámica.
		// Excluye `new $v(...)`: instancia una CLASE de nombre dinámico, no
		// invoca una función — patrón extendido y benigno en Joomla (fábricas:
		// Factory.php, DatabaseFactory.php, CacheStorage.php, etc., verificado
		// contra el sitio real) que no debe confundirse con J0W-CODE-004.
		if t.Kind == phpscan.Variable && idx+1 < len(toks) &&
			toks[idx+1].Kind == phpscan.Punct && toks[idx+1].Text == "(" &&
			!methodPrefixed(toks, idx) && !newPrefixed(toks, idx) {
			if vars[lower(t.Text)].dynamicName {
				emit("dynamic_call", "variable_function", lower(t.Text), "dataflow", t.Line)
			}
			// no continue: el interior de la llamada se recorre normalmente
		}

		// Llamada por nombre: sink( … ).
		name, open, ok := callAt(toks, idx)
		if !ok {
			continue
		}
		end := matchParen(toks, open)
		if end < 0 {
			continue
		}
		span := toks[open+1 : end] // tokens del argumento (paréntesis balanceados)

		// --- Inline v1 (sin cambios salvo el "" de via) ---
		// CODE-001: sink de ejecución con una llamada de decodificación dentro.
		if execSinks[name] {
			if trig := decodeCallIn(span); trig != "" {
				emit("obfuscated_eval", name, trig, "", toks[idx].Line)
			}
		}

		// CODE-002: sink peligroso con superglobal / php://input como token desnudo.
		if isDangerousSink(name) {
			if trig := attackerInputIn(span); trig != "" {
				emit("input_to_sink", name, trig, "", toks[idx].Line)
			}
		}
		// CODE-003: preg_replace cuyo primer argumento es un patrón con modificador e.
		if name == "preg_replace" {
			if pat := firstStringArg(span); pat != "" && patternHasEModifier(pat) {
				emit("preg_e", name, pat, "", toks[idx].Line)
			}
		}

		// --- Dataflow hacia sink (variable con hecho en el primer argumento) ---
		arg := firstArgSpan(span)
		if execSinks[name] {
			if v := decodedVarIn(arg, vars); v != "" {
				emit("obfuscated_eval", name, v, "dataflow", toks[idx].Line)
			}
		}
		if isDangerousSink(name) {
			if v := taintedVarIn(arg, vars); v != "" {
				emit("input_to_sink", name, v, "dataflow", toks[idx].Line)
			}
		}

		idx = end // continúa tras el cierre (evita re-escanear el interior como top-level)
	}

	// CODE-002 (operador backtick): `...` con referencia a superglobal dentro.
	for _, t := range toks {
		if t.Kind == phpscan.Backtick {
			if trig := superglobalInText(t.Text); trig != "" {
				emit("input_to_sink", "`backtick`", trig, "", t.Line)
			}
		}
	}
	return out
}

// callAt informa de si toks[idx] es una llamada a la función global `name`:
// un Ident seguido de `(`, NO precedido de -> ni :: (método), y si va precedido
// de `\` (namespace) el token anterior no debe ser un Ident (sería Foo\name, no
// la global \name). Devuelve (nombre en minúsculas, índice del `(`, ok).
func callAt(toks []phpscan.Token, idx int) (string, int, bool) {
	t := toks[idx]
	if t.Kind != phpscan.Ident {
		return "", 0, false
	}
	if idx+1 >= len(toks) || toks[idx+1].Kind != phpscan.Punct || toks[idx+1].Text != "(" {
		return "", 0, false
	}
	// Excluir método (->name, ::name).
	if idx > 0 && toks[idx-1].Kind == phpscan.Punct && (toks[idx-1].Text == "->" || toks[idx-1].Text == "::") {
		return "", 0, false
	}
	// \name global vs Foo\name namespaced.
	if idx > 0 && toks[idx-1].Kind == phpscan.Punct && toks[idx-1].Text == "\\" {
		if idx > 1 && toks[idx-2].Kind == phpscan.Ident {
			return "", 0, false // Foo\name
		}
	}
	return lower(t.Text), idx + 1, true
}

// matchParen devuelve el índice del `)` que cierra el `(` en openIdx, o -1.
func matchParen(toks []phpscan.Token, openIdx int) int {
	depth := 0
	for i := openIdx; i < len(toks); i++ {
		if toks[i].Kind == phpscan.Punct {
			switch toks[i].Text {
			case "(":
				depth++
			case ")":
				depth--
				if depth == 0 {
					return i
				}
			}
		}
	}
	return -1
}

// decodeCallIn devuelve el nombre de la primera llamada a una función de
// decodificación dentro de span, o "".
func decodeCallIn(span []phpscan.Token) string {
	for i := 0; i < len(span); i++ {
		if name, _, ok := callAt(span, i); ok && decodeFuncs[name] {
			return name
		}
	}
	return ""
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

// attackerInputIn devuelve el disparador (nombre de superglobal o "php://input")
// si aparece en el PRIMER argumento (el comando/código; hallazgo 1a) de span,
// excluyendo las superglobales saneadas dentro de escapeshellarg()/
// escapeshellcmd() (hallazgo 1b: exención de escapeshell). El primer
// argumento es siempre el comando/código para todos los sinks de la lista
// (eval/assert/system/exec/shell_exec/passthru/popen/proc_open/pcntl_exec),
// así que argumentos posteriores (p.ej. el entorno de proc_open) no cuentan.
func attackerInputIn(span []phpscan.Token) string {
	arg := firstArgSpan(span)
	exempt := escapeshellExemptRegions(arg)
	for i, t := range arg {
		if t.Kind == phpscan.Variable && superglobals[lower(t.Text)] && !inRegions(i, exempt) {
			return lower(t.Text)
		}
		if t.Kind == phpscan.String && lower(t.Text) == "php://input" {
			return "php://input"
		}
	}
	return ""
}

// escapeshellExemptRegions devuelve los intervalos [ini,fin] (índices en toks)
// cubiertos por una llamada a escapeshellarg/escapeshellcmd.
func escapeshellExemptRegions(toks []phpscan.Token) [][2]int {
	var out [][2]int
	for i := 0; i < len(toks); i++ {
		if name, open, ok := callAt(toks, i); ok && escapeshellFuncs[name] {
			end := matchParen(toks, open)
			if end < 0 {
				end = len(toks) - 1
			}
			out = append(out, [2]int{i, end})
		}
	}
	return out
}

func inRegions(idx int, regions [][2]int) bool {
	for _, r := range regions {
		if idx >= r[0] && idx <= r[1] {
			return true
		}
	}
	return false
}

// firstArgSpan devuelve los tokens del primer argumento de span (los previos
// a la primera coma de nivel superior, profundidad 0 rastreando ()/[] igual
// que firstStringArg). Si no hay coma de nivel superior, devuelve span
// entero (un único argumento).
func firstArgSpan(span []phpscan.Token) []phpscan.Token {
	depth := 0
	for i, t := range span {
		if t.Kind == phpscan.Punct {
			switch t.Text {
			case "(", "[":
				depth++
			case ")", "]":
				depth--
			case ",":
				if depth == 0 {
					return span[:i]
				}
			}
		}
	}
	return span
}

// superglobalInText busca referencias a superglobales dentro del contenido
// crudo de un backtick (p.ej. "$_GET[c]"). Excepción acotada; no interpolación
// general. Si hay varias (p.ej. "$_SERVER[a] $_GET[b]"), devuelve la que
// aparece más a la izquierda (empate: orden de superglobalNames), para que el
// resultado sea determinista pese a que puedan solaparse varios candidatos
// (Principio IV: no se itera el mapa `superglobals` para decidir el trigger).
// Devuelve el nombre o "".
func superglobalInText(s string) string {
	ls := lower(s)
	best := ""
	bestPos := -1
	for _, name := range superglobalNames {
		k := indexSuperglobal(ls, name)
		if k < 0 {
			continue
		}
		if bestPos == -1 || k < bestPos {
			bestPos = k
			best = name
		}
	}
	return best
}

// indexSuperglobal encuentra name en s solo si va seguido de un carácter no
// identificador (evita casar $_getter con $_get).
func indexSuperglobal(s, name string) int {
	from := 0
	for {
		k := strings.Index(s[from:], name)
		if k < 0 {
			return -1
		}
		k += from
		after := k + len(name)
		if after >= len(s) || !isIdentByte(s[after]) {
			return k
		}
		from = k + 1
	}
}

func isIdentByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c >= 0x80
}

// firstStringArg devuelve el contenido del primer literal String de span antes
// de la primera coma de nivel superior, o "".
func firstStringArg(span []phpscan.Token) string {
	depth := 0
	for _, t := range span {
		if t.Kind == phpscan.Punct {
			switch t.Text {
			case "(", "[":
				depth++
			case ")", "]":
				depth--
			case ",":
				if depth == 0 {
					return ""
				}
			}
		}
		if depth == 0 && t.Kind == phpscan.String {
			return t.Text
		}
	}
	return ""
}

// patternHasEModifier informa de si pat es un patrón PCRE cuyo delimitador porta
// el modificador e. El primer carácter es el delimitador de apertura; su pareja
// de cierre es el mismo (o el bracket espejo para ( ) { } [ ] < >); los
// caracteres tras el cierre son los modificadores.
func patternHasEModifier(pat string) bool {
	if len(pat) < 2 {
		return false
	}
	open := pat[0]
	closeDelim := open
	switch open {
	case '(':
		closeDelim = ')'
	case '{':
		closeDelim = '}'
	case '[':
		closeDelim = ']'
	case '<':
		closeDelim = '>'
	}
	// Último cierre.
	last := -1
	for i := len(pat) - 1; i > 0; i-- {
		if pat[i] == closeDelim {
			last = i
			break
		}
	}
	if last < 0 {
		return false
	}
	for _, m := range pat[last+1:] {
		if m == 'e' {
			return true
		}
	}
	return false
}

// varFact son los hechos que rastreamos de una variable dentro de un ámbito.
type varFact struct {
	decoded     bool // asignada desde una cadena de decodificación/inflado
	tainted     bool // asignada desde una superglobal/php://input sin sanear
	dynamicName bool // nombre de función computado (decode o concat con literal)
}

// methodPrefixed informa de si toks[idx] va precedido de -> o :: (acceso a
// método/propiedad), no una función/palabra clave global.
func methodPrefixed(toks []phpscan.Token, idx int) bool {
	return idx > 0 && toks[idx-1].Kind == phpscan.Punct &&
		(toks[idx-1].Text == "->" || toks[idx-1].Text == "::")
}

// newPrefixed informa de si toks[idx] va precedido de la palabra clave `new`:
// `new $v(...)` instancia una clase de nombre dinámico, no llama a una
// función — un patrón de fábrica (factory) omnipresente y benigno.
func newPrefixed(toks []phpscan.Token, idx int) bool {
	return idx > 0 && toks[idx-1].Kind == phpscan.Ident && lower(toks[idx-1].Text) == "new"
}

// namedFunctionDeclAt informa de si el token `function` en idx encabeza una
// DECLARACIÓN con nombre (`function foo(...)`, o con retorno por referencia
// `function &foo(...)`) en vez de una expresión closure (`function(...)` /
// `function &(...)`). Solo las declaraciones con nombre delimitan un ámbito
// nuevo: una closure comparte el ámbito envolvente porque el bucle de Scan
// no mantiene una pila de ámbitos anidados (no-objetivo explícito).
func namedFunctionDeclAt(toks []phpscan.Token, idx int) bool {
	i := idx + 1
	if i < len(toks) && toks[i].Kind == phpscan.Punct && toks[i].Text == "&" {
		i++
	}
	return i < len(toks) && toks[i].Kind == phpscan.Ident
}

// assignmentAt reconoce `$v = RHS` (asignación simple; NO ==, ===, =>, ni
// compuesta como .= porque el `.` se interpone). Devuelve (nombre en minúsculas
// incluida la $, tokens del RHS hasta el ; de nivel superior, ok).
func assignmentAt(toks []phpscan.Token, i int) (string, []phpscan.Token, bool) {
	if toks[i].Kind != phpscan.Variable {
		return "", nil, false
	}
	if i+1 >= len(toks) || toks[i+1].Kind != phpscan.Punct || toks[i+1].Text != "=" {
		return "", nil, false
	}
	if i+2 < len(toks) && toks[i+2].Kind == phpscan.Punct && (toks[i+2].Text == "=" || toks[i+2].Text == ">") {
		return "", nil, false // == / === / =>
	}
	return lower(toks[i].Text), rhsSpan(toks, i+2), true
}

// rhsSpan devuelve los tokens desde start hasta el ; de nivel superior (o el
// final), rastreando ()/[]/{}.
func rhsSpan(toks []phpscan.Token, start int) []phpscan.Token {
	depth := 0
	for i := start; i < len(toks); i++ {
		if toks[i].Kind == phpscan.Punct {
			switch toks[i].Text {
			case "(", "[", "{":
				depth++
			case ")", "]", "}":
				depth--
			case ";":
				if depth <= 0 {
					return toks[start:i]
				}
			}
		}
	}
	return toks[start:]
}

// factOf clasifica el RHS de una asignación. Vacío = benigno/limpio. vars es
// el estado ya fijado por asignaciones anteriores en el mismo recorrido (lo
// necesita concatWithLiteral para reconocer un operando que es, a su vez, una
// variable ya decodificada — decode fragmentado en dos pasos).
func factOf(rhs []phpscan.Token, vars map[string]varFact) varFact {
	f := varFact{}
	if decodeCallIn(rhs) != "" {
		f.decoded = true
		f.dynamicName = true // un valor decodificado usado como nombre de función es dinámico
	}
	if superglobalOutsideEscapeshell(rhs) != "" {
		f.tainted = true
	}
	if concatWithLiteral(rhs, vars) {
		f.dynamicName = true
	}
	return f
}

// concatWithLiteral: hay `.` de concatenación de nivel superior, con al menos
// un operando literal de cadena, Y todo operando NO literal es una variable
// desnuda ya marcada decoded en vars (decode fragmentado: `$part =
// base64_decode(...); $fn = $part.'tem';` — verificado que sigue disparando).
// Sigue disparando también la concatenación toda-literal clásica
// (`'sys'.'tem'`). Si algún operando es una variable/propiedad SIN decodificar
// (p.ej. `$this->component . 'BuildRoute'` del enrutador legado de Joomla, o
// `'get'.$name.'Route'` con `$name` un parámetro plano — ambos verificados
// contra el sitio real) NO cuenta: combinar un valor de tiempo de ejecución
// no decodificado con literales es despacho convencional habitual, no
// ofuscación del nombre.
func concatWithLiteral(rhs []phpscan.Token, vars map[string]varFact) bool {
	operands := splitTopLevelConcat(rhs)
	if len(operands) < 2 {
		return false // sin `.` de nivel superior
	}
	hasLiteral := false
	for _, op := range operands {
		switch {
		case len(op) == 1 && op[0].Kind == phpscan.String:
			hasLiteral = true
		case len(op) == 1 && op[0].Kind == phpscan.Variable && vars[lower(op[0].Text)].decoded:
			// variable decodificada desnuda: operando permitido, no descalifica.
		default:
			return false // operando no-literal y no-decodificado: descalifica todo el concat.
		}
	}
	return hasLiteral
}

// splitTopLevelConcat divide rhs en los operandos separados por `.` de nivel
// superior (profundidad 0, rastreando ()/[]/{} para no partir dentro de una
// llamada o un índice).
func splitTopLevelConcat(rhs []phpscan.Token) [][]phpscan.Token {
	var out [][]phpscan.Token
	depth, start := 0, 0
	for i, t := range rhs {
		if t.Kind == phpscan.Punct {
			switch t.Text {
			case "(", "[", "{":
				depth++
			case ")", "]", "}":
				depth--
			case ".":
				if depth == 0 {
					out = append(out, rhs[start:i])
					start = i + 1
				}
			}
		}
	}
	out = append(out, rhs[start:])
	return out
}

// superglobalOutsideEscapeshell devuelve la primera superglobal en toks que NO
// está dentro de escapeshellarg/escapeshellcmd, o "".
func superglobalOutsideEscapeshell(toks []phpscan.Token) string {
	exempt := escapeshellExemptRegions(toks)
	for i, t := range toks {
		if t.Kind == phpscan.Variable && superglobals[lower(t.Text)] && !inRegions(i, exempt) {
			return lower(t.Text)
		}
	}
	return ""
}

// decodedVarIn devuelve la variable si el primer argumento, tras pelar
// paréntesis redundantes puramente de agrupación (`((...))`), es EXACTAMENTE
// esa variable —uso desnudo, sin comparaciones ni envuelta en otra llamada— y
// tiene el hecho decoded; si no, "". Pelar solo paréntesis de agrupación (no
// los de una llamada: `is_string(` no se pela porque el `(` va precedido de
// un Ident) deja pasar la evasión trivial `eval(($f))` sin dejar pasar
// `assert($v !== false)` ni `assert(is_string($v))` —verificado contra el
// sitio real en brick/math BigInteger::toBytes y lcobucci/jwt
// MultibyteStringConverter—, que son comprobaciones booleanas benignas sobre
// el resultado del decode, no la cadena decodificada cruda en tiempo de
// ejecución. Conserva el caso objetivo `$f = decode(...); eval($f);`.
func decodedVarIn(arg []phpscan.Token, vars map[string]varFact) string {
	core := stripRedundantParens(arg)
	if len(core) != 1 || core[0].Kind != phpscan.Variable {
		return ""
	}
	if vars[lower(core[0].Text)].decoded {
		return lower(core[0].Text)
	}
	return ""
}

// stripRedundantParens pela capas de paréntesis que envuelven TODO arg
// (`(` en arg[0] cuyo cierre es exactamente arg[len(arg)-1]), repitiendo
// mientras haya más capas. No toca los paréntesis de una llamada (`f(...)`),
// porque ahí arg[0] es el Ident, no el `(`.
func stripRedundantParens(arg []phpscan.Token) []phpscan.Token {
	for len(arg) >= 2 && arg[0].Kind == phpscan.Punct && arg[0].Text == "(" {
		end := matchParen(arg, 0)
		if end != len(arg)-1 {
			break
		}
		arg = arg[1 : len(arg)-1]
	}
	return arg
}

// taintedVarIn devuelve la primera variable de arg con hecho tainted que NO está
// saneada en el punto de uso (fuera de escapeshell), o "".
func taintedVarIn(arg []phpscan.Token, vars map[string]varFact) string {
	exempt := escapeshellExemptRegions(arg)
	for i, t := range arg {
		if t.Kind == phpscan.Variable && vars[lower(t.Text)].tainted && !inRegions(i, exempt) {
			return lower(t.Text)
		}
	}
	return ""
}
