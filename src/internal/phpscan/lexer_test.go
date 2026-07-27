package phpscan

import "testing"

func TestTokenizeBasic(t *testing.T) {
	src := []byte("<html><?php system($_GET['c']); Foo->bar(); ns\\baz(); ?><p>x")
	toks := Tokenize(src)
	// Esperado (sin el HTML): system ( $_GET [ c ] ) ; Foo -> bar ( ) ; ns \ baz ( ) ;
	// Desde la Tarea 2 'c' se reconoce como un único token String opaco (Text
	// "c", sin comillas), en vez de los tres tokens sueltos ' (Punct) c (Ident)
	// ' (Punct) que producía el núcleo de la Tarea 1.
	var got []string
	for _, tk := range toks {
		got = append(got, tk.Text)
	}
	want := []string{"system", "(", "$_GET", "[", "c", "]", ")", ";",
		"Foo", "->", "bar", "(", ")", ";", "ns", "\\", "baz", "(", ")", ";"}
	if len(got) != len(want) {
		t.Fatalf("tokens: %v (quiere %v)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("token %d = %q, quiere %q (%v)", i, got[i], want[i], got)
		}
	}
	// Tipos clave.
	if toks[0].Kind != Ident || toks[2].Kind != Variable {
		t.Fatalf("kinds: %v", toks)
	}
	if toks[4].Kind != String || toks[4].Text != "c" {
		t.Fatalf("'c' debe ser un único token String opaco: %+v", toks[4])
	}
}

func TestTokenizeLines(t *testing.T) {
	src := []byte("<?php\n\nsystem($x);\n")
	toks := Tokenize(src)
	if toks[0].Text != "system" || toks[0].Line != 3 {
		t.Fatalf("línea: %+v", toks[0])
	}
}

func TestTokenizeLiterals(t *testing.T) {
	src := []byte("<?php // eval($_GET['x'])\n" +
		"# system($_POST)\n" +
		"/* eval($x) */\n" +
		"$a = 'eval($_GET)'; $b = \"str\"; `$_GET[c]`;\n" +
		"$h = <<<EOT\neval($_POST) no es código\nEOT;\n")
	toks := Tokenize(src)
	for _, tk := range toks {
		if tk.Kind == Ident && (tk.Text == "eval" || tk.Text == "system") {
			t.Fatalf("un nombre de sink dentro de comentario/cadena/heredoc no debe ser Ident: %+v (%v)", tk, toks)
		}
	}
	// La cadena simple es un token String con su contenido interno.
	var sawString, sawBacktick, sawHeredoc bool
	for _, tk := range toks {
		if tk.Kind == String && tk.Text == "eval($_GET)" {
			sawString = true
		}
		if tk.Kind == Backtick && tk.Text == "$_GET[c]" {
			sawBacktick = true
		}
		if tk.Kind == String && tk.Text == "eval($_POST) no es código" {
			sawHeredoc = true
		}
	}
	if !sawString {
		t.Fatalf("cadena simple no tokenizada como String: %v", toks)
	}
	if !sawBacktick {
		t.Fatalf("backtick no tokenizado con su contenido: %v", toks)
	}
	if !sawHeredoc {
		t.Fatalf("heredoc no tokenizado con su contenido exacto (sin salto de línea inicial): %v", toks)
	}
}

func TestTokenizePregEModifierString(t *testing.T) {
	toks := Tokenize([]byte("<?php preg_replace('/.*/e', $r, $s);"))
	// El primer String debe conservar el patrón con el modificador e.
	for _, tk := range toks {
		if tk.Kind == String && tk.Text == "/.*/e" {
			return
		}
	}
	t.Fatalf("patrón /.*/e no preservado: %v", toks)
}
