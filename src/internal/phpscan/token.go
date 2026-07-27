// Package phpscan es un lexer de PHP que produce un flujo de tokens tratando el
// código EXCLUSIVAMENTE como dato (Principio IX: jamás se ejecuta/evalúa). No
// conoce detectores ni hallazgos: solo bytes → tokens.
package phpscan

// Kind es la categoría léxica de un token (solo las que importan al análisis).
type Kind int

const (
	Ident    Kind = iota // palabra desnuda: nombre de función, palabra clave
	Variable             // $nombre, incluidas superglobales ($_GET)
	String               // literal entrecomillado (simple/doble/heredoc/nowdoc); Text = contenido interno
	Backtick             // operador `…` (shell_exec); Text = contenido interno crudo
	Punct                // puntuación/operador: ( ) , ; -> :: \ [ ] etc. Text = el lexema
)

// Token es una unidad léxica con su línea (1-based) para citar archivo:línea.
type Token struct {
	Kind Kind
	Text string
	Line int
}
