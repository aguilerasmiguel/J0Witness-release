package phpscan

// Tokenize convierte src en tokens significativos. El texto fuera de las islas
// <?php … ?> se ignora. Dentro de PHP reconoce tags, espacios, identificadores,
// variables, puntuación (con seguimiento de línea), comentarios (descartados)
// y literales opacos (cadenas simples/dobles, heredoc/nowdoc y backtick), cuyo
// contenido interno nunca se interpreta (Principio IX): solo se cita como dato.
func Tokenize(src []byte) []Token {
	var toks []Token
	line := 1
	i, n := 0, len(src)
	inPHP := false

	isIdentStart := func(c byte) bool {
		return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
	}
	isIdent := func(c byte) bool {
		return isIdentStart(c) || (c >= '0' && c <= '9')
	}

	for i < n {
		c := src[i]
		if !inPHP {
			if c == '<' && i+1 < n && src[i+1] == '?' {
				// Entra a PHP. Salta <?php | <?= | <?
				j := i + 2
				if j+2 < n && src[j] == 'p' && src[j+1] == 'h' && src[j+2] == 'p' {
					j += 3
				} else if j < n && src[j] == '=' {
					j++
				}
				for k := i; k < j; k++ {
					if src[k] == '\n' {
						line++
					}
				}
				i, inPHP = j, true
				continue
			}
			if c == '\n' {
				line++
			}
			i++
			continue
		}
		// Dentro de PHP.
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '?' && i+1 < n && src[i+1] == '>':
			inPHP = false
			i += 2
		case c == '$' && i+1 < n && isIdentStart(src[i+1]):
			j := i + 1
			for j < n && isIdent(src[j]) {
				j++
			}
			toks = append(toks, Token{Variable, string(src[i:j]), line})
			i = j
		case isIdentStart(c):
			j := i
			for j < n && isIdent(src[j]) {
				j++
			}
			toks = append(toks, Token{Ident, string(src[i:j]), line})
			i = j
		case c >= '0' && c <= '9':
			// Los números no afectan a la detección (no anidan paréntesis): se saltan.
			j := i
			for j < n && (isIdent(src[j]) || src[j] == '.') {
				j++
			}
			i = j
		case c == '-' && i+1 < n && src[i+1] == '>':
			toks = append(toks, Token{Punct, "->", line})
			i += 2
		case c == ':' && i+1 < n && src[i+1] == ':':
			toks = append(toks, Token{Punct, "::", line})
			i += 2
		case c == '/' && i+1 < n && src[i+1] == '/':
			i += 2
			for i < n && src[i] != '\n' {
				i++
			}
		case c == '#':
			i++
			for i < n && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && src[i+1] == '*':
			i += 2
			for i < n && !(src[i] == '*' && i+1 < n && src[i+1] == '/') {
				if src[i] == '\n' {
					line++
				}
				i++
			}
			i += 2 // salta el */ (si falta, i ya == n)
			if i > n {
				i = n
			}
		case c == '\'':
			s, j, ln := scanQuoted(src, i, '\'', line)
			toks = append(toks, Token{String, s, line})
			i, line = j, ln
		case c == '"':
			s, j, ln := scanQuoted(src, i, '"', line)
			toks = append(toks, Token{String, s, line})
			i, line = j, ln
		case c == '`':
			s, j, ln := scanQuoted(src, i, '`', line)
			toks = append(toks, Token{Backtick, s, line})
			i, line = j, ln
		case c == '<' && i+2 < n && src[i+1] == '<' && src[i+2] == '<':
			s, j, ln := scanHeredoc(src, i, line)
			toks = append(toks, Token{String, s, line})
			i, line = j, ln
		default:
			// Cualquier otro carácter (incl. ( ) , ; \ [ ] operadores) como Punct de 1 byte.
			toks = append(toks, Token{Punct, string(src[i : i+1]), line})
			i++
		}
	}
	return toks
}

// scanQuoted consume un literal delimitado por quote desde start (que apunta al
// delimitador de apertura) y devuelve (contenido interno, índice tras el cierre,
// línea actualizada). Respeta el escape con backslash. Para el propósito del
// análisis el contenido es opaco (no se interpreta interpolación).
func scanQuoted(src []byte, start int, quote byte, line int) (string, int, int) {
	n := len(src)
	i := start + 1
	var b []byte
	for i < n {
		c := src[i]
		if c == '\\' && i+1 < n {
			b = append(b, src[i+1]) // conserva el carácter escapado como dato
			if src[i+1] == '\n' {
				line++
			}
			i += 2
			continue
		}
		if c == quote {
			i++
			break
		}
		if c == '\n' {
			line++
		}
		b = append(b, c)
		i++
	}
	return string(b), i, line
}

// scanHeredoc consume un heredoc/nowdoc <<<[']LABEL['] … LABEL. Devuelve el
// contenido interno como opaco. Reconoce el cierre por una línea cuyo contenido
// (permitiendo sangría, PHP 7.3+) empieza por LABEL seguido de un carácter no
// identificador.
func scanHeredoc(src []byte, start, line int) (string, int, int) {
	n := len(src)
	i := start + 3
	for i < n && (src[i] == ' ' || src[i] == '\t') {
		i++
	}
	q := byte(0)
	if i < n && (src[i] == '\'' || src[i] == '"') {
		q = src[i]
		i++
	}
	ls := i
	for i < n && (src[i] == '_' || (src[i] >= 'a' && src[i] <= 'z') || (src[i] >= 'A' && src[i] <= 'Z') || (src[i] >= '0' && src[i] <= '9') || src[i] >= 0x80) {
		i++
	}
	label := string(src[ls:i])
	if q != 0 && i < n && src[i] == q {
		i++
	}
	// Salta hasta el fin de la línea de apertura y consume su salto de línea:
	// el contenido del heredoc empieza en la línea SIGUIENTE a <<<LABEL, así
	// que ese salto de línea de apertura no forma parte del contenido.
	for i < n && src[i] != '\n' {
		i++
	}
	if i < n && src[i] == '\n' {
		i++
		line++
	}
	contentStart := i
	lineStart := i
	isIdentByte := func(c byte) bool {
		return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
	}
	// Busca la línea de cierre, comprobando cada línea (incluida la primera,
	// para el caso de contenido vacío) desde su inicio, permitiendo sangría.
	for {
		k := lineStart
		for k < n && (src[k] == ' ' || src[k] == '\t') {
			k++
		}
		if k+len(label) <= n && string(src[k:k+len(label)]) == label {
			after := k + len(label)
			if after >= n || !isIdentByte(src[after]) {
				end := lineStart
				if end > contentStart {
					end-- // excluye el \n que separa el contenido de la línea de cierre
				}
				return string(src[contentStart:end]), after, line
			}
		}
		for i < n && src[i] != '\n' {
			i++
		}
		if i >= n {
			break
		}
		line++
		i++
		lineStart = i
	}
	return string(src[contentStart:i]), i, line
}
