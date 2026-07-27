package dbscan

import (
	"bufio"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Dump es el resultado de parsear un volcado mysqldump: las filas tipadas de
// las tablas objetivo (con el prefijo real de Joomla resuelto) más las
// banderas de degradación. Ante ambigüedad o formato no reconocido se
// degrada (Ambiguous/Unsupported) en vez de adivinar (Principio VI).
type Dump struct {
	Prefix      string // prefijo real detectado (p.ej. "abc12_"); "" si no se pudo
	Users       []UserRow
	Groups      []GroupRow
	Memberships []MembershipRow
	Extensions  []ExtRow
	Modules     []ModuleRow
	Ambiguous   bool // >1 prefijo candidato → degradar, no adivinar
	Unsupported bool // dialecto/formato no reconocido → degradar
}

// UserRow refleja `#__users` (solo las columnas que necesita la correlación).
type UserRow struct {
	ID          int64
	Username    string
	Email       string
	Activation  string
	Block       int
	RegisterNS  int64
	LastVisitNS int64
}

// GroupRow refleja `#__usergroups`.
type GroupRow struct {
	ID    int64
	Title string
}

// MembershipRow refleja `#__user_usergroup_map` (clave compuesta).
type MembershipRow struct {
	UserID  int64
	GroupID int64
}

// ExtRow refleja `#__extensions`.
//
// Folder y ClientID (Finding C1, review final) se capturan además de Element
// porque el `element` de BD es desnudo (p.ej. "joomla", "mod_menu") mientras
// que la clave de disco (extmap.Extension.ElementKey, vía
// manifest.ExtensionKey) lleva forma: "system/joomla" (plugin, con folder),
// "mod_menu@administrator" (módulo/plantilla de admin, con client_id). Sin
// estas dos columnas, el join Clase 2 comparaba claves incompatibles y
// producía huérfanas falsas (dbscan.go construye la clave con forma; ver
// dbExtensionKey).
type ExtRow struct {
	ExtensionID int64
	Element     string
	Type        string
	Folder      string // solo plugins: el grupo (system, content, ...)
	ClientID    int    // 0 = site, 1 = administrator (módulos/plantillas)
	Enabled     int
	Protected   int
	State       int
}

// ModuleRow refleja `#__modules`.
type ModuleRow struct {
	ID        int64
	Title     string
	Module    string
	Content   string
	Published int
}

// knownSuffixes son los sufijos de tabla que reconocemos (sin el prefijo de
// Joomla). Cualquier otra tabla del dump se ignora.
var knownSuffixes = []string{"users", "usergroups", "user_usergroup_map", "extensions", "modules"}

// parseState acumula, durante el único paso de streaming de Parse, el
// conocimiento necesario para resolver los defectos del mundo real:
//   - cols: orden de columnas aprendido de cada `CREATE TABLE` (clave: nombre
//     de tabla EXACTO, tal cual aparece en el dump) — usado por
//     processStatement cuando el INSERT correspondiente llega en su forma
//     desnuda, sin lista de columnas (Defecto D1).
//   - seen: conjunto de nombres de tabla EXACTOS (crudos) que terminan en un
//     sufijo conocido, vistos vía CREATE TABLE o INSERT. Es la base para
//     resolver el prefijo real al final de Parse (ver resolvePrefix).
//   - userBuf/groupBuf/membBuf/extBuf/modBuf: TODAS las filas de tablas con
//     sufijo objetivo se BUFERIZAN por nombre de tabla CRUDO durante el
//     streaming; nada se vuelca a d.Users/... hasta EOF. mysqldump intercala
//     DROP/CREATE/INSERT por tabla, así que no se conocen todos los nombres
//     antes del primer INSERT: por eso la resolución del prefijo (por MÁXIMO
//     de tablas objetivo exactas) tiene que ocurrir al final. En ese momento
//     solo se confirman las filas de las cinco tablas objetivo EXACTAS del
//     prefijo ganador `P*` (`P*users`, ...); el resto de tablas con sufijo
//     objetivo pero que NO son la tabla objetivo (`<p>_action_logs_users`,
//     `<p>_j2xml_usergroups`, `<p>_update_sites_extensions`, ...) se descartan
//     sin marcar Ambiguous (Defecto D3, y su generalización con la colisión
//     de `_users`/`_usergroups` del segundo dump real).
//   - schemalessTargetHit (Fix P2): true si algún INSERT desnudo (sin lista de
//     columnas explícita) casó con una tabla OBJETIVO pero no se conocía su
//     orden de columnas (nunca se vio su CREATE TABLE) — un dump solo-datos.
//     Si al final no se parseó NINGUNA fila objetivo y esto ocurrió, Parse
//     restaura Unsupported=true (la pérdida total deja de ser silenciosa).
type parseState struct {
	cols                map[string][]string
	seen                map[string]bool
	userBuf             map[string][]UserRow
	groupBuf            map[string][]GroupRow
	membBuf             map[string][]MembershipRow
	extBuf              map[string][]ExtRow
	modBuf              map[string][]ModuleRow
	schemalessTargetHit bool
}

func newParseState() *parseState {
	return &parseState{
		cols:     map[string][]string{},
		seen:     map[string]bool{},
		userBuf:  map[string][]UserRow{},
		groupBuf: map[string][]GroupRow{},
		membBuf:  map[string][]MembershipRow{},
		extBuf:   map[string][]ExtRow{},
		modBuf:   map[string][]ModuleRow{},
	}
}

// Parse lee un volcado mysqldump como texto (NUNCA lo ejecuta, Principio IX)
// y extrae las filas de las tablas objetivo. Determinista: cada slice
// devuelto se ordena por clave primaria ascendente.
func Parse(r io.Reader) (Dump, error) {
	var d Dump
	recognized := false
	ps := newParseState()

	br := bufio.NewReaderSize(r, 64*1024)
	var stmt strings.Builder
	active := false
	inQuote := false
	kind := "" // "insert" | "create"

	flush := func() {
		if stmt.Len() == 0 {
			return
		}
		switch kind {
		case "insert":
			if processStatement(stmt.String(), &d, ps) {
				recognized = true
			}
		case "create":
			processCreateTable(stmt.String(), ps)
		}
		stmt.Reset()
		active = false
		inQuote = false
		kind = ""
	}

	for {
		line, err := br.ReadString('\n')
		raw := strings.TrimRight(line, "\r\n")

		if !active {
			t := strings.TrimSpace(raw)
			tu := strings.ToUpper(t)
			switch {
			case strings.HasPrefix(tu, "INSERT INTO"):
				active = true
				kind = "insert"
				stmt.Reset()
				inQuote = false
				stmt.WriteString(raw)
				updateQuoteState(raw, &inQuote)
			case strings.HasPrefix(tu, "CREATE TABLE"):
				active = true
				kind = "create"
				stmt.Reset()
				inQuote = false
				stmt.WriteString(raw)
				updateQuoteState(raw, &inQuote)
			}
		} else {
			stmt.WriteByte('\n')
			stmt.WriteString(raw)
			updateQuoteState(raw, &inQuote)
		}

		if active && !inQuote {
			trimmed := strings.TrimRight(stmt.String(), " \t\r\n")
			if strings.HasSuffix(trimmed, ";") {
				flush()
			}
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			return Dump{}, err
		}
	}
	// Un statement acumulado sin ';' final al llegar a EOF está incompleto:
	// se descarta (robustez sobre agudeza, no aborta el resto del volcado).

	if !recognized {
		d.Unsupported = true
	}

	// Resuelve el prefijo real por MÁXIMO número de tablas objetivo EXACTAS y
	// vuelca las filas del ganador. Para cada prefijo candidato `P` (nombre de
	// tabla con sufijo objetivo menos el sufijo) se cuenta cuántas de las CINCO
	// tablas objetivo exactas `P+s` existen en el conjunto `seen`; gana el
	// candidato con el conteo estrictamente mayor. Un empate en el conteo
	// máximo es ambigüedad genuina (dos installs mezclados) → Ambiguous, sin
	// adivinar. Las tablas que solo "terminan en" un sufijo objetivo sin ser
	// la tabla objetivo del prefijo ganador (`<p>_action_logs_users`,
	// `<p>_j2xml_usergroups`, `<p>_update_sites_extensions`, ...) quedan
	// bufferizadas pero nunca se confirman: se descartan al no formar parte de
	// las cinco tablas exactas del prefijo ganador (Defecto D3 y su
	// generalización a `_users`/`_usergroups` del segundo dump real).
	resolvedPrefix, ambiguous := resolvePrefix(ps.seen)
	if ambiguous {
		d.Ambiguous = true
	}
	if resolvedPrefix != "" {
		d.Prefix = resolvedPrefix
		d.Users = ps.userBuf[resolvedPrefix+"users"]
		d.Groups = ps.groupBuf[resolvedPrefix+"usergroups"]
		d.Memberships = ps.membBuf[resolvedPrefix+"user_usergroup_map"]
		d.Extensions = ps.extBuf[resolvedPrefix+"extensions"]
		d.Modules = ps.modBuf[resolvedPrefix+"modules"]
	}

	// Fix P2: dump solo-datos. Si algún INSERT desnudo casó con una tabla
	// objetivo pero sin CREATE TABLE (schemalessTargetHit) y NO se parseó
	// ninguna fila objetivo en todo el dump, la pérdida es total: se restaura
	// Unsupported=true (señal ruidosa) en vez de devolver cero filas en
	// silencio. No regresa el camino normal: un dump CON CREATE TABLE parsea
	// filas y este bloque no se dispara.
	if ps.schemalessTargetHit &&
		len(d.Users)+len(d.Groups)+len(d.Memberships)+len(d.Extensions)+len(d.Modules) == 0 {
		d.Unsupported = true
	}

	sort.Slice(d.Users, func(i, j int) bool { return d.Users[i].ID < d.Users[j].ID })
	sort.Slice(d.Groups, func(i, j int) bool { return d.Groups[i].ID < d.Groups[j].ID })
	sort.Slice(d.Memberships, func(i, j int) bool {
		if d.Memberships[i].UserID != d.Memberships[j].UserID {
			return d.Memberships[i].UserID < d.Memberships[j].UserID
		}
		return d.Memberships[i].GroupID < d.Memberships[j].GroupID
	})
	sort.Slice(d.Extensions, func(i, j int) bool { return d.Extensions[i].ExtensionID < d.Extensions[j].ExtensionID })
	sort.Slice(d.Modules, func(i, j int) bool { return d.Modules[i].ID < d.Modules[j].ID })

	return d, nil
}

// updateQuoteState actualiza inQuote recorriendo line, respetando el escape
// por backslash y las comillas simples dobladas (”). Persiste entre líneas
// para soportar (en teoría) cadenas que abarquen varias líneas físicas.
func updateQuoteState(line string, inQuote *bool) {
	i := 0
	for i < len(line) {
		c := line[i]
		if *inQuote {
			switch {
			case c == '\\' && i+1 < len(line):
				i += 2
				continue
			case c == '\'' && i+1 < len(line) && line[i+1] == '\'':
				i += 2
				continue
			case c == '\'':
				*inQuote = false
				i++
				continue
			default:
				i++
				continue
			}
		}
		if c == '\'' {
			*inQuote = true
		}
		i++
	}
}

// colIndex mapea nombre de columna (tal cual aparece en el INSERT) a su
// posición dentro de la tupla de valores.
type colIndex map[string]int

func buildColIndex(cols []string) colIndex {
	m := make(colIndex, len(cols))
	for i, c := range cols {
		name := strings.Trim(strings.TrimSpace(c), "`")
		m[name] = i
	}
	return m
}

func getStr(vals []string, idx colIndex, name string) (string, bool) {
	i, ok := idx[name]
	if !ok || i < 0 || i >= len(vals) {
		return "", false
	}
	return unquote(vals[i]), true
}

func getInt(vals []string, idx colIndex, name string) (int, bool) {
	s, ok := getStr(vals, idx, name)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// processStatement parsea un statement `INSERT INTO ... VALUES ...;` ya
// acumulado. Devuelve true si la estructura (tabla + VALUES, con o sin lista
// de columnas explícita) fue reconocible, independientemente de si la tabla
// es una de las objetivo o de si alguna fila individual estaba corrupta
// (esas se saltan sin abortar).
//
// Defecto D1: mysqldump por DEFECTO (sin --complete-insert) emite
// `INSERT INTO `t` VALUES (...);` SIN lista de columnas — antes de este fix
// esa forma desnuda hacía que la función devolviera false para TODO INSERT
// de un volcado real, dejando Unsupported=true y cero filas. Ahora, si tras
// el nombre de tabla lo que sigue es VALUES (no un `(` de columnas), se usa
// el orden de columnas aprendido de su `CREATE TABLE` (ps.cols, poblado por
// processCreateTable); si no se conoce (no se vio su CREATE TABLE), se
// degrada saltando el statement en vez de adivinar el mapeo.
func processStatement(stmt string, d *Dump, ps *parseState) bool {
	trimmed := strings.TrimSpace(stmt)
	upper := strings.ToUpper(trimmed)
	if !strings.HasPrefix(upper, "INSERT INTO") {
		return false
	}
	rest := strings.TrimSpace(trimmed[len("INSERT INTO"):])

	table, rest, ok := readIdent(rest)
	if !ok {
		return false
	}
	rest = strings.TrimSpace(rest)

	var cols []string
	if len(rest) > 0 && rest[0] == '(' {
		// Forma explícita (p.ej. --complete-insert, o los dumps sintéticos
		// existentes): lista de columnas entre paréntesis inmediatamente
		// tras el nombre de tabla.
		depth := 0
		colsEnd := -1
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					colsEnd = i
				}
			}
			if colsEnd != -1 {
				break
			}
		}
		if colsEnd == -1 {
			return false
		}
		cols = strings.Split(rest[1:colsEnd], ",")
		rest = strings.TrimSpace(rest[colsEnd+1:])
	}

	if !strings.HasPrefix(strings.ToUpper(rest), "VALUES") {
		return false
	}
	valuesText := strings.TrimSpace(rest[len("VALUES"):])
	if !strings.HasSuffix(valuesText, ";") {
		return false
	}
	valuesText = strings.TrimSuffix(valuesText, ";")

	// Fix P2: detectSuffix se evalúa INDEPENDIENTE del conocimiento de
	// columnas — así, un INSERT desnudo sobre una tabla objetivo sin CREATE
	// TABLE (dump solo-datos) se puede registrar como pérdida antes de
	// degradar, en vez de perderse en silencio.
	suffix, _, matched := detectSuffix(table)
	if matched {
		// El nombre existe y termina en un sufijo objetivo: cuenta para la
		// resolución del prefijo al final de Parse, con o sin filas parseables.
		ps.seen[table] = true
	}

	if cols == nil {
		// Forma desnuda (por defecto en mysqldump): sin lista de columnas,
		// solo se puede mapear si su CREATE TABLE ya se vio en este mismo
		// paso de streaming.
		learned, known := ps.cols[table]
		if !known {
			if matched {
				// Tabla objetivo sin orden de columnas conocido: se registra
				// para que Parse restaure Unsupported si no se parsea ninguna
				// fila objetivo en todo el dump (Fix P2).
				ps.schemalessTargetHit = true
			}
			return true // estructura reconocida; sin CREATE TABLE, se degrada
		}
		cols = learned
	}

	if !matched {
		return true // estructura reconocida; tabla fuera del alcance
	}

	idx := buildColIndex(cols)

	// Todas las filas de tablas con sufijo objetivo se BUFERIZAN por nombre de
	// tabla CRUDO (table); nada se vuelca a d.* hasta EOF. Solo las cinco
	// tablas objetivo EXACTAS del prefijo ganador se confirman entonces; el
	// resto (colisiones action_logs_/j2xml_/update_sites_/...) se descarta.
	for _, tup := range extractTuples(valuesText) {
		vals := splitValues(tup)
		switch suffix {
		case "users":
			if row, ok := buildUserRow(vals, idx); ok {
				ps.userBuf[table] = append(ps.userBuf[table], row)
			}
		case "usergroups":
			if row, ok := buildGroupRow(vals, idx); ok {
				ps.groupBuf[table] = append(ps.groupBuf[table], row)
			}
		case "user_usergroup_map":
			if row, ok := buildMembershipRow(vals, idx); ok {
				ps.membBuf[table] = append(ps.membBuf[table], row)
			}
		case "extensions":
			if row, ok := buildExtRow(vals, idx); ok {
				ps.extBuf[table] = append(ps.extBuf[table], row)
			}
		case "modules":
			if row, ok := buildModuleRow(vals, idx); ok {
				ps.modBuf[table] = append(ps.modBuf[table], row)
			}
		}
	}
	return true
}

// processCreateTable parsea un statement `CREATE TABLE `t` ( ... );` ya
// acumulado y, si tiene forma reconocible, registra en ps.cols el orden de
// columnas de t (clave: nombre de tabla EXACTO). No filtra por tabla
// objetivo: registrar de más (tablas fuera de alcance) es barato y evita
// acoplar esta función al conjunto de sufijos conocidos.
//
// Reglas de extracción (dentro del bloque exterior entre paréntesis, Fix P1):
// el cuerpo se parte por COMAS DE NIVEL SUPERIOR con el mismo escáner
// consciente de profundidad/comillas que splitValues/extractTuples (NO por
// "\n", que rompía un CREATE TABLE minificado de una sola línea capturando
// solo la primera columna). De cada definición se toma el primer identificador
// entre backticks como nombre de columna; las definiciones cuyo primer token
// NO empieza por backtick (PRIMARY KEY, KEY, UNIQUE KEY, CONSTRAINT, FULLTEXT,
// INDEX, ...) no son columnas y se saltan. Se preserva el ORDEN.
func processCreateTable(stmt string, ps *parseState) bool {
	trimmed := strings.TrimSpace(stmt)
	upper := strings.ToUpper(trimmed)
	if !strings.HasPrefix(upper, "CREATE TABLE") {
		return false
	}
	rest := strings.TrimSpace(trimmed[len("CREATE TABLE"):])
	if strings.HasPrefix(strings.ToUpper(rest), "IF NOT EXISTS") {
		rest = strings.TrimSpace(rest[len("IF NOT EXISTS"):])
	}

	table, rest, ok := readIdent(rest)
	if !ok {
		return false
	}
	if _, _, matched := detectSuffix(table); matched {
		// Una tabla objetivo puede existir sin filas (CREATE sin INSERT):
		// igual cuenta para la resolución del prefijo al final de Parse.
		ps.seen[table] = true
	}
	rest = strings.TrimSpace(rest)
	if len(rest) == 0 || rest[0] != '(' {
		return false
	}

	// Localiza el bloque exterior entre paréntesis (la lista de definiciones
	// de columna/clave), respetando paréntesis anidados (tipos como
	// varchar(100)) y comillas simples (COMMENT '...', DEFAULT '...') para
	// que un ')' o '(' literal dentro de una cadena no confunda el cierre.
	depth := 0
	inQuote := false
	bodyStart := -1
	bodyEnd := -1
	i := 0
	for i < len(rest) {
		c := rest[i]
		if inQuote {
			switch {
			case c == '\\' && i+1 < len(rest):
				i += 2
				continue
			case c == '\'' && i+1 < len(rest) && rest[i+1] == '\'':
				i += 2
				continue
			case c == '\'':
				inQuote = false
				i++
				continue
			default:
				i++
				continue
			}
		}
		switch c {
		case '\'':
			inQuote = true
		case '(':
			depth++
			if depth == 1 {
				bodyStart = i + 1
			}
		case ')':
			depth--
			if depth == 0 {
				bodyEnd = i
			}
		}
		i++
		if bodyEnd != -1 {
			break
		}
	}
	if bodyStart == -1 || bodyEnd == -1 || bodyEnd < bodyStart {
		return false
	}
	body := rest[bodyStart:bodyEnd]

	var cols []string
	for _, def := range splitColumnDefs(body) {
		l := strings.TrimSpace(def)
		// Solo las definiciones de columna empiezan por backtick; PRIMARY KEY,
		// KEY, UNIQUE KEY, CONSTRAINT, FULLTEXT, INDEX, ... no.
		if l == "" || l[0] != '`' {
			continue
		}
		end := strings.IndexByte(l[1:], '`')
		if end == -1 {
			continue
		}
		cols = append(cols, l[1:1+end])
	}
	if len(cols) > 0 {
		ps.cols[table] = cols
	}
	return true
}

// splitColumnDefs parte el cuerpo de un CREATE TABLE (lo que hay entre el
// paréntesis exterior) en sus definiciones de columna/clave por comas de
// NIVEL SUPERIOR, respetando paréntesis anidados (p.ej. varchar(100),
// decimal(10,2), enum('a','b')) y comillas simples (DEFAULT '...',
// COMMENT '...') — Fix P1: sustituye al split ingenuo por "\n" que perdía
// todas las columnas menos la primera en un CREATE TABLE de una sola línea.
func splitColumnDefs(body string) []string {
	var out []string
	var cur strings.Builder
	depth := 0
	inQuote := false
	i := 0
	for i < len(body) {
		c := body[i]
		if inQuote {
			switch {
			case c == '\\' && i+1 < len(body):
				cur.WriteByte(c)
				cur.WriteByte(body[i+1])
				i += 2
				continue
			case c == '\'' && i+1 < len(body) && body[i+1] == '\'':
				cur.WriteByte(c)
				cur.WriteByte(body[i+1])
				i += 2
				continue
			case c == '\'':
				cur.WriteByte(c)
				inQuote = false
				i++
				continue
			default:
				cur.WriteByte(c)
				i++
				continue
			}
		}
		switch c {
		case '\'':
			inQuote = true
			cur.WriteByte(c)
		case '(':
			depth++
			cur.WriteByte(c)
		case ')':
			if depth > 0 {
				depth--
			}
			cur.WriteByte(c)
		case ',':
			if depth == 0 {
				out = append(out, cur.String())
				cur.Reset()
			} else {
				cur.WriteByte(c)
			}
		default:
			cur.WriteByte(c)
		}
		i++
	}
	out = append(out, cur.String())
	return out
}

// detectSuffix comprueba si table termina en "_<sufijo conocido>" y, de ser
// así, devuelve el sufijo y el prefijo candidato (con el guion bajo incluido,
// p.ej. "abc12_").
func detectSuffix(table string) (suffix, prefix string, matched bool) {
	for _, sfx := range knownSuffixes {
		needle := "_" + sfx
		if strings.HasSuffix(table, needle) {
			return sfx, table[:len(table)-len(sfx)], true
		}
	}
	return "", "", false
}

// resolvePrefix elige el prefijo real de Joomla por MÁXIMO número de tablas
// objetivo EXACTAS presentes en `seen` (nombres de tabla crudos que terminan
// en un sufijo conocido). Para cada prefijo candidato `P` (un nombre de tabla
// menos su sufijo, con el guion bajo incluido) cuenta cuántas de las cinco
// tablas objetivo exactas `P+s` (s ∈ knownSuffixes) existen; devuelve el
// candidato con el conteo estrictamente mayor. Si el conteo máximo lo empatan
// dos o más candidatos, es ambigüedad genuina (dos installs mezclados) y se
// devuelve prefix="" con ambiguous=true. Si ningún candidato casa con tabla
// objetivo alguna (seen sin sufijos objetivo), devuelve prefix="" sin
// ambigüedad (el camino Unsupported se aplica aguas arriba).
func resolvePrefix(seen map[string]bool) (prefix string, ambiguous bool) {
	candidates := map[string]bool{}
	for name := range seen {
		for _, s := range knownSuffixes {
			if strings.HasSuffix(name, "_"+s) {
				candidates[name[:len(name)-len(s)]] = true
				break
			}
		}
	}
	best := ""
	bestCount := 0
	tie := false
	for p := range candidates {
		c := 0
		for _, s := range knownSuffixes {
			if seen[p+s] {
				c++
			}
		}
		switch {
		case c > bestCount:
			best, bestCount, tie = p, c, false
		case c == bestCount:
			tie = true
		}
	}
	if bestCount == 0 {
		return "", false
	}
	if tie {
		// El conteo máximo aparece en ≥2 candidatos: no adivinar cuál install
		// es el real. (best/orden de iteración es irrelevante: se descarta.)
		return "", true
	}
	return best, false
}

// readIdent lee el nombre de tabla tras INSERT INTO, con o sin comillas
// backtick, y devuelve el resto de la cadena sin consumir.
func readIdent(s string) (ident string, rest string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", s, false
	}
	if s[0] == '`' {
		end := strings.IndexByte(s[1:], '`')
		if end == -1 {
			return "", s, false
		}
		end++ // índice relativo a s
		return s[1:end], s[end+1:], true
	}
	i := 0
	for i < len(s) {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '(' {
			break
		}
		i++
	}
	if i == 0 {
		return "", s, false
	}
	return s[:i], s[i:], true
}

// extractTuples separa la lista "(v1,v2),(v3,v4)" en sus tuplas de nivel
// superior (sin los paréntesis externos), respetando comillas/escapes para
// no confundir un paréntesis literal dentro de una cadena con el cierre de
// la tupla.
func extractTuples(s string) []string {
	var out []string
	var cur strings.Builder
	depth := 0
	inQuote := false
	i := 0
	for i < len(s) {
		c := s[i]
		if inQuote {
			switch {
			case c == '\\' && i+1 < len(s):
				cur.WriteByte(c)
				cur.WriteByte(s[i+1])
				i += 2
				continue
			case c == '\'' && i+1 < len(s) && s[i+1] == '\'':
				cur.WriteByte(c)
				cur.WriteByte(s[i+1])
				i += 2
				continue
			case c == '\'':
				cur.WriteByte(c)
				inQuote = false
				i++
				continue
			default:
				cur.WriteByte(c)
				i++
				continue
			}
		}
		switch c {
		case '\'':
			if depth > 0 {
				inQuote = true
				cur.WriteByte(c)
			}
		case '(':
			depth++
			if depth > 1 {
				cur.WriteByte(c)
			}
		case ')':
			depth--
			switch {
			case depth == 0:
				out = append(out, cur.String())
				cur.Reset()
			case depth > 0:
				cur.WriteByte(c)
			default:
				depth = 0 // desbalanceado: ignora
			}
		default:
			if depth > 0 {
				cur.WriteByte(c)
			}
		}
		i++
	}
	return out
}

// splitValues separa el contenido de una tupla en sus valores individuales
// por comas de nivel superior, respetando comillas simples con escapes '\”
// ” y '\\'. Cada valor devuelto conserva su forma cruda (comillas y escapes
// incluidos); unquote() se encarga de desescaparlo después.
func splitValues(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	i := 0
	for i < len(s) {
		c := s[i]
		if inQuote {
			switch {
			case c == '\\' && i+1 < len(s):
				cur.WriteByte(c)
				cur.WriteByte(s[i+1])
				i += 2
				continue
			case c == '\'' && i+1 < len(s) && s[i+1] == '\'':
				cur.WriteByte(c)
				cur.WriteByte(s[i+1])
				i += 2
				continue
			case c == '\'':
				cur.WriteByte(c)
				inQuote = false
				i++
				continue
			default:
				cur.WriteByte(c)
				i++
				continue
			}
		}
		switch c {
		case '\'':
			inQuote = true
			cur.WriteByte(c)
		case ',':
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
		i++
	}
	out = append(out, strings.TrimSpace(cur.String()))
	return out
}

// unquote quita las comillas simples externas de un valor (si las tiene) y
// desescapa su contenido; los literales sin comillas (números, NULL) se
// devuelven tal cual.
func unquote(tok string) string {
	tok = strings.TrimSpace(tok)
	if len(tok) >= 2 && tok[0] == '\'' && tok[len(tok)-1] == '\'' {
		return unescape(tok[1 : len(tok)-1])
	}
	return tok
}

// mysqlEscapes es la tabla real de escapes de mysqldump para cadenas: los
// caracteres de control que \n, \r, \t, \0, \Z, \b representan como byte de
// control (no como la letra literal). Cualquier \X fuera de esta tabla
// conserva X tal cual (comportamiento previo, sigue siendo correcto para \\,
// \' y \").
var mysqlEscapes = map[byte]byte{
	'n': '\n',
	'r': '\r',
	't': '\t',
	'0': 0x00,
	'Z': 0x1A,
	'b': '\b',
}

// unescape resuelve los escapes de mysqldump (\n, \r, \t, \0, \Z, \b como
// carácter de control real; \\, \', \" como el carácter literal; cualquier
// otro \X conserva X) y ” → ' dentro del contenido de una cadena ya
// desenvuelta de sus comillas externas.
func unescape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i++
			next := s[i]
			if mapped, ok := mysqlEscapes[next]; ok {
				b.WriteByte(mapped)
			} else {
				b.WriteByte(next)
			}
			continue
		}
		if c == '\'' && i+1 < len(s) && s[i+1] == '\'' {
			b.WriteByte('\'')
			i++
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func buildUserRow(vals []string, idx colIndex) (UserRow, bool) {
	idStr, ok := getStr(vals, idx, "id")
	if !ok {
		return UserRow{}, false
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return UserRow{}, false
	}
	row := UserRow{ID: id}
	if v, ok := getStr(vals, idx, "username"); ok {
		row.Username = v
	}
	if v, ok := getStr(vals, idx, "email"); ok {
		row.Email = v
	}
	if v, ok := getStr(vals, idx, "activation"); ok {
		row.Activation = v
	}
	if v, ok := getInt(vals, idx, "block"); ok {
		row.Block = v
	}
	if v, ok := getStr(vals, idx, "registerDate"); ok {
		row.RegisterNS = parseMySQLDatetime(v)
	}
	if v, ok := getStr(vals, idx, "lastvisitDate"); ok {
		row.LastVisitNS = parseMySQLDatetime(v)
	}
	return row, true
}

func buildGroupRow(vals []string, idx colIndex) (GroupRow, bool) {
	idStr, ok := getStr(vals, idx, "id")
	if !ok {
		return GroupRow{}, false
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return GroupRow{}, false
	}
	row := GroupRow{ID: id}
	if v, ok := getStr(vals, idx, "title"); ok {
		row.Title = v
	}
	return row, true
}

func buildMembershipRow(vals []string, idx colIndex) (MembershipRow, bool) {
	userIDStr, ok := getStr(vals, idx, "user_id")
	if !ok {
		return MembershipRow{}, false
	}
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		return MembershipRow{}, false
	}
	row := MembershipRow{UserID: userID}
	if v, ok := getStr(vals, idx, "group_id"); ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			row.GroupID = n
		}
	}
	return row, true
}

func buildExtRow(vals []string, idx colIndex) (ExtRow, bool) {
	idStr, ok := getStr(vals, idx, "extension_id")
	if !ok {
		return ExtRow{}, false
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return ExtRow{}, false
	}
	row := ExtRow{ExtensionID: id}
	if v, ok := getStr(vals, idx, "element"); ok {
		row.Element = v
	}
	if v, ok := getStr(vals, idx, "type"); ok {
		row.Type = v
	}
	if v, ok := getStr(vals, idx, "folder"); ok && !strings.EqualFold(v, "NULL") {
		row.Folder = v
	}
	if v, ok := getInt(vals, idx, "client_id"); ok {
		row.ClientID = v
	}
	if v, ok := getInt(vals, idx, "enabled"); ok {
		row.Enabled = v
	}
	if v, ok := getInt(vals, idx, "protected"); ok {
		row.Protected = v
	}
	if v, ok := getInt(vals, idx, "state"); ok {
		row.State = v
	}
	return row, true
}

func buildModuleRow(vals []string, idx colIndex) (ModuleRow, bool) {
	idStr, ok := getStr(vals, idx, "id")
	if !ok {
		return ModuleRow{}, false
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return ModuleRow{}, false
	}
	row := ModuleRow{ID: id}
	if v, ok := getStr(vals, idx, "title"); ok {
		row.Title = v
	}
	if v, ok := getStr(vals, idx, "module"); ok {
		row.Module = v
	}
	if v, ok := getStr(vals, idx, "content"); ok {
		row.Content = v
	}
	if v, ok := getInt(vals, idx, "published"); ok {
		row.Published = v
	}
	return row, true
}
