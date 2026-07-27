// Package dbscan implementa L7: correlaciona el estado ya persistido en la
// base de datos (un volcado mysqldump, parseado por Parse) con el árbol de
// archivos ya conocido por capas anteriores (Principio III: no vuelve a
// recorrer disco, consume []extmap.Extension). Analyze deriva observaciones
// de tres clases — cuentas privilegiadas anómalas, estado de extensión
// (huérfana en BD vs en disco) y payload ejecutable residente en #__modules —
// sin decidir hallazgos (Principio II: eso es de la capa de derivación).
package dbscan

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"j0witness/internal/codescan"
	"j0witness/internal/extmap"
	"j0witness/internal/observe"
)

// Constantes locales para la heurística de cohorte por hueco de registro
// (Clase 1). Deliberadamente NO se importa internal/timeline: son la misma
// idea (un hueco grande separa la cohorte de instalación de plantados
// tardíos) pero timeline la aplica a ctime de archivos y dbscan a
// registerDate de usuarios; son dominios distintos que no deben acoplarse.
const (
	nsPerDay          = int64(24) * 60 * 60 * 1_000_000_000
	gapThresholdNS    = int64(30) * nsPerDay
	minFilesForCohort = 20
	// maxOutlierFrac espeja internal/timeline.maxOutlierFrac (declarada aquí
	// localmente, sin importar ese paquete): la cola tras el hueco solo se
	// afirma "outlier" si es una fracción pequeña de la población; una cola
	// grande es una segunda cohorte real (import/relanzamiento), no
	// plantados (Fix round 1, Finding 1).
	maxOutlierFrac = 0.05
)

// Fix B (guarda de correspondencia dump↔disco): si, sobre las extensiones
// habilitadas, no protegidas y LOCALIZABLES, la fracción ausente del disco
// supera mismatchFrac con al menos minCorrespondencePop en la población, el
// dump no corresponde a este árbol (versión/instalación distinta) → se suprime
// toda la Clase 2 y se declara la salvedad en coverage.database. Umbrales
// fijos (Principio IV, determinismo).
const (
	mismatchFrac         = 0.30
	minCorrespondencePop = 10
)

// excerptMaxRunes acota la longitud del excerpt de Clase 3 (~120 caracteres):
// suficiente para ser útil, insuficiente para filtrar el cuerpo completo del
// payload.
const excerptMaxRunes = 120

// hashPattern reconoce hashes con prefijo de esquema crypt (bcrypt $2y$/$2a$/
// $2b$, MD5-crypt $1$) para enmascararlos en el excerpt (FR-047): el hash en
// sí es un secreto, nunca debe llegar a la evidencia/informe/SQLite aunque
// aparezca incrustado en un payload PHP sembrado en un módulo.
var hashPattern = regexp.MustCompile(`\$(?:2[aby]|1)\$[A-Za-z0-9./$]*`)

// sentinelToken enmascara tokens con pinta de secreto sembrado (todo
// mayúsculas, ≥2 segmentos separados por "_", como los usados por
// internal/lab: SENTINEL_DB_PASSWORD_XYZZY, SENTINEL_SECRET_PLUGH) sin
// importar ese paquete (es solo de test/corpus, dbscan es código de
// producción): el patrón es genérico, no depende de sus valores exactos.
var sentinelToken = regexp.MustCompile(`\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b`)

// hexHashPattern reconoce cadenas hexadecimales largas (≥32 caracteres: MD5
// son 32, SHA1 40, SHA256 64...) que probablemente sean un hash de contraseña
// SIN prefijo de esquema crypt (a diferencia de hashPattern, que exige
// $2y$/$2a$/$2b$/$1$). Finding M2 (review final, diseño §7): "hashes de
// contraseña → a lo sumo algo=bcrypt len=60" no distingue por prefijo — un
// hash crudo es igual de secreto.
var hexHashPattern = regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`)

// emailPattern reconoce direcciones de correo dentro de texto libre (excerpt
// de módulo, title) y se enmascaran a "*@dominio" (Finding M2, diseño §7:
// "email → a lo sumo el dominio").
var emailPattern = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b`)

// DBSummary alimenta coverage.db (contexto de degradación + roster
// informativo; Principio VII). PrivilegedRoster son usernames, NUNCA email.
type DBSummary struct {
	Prefix           string
	Ambiguous        bool
	Unsupported      bool
	UsersParsed      int
	ExtensionsParsed int
	ModulesParsed    int
	PrivilegedRoster []string // usernames de cuentas privilegiadas (contexto; email nunca)
	// Correspondence (Fix B): "" = el dump corresponde al disco (o no había
	// población suficiente para juzgarlo); "mismatch" = demasiadas extensiones
	// habilitadas/no-protegidas/localizables ausentes del disco (dump de otra
	// instalación/versión) → toda la Clase 2 se suprimió. AbsentFraction es la
	// fracción ausente (redondeada) que motivó la salvedad; 0 si no hubo
	// mismatch.
	Correspondence string
	AbsentFraction float64
}

// isSuperGroup identifica el grupo Super Users por el id por defecto de
// Joomla (8) y por título (renombrado defensivo). Heurística declarada en
// cobertura, no en secreto.
func isSuperGroup(g GroupRow) bool {
	return g.ID == 8 || strings.EqualFold(strings.TrimSpace(g.Title), "Super Users")
}

// Analyze deriva las tres clases de observación a partir de d (Task 1) y
// diskExts (extmap.Discover ya ejecutado). nowNS sella las observaciones
// (Principio IV: nunca se consulta el reloj). El orden de emisión es
// determinista: usuarios, luego extensiones, luego módulos, cada uno
// iterando filas ya ordenadas por PK (Task 1).
// dirExists es el oráculo de presencia en disco respaldado por el inventario
// ya recorrido (Principio III: no re-recorre disco). Devuelve true si rel
// existe como directorio en el árbol capturado. adminDir es el nombre real del
// directorio de administración (por defecto "administrator").
func Analyze(d Dump, diskExts []extmap.Extension, dirExists func(rel string) bool, adminDir string, nowNS int64) ([]observe.Observation, DBSummary) {
	var obs []observe.Observation
	sum := DBSummary{
		Prefix: d.Prefix, Ambiguous: d.Ambiguous, Unsupported: d.Unsupported,
		UsersParsed: len(d.Users), ExtensionsParsed: len(d.Extensions), ModulesParsed: len(d.Modules),
	}

	// Finding M1 (review final): un dump AMBIGUO (>1 prefijo candidato, Parse
	// ya lo detectó) mezcla filas de instalaciones potencialmente distintas —
	// cualquier join (usuario↔grupo, elemento↔disco) sobre esa mezcla sería
	// una adivinanza, no una correlación (diseño §4: "se degrada, no
	// adivina"). Se degrada devolviendo solo el resumen (Ambiguous=true, los
	// *_parsed ya calculados arriba a partir de d, que no requieren join) sin
	// emitir NINGUNA observación de las tres clases.
	if d.Ambiguous {
		return nil, sum
	}

	// --- Clase 1: cuentas privilegiadas anómalas ---
	//
	// Principio VI: el mero hecho de ser Super User NUNCA es un hallazgo. Solo
	// se emite observación cuando, ADEMÁS de privilegiada, la cuenta presenta
	// una anomalía concreta: quedar fuera de la cohorte de registro (outlier
	// tras un hueco grande) o tener flags incoherentes (activa pero con un
	// token de activación pendiente). Un único Super User legítimo, registrado
	// dentro de la cohorte y con flags coherentes, produce cero observaciones
	// aunque sea la única cuenta con privilegios — ver
	// TestAnalyzeLegitPrivilegedNoFinding.
	superGroups := map[int64]bool{}
	for _, g := range d.Groups {
		if isSuperGroup(g) {
			superGroups[g.ID] = true
		}
	}
	privileged := map[int64]bool{}
	for _, m := range d.Memberships {
		if superGroups[m.GroupID] {
			privileged[m.UserID] = true
		}
	}
	cohortHi := registerCohortUpperBound(d.Users)
	for _, u := range d.Users {
		if !privileged[u.ID] {
			continue
		}
		sum.PrivilegedRoster = append(sum.PrivilegedRoster, u.Username)
		reasons := anomalyReasons(u, cohortHi)
		if len(reasons) == 0 {
			continue
		}
		ev := map[string]any{
			"user_id": u.ID, "username": u.Username,
			"register_date_ns": u.RegisterNS, "reasons": reasons,
		} // email/hash NUNCA
		if o, err := observe.New([]byte(fmt.Sprintf("db://users/%d", u.ID)),
			observe.DBPrivilegedAnomaly, ev, observe.SrcDB, observe.High, nowNS); err == nil {
			obs = append(obs, o)
		}
	}

	// --- Clase 2: estado de extensión (correlación disco↔BD) ---
	//
	// Resolución de la brecha de interfaz Task 2↔Task 3: la observación no
	// llevaba rutas de disco, y las observaciones de propiedad de disco
	// (ext_undeclared, etc.) clavan por la ruta del archivo, no por el
	// `element` declarado en BD — no había join fiable ruta→elemento. Se
	// añade aquí, en la fuente, el mínimo necesario: para cada extensión
	// habilitada en BD y presente en disco, sus raíces de instalación
	// (extmap.Extension.Layout.Roots, ya ordenadas — determinista). Las
	// huérfanas (ausentes en disco) no llevan disk_paths: no hay raíz que
	// correlacionar.
	//
	// Finding C1 (review final): dos incompatibilidades producían una
	// tormenta de falsos positivos J0W-DB-002 sobre extensiones legítimas.
	//   1. diskExts (extmap.Discover) es SOLO de terceros — el core-bundled se
	//      excluye a propósito (extmap/discover.go: "de terceros, core-bundled
	//      ya excluidas"). Cualquier extensión core enabled=1 en el dump
	//      jamás aparece en diskByKey, aunque esté perfectamente presente.
	//      Joomla marca el core protected=1: se usa esa bandera de guarda.
	//      Una extensión protected=1 NUNCA se afirma huérfana (Principio VI:
	//      su ausencia en un mapa que por diseño la excluye no prueba nada).
	//   2. El `element` de BD es desnudo ("joomla", "mod_menu") mientras
	//      ElementKey lleva forma ("system/joomla", "mod_menu@administrator").
	//      Se construye la clave de BD con la MISMA forma (dbExtensionKey)
	//      para comparar claves compatibles.
	// Fix A: la presencia en disco se decide por la EXISTENCIA del directorio
	// de instalación de la extensión (dirExists sobre extInstallDirs), no solo
	// por aparecer en diskExts (que es SOLO de terceros — extmap.Discover
	// excluye el core-bundled). Así, una extensión core removible (protected=0,
	// p.ej. com_banners) presente en el disco 5.x deja de ser un falso
	// positivo. diskExts se sigue usando para la anotación de correlación
	// cruzada (disk_paths → element).
	//
	// Fix B: se acumula la fracción ausente sobre la población habilitada, no
	// protegida y LOCALIZABLE; si supera el umbral con población suficiente, el
	// dump no corresponde al disco → se suprime toda la Clase 2.
	diskByKey := map[string]extmap.Extension{}
	for _, e := range diskExts {
		diskByKey[e.ElementKey] = e
	}
	var class2 []observe.Observation
	var fracTotal, fracAbsent int
	for _, x := range d.Extensions {
		if x.Enabled != 1 || x.Element == "" {
			continue
		}
		key := dbExtensionKey(x)
		matched, inDiskExts := diskByKey[key]

		dirs := extInstallDirs(x, adminDir)
		locatable := dirs != nil
		present := inDiskExts
		if !present && locatable {
			for _, dir := range dirs {
				if dirExists(dir) {
					present = true
					break
				}
			}
		}

		// Fix B: la población que juzga la correspondencia es solo la
		// habilitada, no protegida y localizable (aquellas cuya ausencia sería
		// una afirmación fiable).
		if locatable && x.Protected != 1 {
			fracTotal++
			if !present {
				fracAbsent++
			}
		}

		if !present && !locatable {
			// Presencia DESCONOCIDA (file/package/language/otros): jamás se
			// afirma huérfana (Principio VI: degradar hacia el silencio).
			continue
		}
		if !present && x.Protected == 1 {
			// Core protegida ausente: su ausencia en el disco no se afirma como
			// huérfana (conservador; el core no debería faltar y, si falta, no
			// es esta capa quien lo dictamina).
			continue
		}
		ev := map[string]any{
			"element": x.Element, "ext_type": x.Type,
			"protected": x.Protected == 1, "present_on_disk": present,
		}
		if present && len(matched.Layout.Roots) > 0 {
			ev["disk_paths"] = matched.Layout.Roots
		}
		if o, err := observe.New([]byte("db://extensions/"+x.Element),
			observe.DBExtensionState, ev, observe.SrcDB, observe.High, nowNS); err == nil {
			class2 = append(class2, o)
		}
	}
	// Fix B: guarda de correspondencia. Con población suficiente y demasiadas
	// ausentes, el dump es de otra instalación/versión → cero Clase 2 + la
	// salvedad declarada en el resumen (coverage.database). Las Clases 1 y 3
	// (usuarios, payloads en módulos) son INDEPENDIENTES del disco y se
	// conservan.
	if fracTotal >= minCorrespondencePop && float64(fracAbsent)/float64(fracTotal) > mismatchFrac {
		sum.Correspondence = "mismatch"
		sum.AbsentFraction = math.Round(float64(fracAbsent)/float64(fracTotal)*100) / 100
	} else {
		obs = append(obs, class2...)
	}

	// --- Clase 3: payload ejecutable residente en #__modules ---
	for _, m := range d.Modules {
		pats, ok := codescan.SuspiciousContent([]byte(m.Content))
		if !ok {
			continue
		}
		ev := map[string]any{
			// Finding M2 (review final): el title también es evidencia — un
			// hash/email sembrado ahí (p.ej. por error de captura, o de
			// prueba) no debe escapar la redacción solo porque no es el
			// excerpt del cuerpo.
			"module_id": m.ID, "title": redactSecrets(m.Title), "module_type": m.Module,
			"patterns": pats, "excerpt": redactExcerpt(m.Content),
		} // nunca el cuerpo crudo
		if o, err := observe.New([]byte(fmt.Sprintf("db://modules/%d", m.ID)),
			observe.DBContentPayload, ev, observe.SrcDB, observe.High, nowNS); err == nil {
			obs = append(obs, o)
		}
	}

	sort.Strings(sum.PrivilegedRoster)
	return obs, sum
}

// registerCohortUpperBound halla el límite superior (ns) de la cohorte de
// instalación a partir de registerDate de todos los usuarios: se ordenan los
// instantes de registro y se busca el hueco (gap) más reciente mayor que
// gapThresholdNS; el límite es el instante justo antes de ese hueco. Devuelve
// 0 (ninguna cohorte definida, ningún outlier reclamable) cuando hay menos de
// minFilesForCohort usuarios o no existe tal hueco — con pocos usuarios, un
// intervalo grande entre dos registros legítimos es la norma, no la señal
// (Principio VI: sin cohorte suficiente, no se afirma un outlier).
//
// Fix round 1 (Finding 1): además del hueco, se exige que la cola (usuarios
// tras el hueco) sea ≤ maxOutlierFrac de la población — mismo guardián que
// internal/timeline. Un hueco grande con una cola GRANDE (p.ej. un lote de
// 10 altas legítimas sobre 30 usuarios: relanzamiento/import masivo) no es
// un grupo de outliers plantados, es una segunda cohorte real; afirmar
// "register_outlier" ahí sería un falso positivo de Principio VI.
func registerCohortUpperBound(users []UserRow) int64 {
	if len(users) < minFilesForCohort {
		return 0
	}
	times := make([]int64, len(users))
	for i, u := range users {
		times[i] = u.RegisterNS
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	for i := len(times) - 1; i >= 1; i-- {
		if times[i]-times[i-1] > gapThresholdNS {
			tail := len(times) - i
			if float64(tail) <= maxOutlierFrac*float64(len(times)) {
				return times[i-1]
			}
			return 0 // hueco encontrado, pero cola demasiado grande: cohorte real, no outliers
		}
	}
	return 0
}

// anomalyReasons enumera las razones concretas por las que una cuenta
// privilegiada u es anómala (vacío = ninguna, Principio VI):
//   - "register_outlier": se registró después del límite de la cohorte de
//     instalación (cohortHi != 0 exige que exista cohorte definida).
//
// Finding I1 (review final): el disparador "incoherent_flags" (Block == 0 con
// Activation poblado) se ELIMINA por completo. Joomla reutiliza
// `#__users.activation` para almacenar el token de RESETEO de contraseña
// (com_users, flujo "olvidé mi contraseña"), y la cuenta NO se bloquea
// durante ese reseteo: `block=0` + `activation` poblado es un reseteo de
// contraseña en curso, el estado NORMAL de cualquier cuenta (privilegiada o
// no) que pidió resetear su clave — jamás una manipulación directa de fila.
// Afirmarlo como anomalía era un falso positivo estructural (Principio VI
// prevalece sobre diseño §5.1 aquí: un FP es un defecto de severidad alta,
// no una heurística "casi sin FP" que en la práctica dispara en cualquier
// reseteo legítimo). Se conserva únicamente "register_outlier" (la señal de
// cohorte, near-zero-FP por construcción).
func anomalyReasons(u UserRow, cohortHi int64) []string {
	var reasons []string
	if cohortHi != 0 && u.RegisterNS > cohortHi {
		reasons = append(reasons, "register_outlier")
	}
	return reasons
}

// extInstallDirs devuelve, de forma determinista, los directorios de
// instalación candidatos de una extensión según su tipo (Fix A). El chequeo de
// presencia (dirExists) los prueba en orden; basta con que UNO exista. Los
// tipos no localizables de forma fiable (file/package/language/otros) devuelven
// nil → presencia DESCONOCIDA (nunca se afirma huérfana, Principio VI).
//
//   - component (com_x): components/com_x y <adminDir>/components/com_x
//   - module (mod_x): client_id==1 → <adminDir>/modules/mod_x; si no modules/mod_x
//   - plugin (folder f, element e): plugins/f/e
//   - template (x): client_id==1 → <adminDir>/templates/x; si no templates/x
//   - library (x): libraries/x
func extInstallDirs(x ExtRow, adminDir string) []string {
	switch x.Type {
	case "component":
		return []string{"components/" + x.Element, adminDir + "/components/" + x.Element}
	case "module":
		if x.ClientID == 1 {
			return []string{adminDir + "/modules/" + x.Element}
		}
		return []string{"modules/" + x.Element}
	case "plugin":
		if x.Folder == "" {
			return nil // sin folder no hay ruta fiable plugins/<folder>/<element>
		}
		return []string{"plugins/" + x.Folder + "/" + x.Element}
	case "template":
		if x.ClientID == 1 {
			return []string{adminDir + "/templates/" + x.Element}
		}
		return []string{"templates/" + x.Element}
	case "library":
		return []string{"libraries/" + x.Element}
	default:
		return nil // file/package/language/otros: no localizable de forma fiable
	}
}

// dbExtensionKey construye, a partir de una fila de BD, la clave con la MISMA
// forma que manifest.ExtensionKey (el lado de disco, extmap.Extension.
// ElementKey) — component: element desnudo; plugin: folder/element; módulo o
// plantilla de administrator (client_id==1): element@administrator; site
// (client_id==0) y cualquier otro tipo: element desnudo. No se importa el
// paquete manifest (evita acoplar dbscan al modelo de manifiesto): el mapeo
// es deliberadamente local y mínimo, replicando solo la forma, no la lógica
// de resolución de manifiestos (Finding C1, review final).
func dbExtensionKey(x ExtRow) string {
	switch x.Type {
	case "plugin":
		return x.Folder + "/" + x.Element
	case "module", "template":
		if x.ClientID == 1 {
			return x.Element + "@administrator"
		}
		return x.Element
	default:
		return x.Element
	}
}

// redactSecrets aplica las cuatro máscaras de secreto — hash crypt con
// prefijo de esquema, hash hexadecimal crudo ≥32 caracteres, token con pinta
// de centinela sembrado y dirección de email (a lo sumo el dominio) — SIN
// acotar longitud. La usan tanto redactExcerpt (que además recorta) como el
// title de Clase 3 (Finding M2, review final: el title también es evidencia
// que puede llevar un secreto, y el diseño §7 exige la misma barrera para
// cualquier campo que llegue a la observación, no solo el excerpt del
// cuerpo).
func redactSecrets(s string) string {
	red := hashPattern.ReplaceAllString(s, "[REDACTED_HASH]")
	red = hexHashPattern.ReplaceAllString(red, "[REDACTED_HASH]")
	red = sentinelToken.ReplaceAllString(red, "[REDACTED_TOKEN]")
	red = emailPattern.ReplaceAllString(red, "*@$1")
	return red
}

// redactExcerpt produce un extracto acotado (~120 runas) del contenido de un
// módulo ya marcado sospechoso, con los secretos enmascarados (FR-047/diseño
// §7: hashes de contraseña —con o sin prefijo de esquema—, emails y tokens
// con pinta de centinela NUNCA en la evidencia) pero conservando visibles los
// marcadores que hacen el extracto útil (`<?php`, nombres de función). Nunca
// se emite el cuerpo crudo.
func redactExcerpt(s string) string {
	red := redactSecrets(s)
	r := []rune(red)
	if len(r) > excerptMaxRunes {
		r = r[:excerptMaxRunes]
	}
	return string(r)
}
