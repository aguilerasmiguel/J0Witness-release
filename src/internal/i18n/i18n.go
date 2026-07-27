// Package i18n resuelve los mensajes del informe a español o inglés. El
// catálogo es estático (determinismo, Principio IV): mismo (lang, id, params)
// → misma cadena. La resolución no usa reloj ni aleatoriedad. Las claves de
// params se aplican en orden ordenado (T, línea ~56), asegurando determinismo;
// ningún param de evidencia real contiene {otras_claves}, por lo que la
// sustitución no introduce nuevas claves después de la evaluación.
package i18n

import (
	"fmt"
	"sort"
	"strings"
)

type Lang string

const (
	ES Lang = "es"
	EN Lang = "en"
)

// Parse normaliza un valor de flag a Lang. "" → ES (por defecto y
// retrocompatibilidad); acepta "es"/"en"; cualquier otro es error.
func Parse(s string) (Lang, error) {
	switch s {
	case "", "es":
		return ES, nil
	case "en":
		return EN, nil
	default:
		return ES, fmt.Errorf("idioma no soportado: %q (usa es|en)", s)
	}
}

type entry struct{ es, en string }

// T resuelve id al idioma lang y sustituye cada {clave} por params[clave]
// (formateado con fmt.Sprint). Un id ausente devuelve el propio id (visible en
// tests). Las claves de params se aplican en orden ordenado por robustez, aun
// siendo el resultado indiferente al orden.
func T(lang Lang, id string, params map[string]any) string {
	e, ok := messages[id]
	if !ok {
		return id
	}
	s := e.es
	if lang == EN {
		s = e.en
	}
	if len(params) == 0 {
		return s
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s = strings.ReplaceAll(s, "{"+k+"}", fmt.Sprint(params[k]))
	}
	return s
}

var messages = map[string]entry{
	// Compartidos
	"compared.baseline":          {es: "distribución oficial {version}", en: "official distribution {version}"},
	"compared.witness":           {es: "conjunto testigo del catálogo", en: "catalog witness set"},
	"compared.manifest":          {es: "manifiesto de {ext}", en: "{ext} manifest"},
	"compared.official_pkg":      {es: "paquete oficial de la extensión", en: "official extension package"},
	"compared.webshell":          {es: "técnicas conocidas de webshell", en: "known webshell techniques"},
	"compared.rce":               {es: "técnicas conocidas de webshell/RCE", en: "known webshell/RCE techniques"},
	"compared.webshell_backdoor": {es: "técnicas conocidas de webshell/backdoor", en: "known webshell/backdoor techniques"},

	// J0W-CORE
	"core001.observed":                  {es: "archivo del core con contenido distinto al distribuido", en: "core file whose content differs from what is distributed"},
	"core001.rationale":                 {es: "cualquier divergencia del core no atribuible a normalización es una modificación efectiva", en: "any core divergence not attributable to normalization is an effective modification"},
	"core001.alt.minor":                 {es: "edición puntual del administrador (p.ej. ajuste de compatibilidad)", en: "one-off admin edit (e.g. a compatibility tweak)"},
	"core001.alt.inert":                 {es: "archivo de datos inerte: una imagen/fuente/media del core modificada no ejecuta código; es integridad de contenido, no de ejecución", en: "inert data file: a modified core image/font/media file executes no code; this is content integrity, not execution integrity"},
	"core002.observed":                  {es: "archivo del core con fragmento inyectado de aspecto ejecutable", en: "core file with an injected, executable-looking fragment"},
	"core002.rationale":                 {es: "la distribución oficial no contiene ese fragmento; las construcciones detectadas son típicas de webshells", en: "the official distribution contains no such fragment; the detected constructs are typical of webshells"},
	"core003.observed":                  {es: "archivo distribuido por el core ausente del árbol", en: "a core-distributed file is missing from the tree"},
	"core003.rationale":                 {es: "el ausente puede ser borrado hostil o instalación incompleta", en: "the missing file may be a hostile deletion or an incomplete installation"},
	"core003.alt":                       {es: "borrado deliberado del administrador", en: "deliberate deletion by the administrator"},
	"core003.rationale.inert_asset":     {es: "un asset estático del core ausente (imagen/fuente/media) rara vez es señal de manipulación; su ausencia sigue el patrón de copia/backup que excluye media/vendored", en: "a missing static core asset (image/font/media) is rarely a sign of tampering; its absence follows the copy/backup pattern that excludes media/vendored"},
	"core003.alt.inert_asset":           {es: "asset estático ausente (imagen/fuente/media): patrón de copia/backup que excluye media/vendored; su ausencia no es señal de manipulación", en: "missing static asset (image/font/media): copy/backup pattern that excludes media/vendored; its absence is not a sign of tampering"},
	"core003.rationale.expected_absent": {es: "un archivo de plantilla/doc de la distribución o de un directorio de runtime ausente es rutina en un sitio configurado; no es indicador por sí mismo", en: "a missing distribution template/doc file, or one from a runtime directory, is routine on a configured site; it is not an indicator on its own"},
	"core003.alt.expected_absent":       {es: "archivo de plantilla/doc de la distribución (LICENSE/README/htaccess.txt/robots.txt.dist) o de un directorio de runtime (cache/logs/tmp): los sitios configurados los borran o renombran de rutina", en: "distribution template/doc file (LICENSE/README/htaccess.txt/robots.txt.dist) or one from a runtime directory (cache/logs/tmp): configured sites routinely delete or rename these"},
	"core003.installation.observed":     {es: "directorio installation/ ausente al completo", en: "the installation/ directory is entirely absent"},
	"core003.installation.rationale":    {es: "el instalador de Joomla lo elimina al terminar la instalación", en: "the Joomla installer removes it once installation completes"},
	"core003.installation.alt":          {es: "eliminación estándar post-instalación; su ausencia total es lo esperado en un sitio en producción", en: "standard post-install removal; its complete absence is expected on a production site"},
	"core003.collapsed.observed":        {es: "subárbol del baseline ausente por completo ({n} archivos)", en: "a baseline subtree is entirely absent ({n} files)"},
	"core003.collapsed.rationale":       {es: "un subárbol entero del baseline ausente: patrón de copia/backup que excluye este subárbol, o eliminación de una librería completa; ningún borrado DIRIGIDO puede ocultarse aquí (esos dejan el directorio parcialmente presente y se reportan archivo a archivo)", en: "an entire baseline subtree absent: a copy/backup pattern that excludes this subtree, or removal of a whole library; no TARGETED deletion can hide here (those leave the directory partially present and are reported file by file)"},
	"core003.collapsed.alt":             {es: "exclusión de backup/copia de este subárbol (media/vendored, dependencias regenerables) o eliminación deliberada de una librería completa", en: "backup/copy exclusion of this subtree (media/vendored, regenerable dependencies) or deliberate removal of an entire library"},
	"core004.observed":                  {es: "archivo ajeno a la distribución dentro de un directorio del core", en: "a file foreign to the distribution inside a core directory"},
	"core004.rationale":                 {es: "la distribución enumera todo su contenido; lo que sobra en sus directorios no vino con ella", en: "the distribution enumerates all of its content; anything extra in its directories did not ship with it"},
	"core004.alt":                       {es: "archivo dejado por una extensión o por el administrador", en: "file left behind by an extension or by the administrator"},
	"core005.observed":                  {es: "ejecutable del servidor en directorio de escritura donde la distribución no coloca ninguno", en: "a server-executable file in a writable directory where the distribution places none"},
	"core005.rationale":                 {es: "images/, cache/, tmp/ y logs/ son los destinos clásicos de webshells subidos", en: "images/, cache/, tmp/ and logs/ are the classic destinations for uploaded webshells"},
	"core005.artifact.observed":         {es: "ejecutable en directorio de escritura reconocido como artefacto de runtime de Joomla", en: "executable in a writable directory recognized as a Joomla runtime artifact"},
	"core005.artifact.rationale":        {es: "caché y logs que Joomla genera con guarda die(); su presencia es esperada", en: "cache and logs that Joomla generates with a die() guard; their presence is expected"},
	"core005.artifact.alt":              {es: "artefacto propio de Joomla, no un ejecutable plantado", en: "a genuine Joomla artifact, not a planted executable"},
	"core006.observed":                  {es: "archivo del core idéntico al original salvo finales de línea o BOM", en: "core file identical to the original except for line endings or BOM"},
	"core006.rationale":                 {es: "el contenido efectivo no cambió", en: "the effective content did not change"},
	"core006.alt":                       {es: "subida en modo ASCII (FTP) o normalización del editor", en: "ASCII-mode (FTP) upload or editor normalization"},
	"core007.observed":                  {es: "la versión declarada no coincide con la inferida por evidencia de archivos", en: "the declared version does not match the one inferred from file evidence"},
	"core007.rationale":                 {es: "editar version.php es el primer paso para ocultar un core desactualizado o troyanizado", en: "editing version.php is the first step to hide an outdated or trojaned core"},
	"core008.observed":                  {es: "archivos correspondientes a más de una versión", en: "files belonging to more than one version"},
	"core008.rationale":                 {es: "una instalación a medio actualizar no puede compararse contra un único baseline sin declararlo", en: "a half-updated installation cannot be compared against a single baseline without declaring so"},
	"core008.alt":                       {es: "actualización interrumpida o parcial", en: "interrupted or partial update"},
	"core009.observed":                  {es: "archivo obsoleto cuyo contenido no coincide con ninguna versión que lo distribuyó", en: "an obsolete file whose content matches no version that ever distributed it"},
	"core009.rationale":                 {es: "los archivos huérfanos que nadie revisa son escondite clásico de webshells", en: "orphan files that nobody reviews are a classic webshell hiding place"},
	"core009.alt.inert":                 {es: "archivo de datos inerte huérfano (imagen/fuente/media de una versión anterior); un residuo binario inerte no es un escondite de webshell ejecutable", en: "orphan inert data file (image/font/media from an earlier version); an inert binary remnant is not an executable webshell hideout"},
	"core010.observed":                  {es: "el tipo real del contenido contradice la extensión", en: "the actual content type contradicts the file extension"},
	"core010.compared":                  {es: "tipo esperado por extensión", en: "type expected from the extension"},
	"core010.rationale":                 {es: "un PHP disfrazado de imagen es una técnica común de evasión", en: "a PHP file disguised as an image is a common evasion technique"},
	"core010.alt":                       {es: "archivo corrupto o renombrado por error", en: "corrupt or mistakenly renamed file"},
	"core010.alt.inert":                 {es: "archivo inerte mal etiquetado (p.ej. un PNG con extensión .jpg); el contenido es una imagen/media, no un script ejecutable", en: "mislabeled inert file (e.g. a PNG with a .jpg extension); the content is an image/media file, not an executable script"},
	"core010.alt.identical":             {es: "el archivo es idéntico al distribuido oficialmente: la discrepancia tipo/extensión viene de la propia distribución", en: "the file is identical to the officially distributed one: the type/extension mismatch comes from the distribution itself"},
	"core011.observed":                  {es: "archivo que esta versión ya no distribuye, con contenido de una versión anterior", en: "a file this version no longer distributes, with content from an earlier version"},
	"core011.rationale":                 {es: "residuo esperado de actualización (FR-033)", en: "expected update remnant (FR-033)"},
	"core011.alt":                       {es: "el actualizador no borró el archivo obsoleto; comportamiento conocido de Joomla", en: "the updater did not remove the obsolete file; known Joomla behavior"},
	"core012.observed":                  {es: "estructura anómala en archivo de configuración esperado", en: "anomalous structure in an expected configuration file"},
	"core012.compared":                  {es: "estructura canónica del archivo", en: "the file's canonical structure"},
	"core012.rationale":                 {es: "los archivos de configuración modificables son vector habitual de persistencia", en: "writable configuration files are a common persistence vector"},

	// J0W-EXT
	"ext001.observed":  {es: "ejecutable no declarado dentro del árbol de la extensión {ext}", en: "undeclared executable inside the {ext} extension tree"},
	"ext001.rationale": {es: "la extensión no reconoce este archivo; es el escondite clásico de un webshell entre archivos legítimos", en: "the extension does not recognize this file; it is the classic place to hide a webshell among legitimate files"},
	"ext002.observed":  {es: "ejecutable dentro de una carpeta declarada por {ext}, no enumerado individualmente", en: "executable inside a folder declared by {ext}, not individually enumerated"},
	"ext002.rationale": {es: "la carpeta está declarada, pero el manifiesto no nombra este ejecutable en concreto (C1)", en: "the folder is declared, but the manifest does not name this particular executable (C1)"},
	"ext002.alt":       {es: "archivo legítimo generado por la extensión dentro de una carpeta que declara por completo", en: "legitimate file generated by the extension inside a folder it fully declares"},
	"ext003.observed":  {es: "manifiesto de extensión ilegible, malformado o de esquema no reconocido", en: "unreadable, malformed, or unrecognized-schema extension manifest"},
	"ext003.compared":  {es: "esquema de manifiesto de Joomla", en: "Joomla manifest schema"},
	"ext003.rationale": {es: "sin manifiesto interpretable no se puede atribuir el árbol de la extensión; puede ser corrupción o manipulación", en: "without an interpretable manifest the extension tree cannot be attributed; this may be corruption or tampering"},
	"ext003.alt":       {es: "manifiesto legacy o roto por una actualización incompleta", en: "legacy manifest, or one broken by an incomplete update"},
	"ext004.observed":  {es: "el manifiesto declara como suyo un archivo en una ubicación anómala", en: "the manifest claims a file in an anomalous location as its own"},
	"ext004.compared":  {es: "raíces de instalación esperadas del tipo de extensión", en: "expected install roots for the extension type"},
	"ext004.rationale": {es: "editar el manifiesto para legitimar un archivo plantado es una vía de evasión; el manifiesto es declaración, no verdad", en: "editing the manifest to legitimize a planted file is an evasion path; the manifest is a declaration, not ground truth"},
	"ext005.observed":  {es: "archivo declarado por {ext} pero ausente del árbol", en: "file declared by {ext} but absent from the tree"},
	"ext005.rationale": {es: "una extensión incompleta puede indicar instalación fallida o borrado selectivo", en: "an incomplete extension may indicate a failed install or selective deletion"},
	"ext005.alt":       {es: "el administrador eliminó un archivo opcional de la extensión", en: "the administrator removed an optional file of the extension"},
	"ext006.observed":  {es: "dos extensiones reclaman la misma ruta", en: "two extensions claim the same path"},
	"ext006.compared":  {es: "manifiestos de las extensiones en conflicto", en: "manifests of the conflicting extensions"},
	"ext006.rationale": {es: "un solapamiento de propiedad puede indicar un paquete mal formado o una suplantación", en: "an ownership overlap may indicate a malformed package or an impersonation"},
	"ext007.observed":  {es: "directorio con estructura de extensión sin su manifiesto", en: "a directory with extension structure but no manifest"},
	"ext007.compared":  {es: "convención de manifiestos de Joomla", en: "Joomla manifest convention"},
	"ext007.rationale": {es: "un árbol de extensión sin manifiesto no se puede atribuir; puede ser residuo o evasión", en: "an extension tree without a manifest cannot be attributed; it may be a remnant or an evasion"},
	"ext007.alt":       {es: "restos de una desinstalación incompleta", en: "leftovers from an incomplete uninstall"},
	"ext008.observed":  {es: "archivo de {ext} con contenido distinto al del paquete oficial ({src})", en: "{ext} file whose content differs from the official package ({src})"},
	"ext008.rationale": {es: "una divergencia respecto al release del autor en un archivo ejecutable es una modificación efectiva — el escondite de un troyano en una extensión de confianza", en: "a divergence from the author's release in an executable file is an effective modification — where a trojan hides inside a trusted extension"},
	"ext008.alt":       {es: "parche puntual del administrador o versión con revisión distinta", en: "one-off admin patch, or a build with a different revision"},
	"ext009.observed":  {es: "archivo que el paquete oficial de {ext} distribuye pero falta en el árbol instalado", en: "a file the official {ext} package distributes but that is missing from the installed tree"},
	"ext009.rationale": {es: "un archivo ausente respecto al release del autor puede indicar instalación incompleta o borrado selectivo", en: "a file missing relative to the author's release may indicate an incomplete install or selective deletion"},

	// J0W-LAYOUT
	"layout001.observed.generic": {es: "no se reconoce el directorio de administración estándar (administrator/)", en: "the standard administration directory (administrator/) is not recognized"},
	"layout001.observed.found":   {es: "el esqueleto de administración parece vivir en '{found}/', no en administrator/", en: "the administration skeleton appears to live in '{found}/', not in administrator/"},
	"layout001.compared":         {es: "layout estándar de Joomla (administrator/ con components/, manifests/, includes/)", en: "standard Joomla layout (administrator/ with components/, manifests/, includes/)"},
	"layout001.rationale":        {es: "un directorio de administración renombrado/ausente degrada la atribución y verificación del lado admin; reejecuta con --administrator-dir=<dir> para analizarlo correctamente", en: "a renamed/absent administration directory degrades admin-side attribution and verification; re-run with --administrator-dir=<dir> to analyze it correctly"},
	"layout001.alt":              {es: "endurecimiento legítimo del administrador o intento de ocultar el panel; también un árbol parcial/no-Joomla", en: "legitimate admin hardening or an attempt to hide the panel; also a partial/non-Joomla tree"},

	// J0W-CODE
	"code001.observed":  {es: "ejecución de un payload decodificado en tiempo de ejecución ({sink} sobre una cadena decodificada)", en: "execution of a runtime-decoded payload ({sink} over a decoded string)"},
	"code001.rationale": {es: "eval/assert/create_function sobre el resultado de base64_decode/gzinflate es la firma de un dropper; el código legítimo no ejecuta blobs ofuscados", en: "eval/assert/create_function over the result of base64_decode/gzinflate is a dropper's signature; legitimate code does not execute obfuscated blobs"},
	"code001.alt":       {es: "desempaquetado de código legítimo ofuscado por un empaquetador comercial (raro)", en: "unpacking of legitimate code obfuscated by a commercial packer (rare)"},
	"code002.observed":  {es: "entrada controlable por el atacante ({trg}) llega directa a un sink de ejecución ({sink})", en: "attacker-controllable input ({trg}) reaches an execution sink directly ({sink})"},
	"code002.rationale": {es: "una superglobal o php://input pasada a un intérprete o a la shell es ejecución remota de código; casi nunca es intencionado", en: "a superglobal or php://input passed to an interpreter or the shell is remote code execution; almost never intentional"},
	"code002.alt":       {es: "código de administración que ejecuta comandos parametrizados por el usuario de forma deliberada (inusual y peligroso igualmente)", en: "admin code that deliberately runs user-parameterized commands (unusual, and dangerous all the same)"},
	"code003.observed":  {es: "preg_replace con modificador /e (ejecuta el reemplazo como PHP)", en: "preg_replace with the /e modifier (executes the replacement as PHP)"},
	"code003.compared":  {es: "técnica de backdoor clásica", en: "classic backdoor technique"},
	"code003.rationale": {es: "el modificador /e convierte preg_replace en un eval; es un vector de puerta trasera muy usado", en: "the /e modifier turns preg_replace into an eval; a heavily used backdoor vector"},
	"code003.alt":       {es: "código legacy inerte: /e fue eliminado en PHP 7, no ejecuta en tiempos de ejecución modernos", en: "inert legacy code: /e was removed in PHP 7 and does not execute on modern runtimes"},
	"code004.observed":  {es: "función de nombre computado en tiempo de ejecución (decodificado o ensamblado) e invocada", en: "function whose name is computed at runtime (decoded or assembled) and then invoked"},
	"code004.rationale": {es: "construir el nombre de una función a partir de datos decodificados o concatenados y llamarla es una forma clásica de ocultar la ejecución al análisis por nombre", en: "building a function name from decoded or concatenated data and calling it is a classic way to hide execution from name-based analysis"},
	"code004.alt":       {es: "código legítimo con despacho dinámico de funciones (poco común; casi siempre malicioso cuando el nombre proviene de un decode)", en: "legitimate code with dynamic function dispatch (uncommon; almost always malicious when the name comes from a decode)"},

	// J0W-CONFIG
	"config001.observed":  {es: "el archivo de config ejecuta un archivo en cada petición ({directive} → {target})", en: "the config file executes a file on every request ({directive} → {target})"},
	"config.compared":     {es: "configuración de servidor sin directivas de ejecución", en: "server configuration without execution directives"},
	"config001.rationale": {es: "auto_prepend_file/auto_append_file carga y ejecuta un archivo en TODA petición; es el cargador de backdoor persistente por excelencia", en: "auto_prepend_file/auto_append_file loads and executes a file on EVERY request; the quintessential persistent-backdoor loader"},
	"config001.alt":       {es: "bootstrap global legítimo (muy raro en un árbol de Joomla)", en: "legitimate global bootstrap (very rare in a Joomla tree)"},
	"config002.observed":  {es: "una extensión no-PHP se ejecuta como PHP ({directive} sobre {target})", en: "a non-PHP extension is executed as PHP ({directive} on {target})"},
	"config002.rationale": {es: "mapear una extensión como {target} al motor PHP convierte cualquier archivo subido con esa extensión en un webshell ejecutable — el habilitador clásico del webshell-imagen", en: "mapping an extension like {target} to the PHP engine turns any uploaded file with that extension into an executable webshell — the classic image-webshell enabler"},
	"config002.alt":       {es: "mapeo de extensión de plantilla legítimo (poco común)", en: "legitimate template-extension mapping (uncommon)"},
	"config003.observed":  {es: "ajuste peligroso del runtime de PHP en config ({directive}={state})", en: "dangerous PHP runtime setting in config ({directive}={state})"},
	"config003.rationale": {es: "reactivar allow_url_include, vaciar disable_functions o redirigir include_path debilita el runtime para RFI/bypass de restricciones", en: "re-enabling allow_url_include, emptying disable_functions, or redirecting include_path weakens the runtime for RFI/restriction bypass"},
	"config003.alt":       {es: "reconfiguración deliberada del administrador (verifica que sea intencionada)", en: "deliberate reconfiguration by the administrator (verify it is intentional)"},

	// J0W-TIME
	"time001.observed":            {es: "el mtime del archivo está fechado en el futuro respecto a su ctime (timestamps manipulados)", en: "the file's mtime is dated in the future relative to its ctime (timestamps manipulated)"},
	"time.compared":               {es: "relación normal mtime ≤ ctime", en: "normal relationship mtime ≤ ctime"},
	"time001.rationale":           {es: "bajo el modelo primario el ctime es el ancla fiable; un mtime posterior al ctime solo se consigue fijándolo a mano — señal de timestomping que corrobora otras sospechas", en: "under the primary threat model ctime is the reliable anchor; an mtime later than ctime is only achievable by setting it by hand — a timestomping signal that corroborates other suspicions"},
	"time001.alt":                 {es: "desajuste de reloj durante la extracción, restauración de backup, o un tarball con marcas de tiempo futuras", en: "clock skew during extraction, backup restore, or a tarball carrying future timestamps"},
	"corroboration.ctime_outlier": {es: " [corroboración temporal: el ctime de este archivo cae {days} días después de la cohorte de instalación]", en: " [temporal corroboration: this file's ctime falls {days} days after the install cohort]"},

	// J0W-DB (capa L7, dbscan: correlación con el estado de la base de datos)
	"db001.observed":             {es: "cuenta privilegiada {username} con anomalía: {reasons}", en: "privileged account {username} with anomaly: {reasons}"},
	"db001.compared":             {es: "estado esperado de una cuenta con privilegios de Super Usuario (registro dentro de la cohorte de instalación, flags coherentes)", en: "expected state of a Super User account (registered within the install cohort, coherent flags)"},
	"db001.rationale":            {es: "una cuenta con privilegios administrativos registrada fuera de la cohorte de instalación, o con flags de activación incoherentes, es indicio de una cuenta plantada o secuestrada", en: "a privileged account registered outside the install cohort, or with incoherent activation flags, is a sign of a planted or hijacked account"},
	"db001.alt":                  {es: "alta legítima tardía de un nuevo administrador, o migración de datos que dejó flags atípicos", en: "a legitimate late signup of a new administrator, or a data migration that left atypical flags"},
	"db002.observed":             {es: "extensión {element} habilitada en la base de datos pero ausente del árbol de archivos", en: "extension {element} enabled in the database but absent from the file tree"},
	"db002.compared":             {es: "extensiones habilitadas en BD con presencia correspondiente en disco", en: "extensions enabled in the DB with matching presence on disk"},
	"db002.rationale":            {es: "una extensión habilitada sin archivos en disco no puede ejecutar código propio legítimo; puede ser el registro residual de una desinstalación a medias, o el habilitador BD-only de una puerta trasera ajena al árbol de extensiones esperado", en: "an extension enabled with no files on disk cannot run legitimate code of its own; it may be the residual record of a half-finished uninstall, or the DB-only enabler for a backdoor outside the expected extension tree"},
	"db002.alt":                  {es: "desinstalación incompleta que dejó el registro de la base de datos sin limpiar", en: "an incomplete uninstall that left the database record uncleaned"},
	"db003.observed":             {es: "contenido de módulo (#__modules) con patrón de payload ejecutable", en: "module content (#__modules) with an executable payload pattern"},
	"db003.compared":             {es: "contenido de módulo sin código ejecutable embebido", en: "module content without embedded executable code"},
	"db003.rationale":            {es: "el contenido de un módulo se renderiza directamente en cada petición; un payload ejecutable ahí persiste sin necesidad de subir ningún archivo al árbol", en: "module content renders directly on every request; an executable payload there persists without needing to upload any file to the tree"},
	"corroboration.db_extension": {es: " [correlación de BD: la extensión {element} está habilitada en la base de datos]", en: " [DB correlation: extension {element} is enabled in the database]"},
}
