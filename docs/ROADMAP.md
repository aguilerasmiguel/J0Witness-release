# Roadmap · Trabajo futuro

*English below · Español más abajo.*

This is a list of **possible** future work, not a committed schedule. Each item is
scoped to preserve the project's principles (offline, deterministic, evidence
immutable, false-positive-averse). Items are grouped by which limitation they
relax — see the "Scope and limitations" section of the README for context.

---

## English

### Closing blind spots

- **Upstream supply-chain trust (GPG).** Baseline integrity is already verified
  against the embedded catalog at scan time. The next axis is verifying that the
  catalog itself reflects the package Joomla actually signed — i.e. checking the
  official package against Joomla's GPG signature when ingesting it. This narrows
  the "compromise upstream of the baseline you feed it" gap.
- **Deeper database-layer coverage (L7).** The current DB correlation covers
  privileged-account anomalies, extension state, and executable payloads in
  modules. Natural extensions: `#__scheduler_tasks` and `#__action_logs` as
  corroboration signals; malicious content in articles / custom fields (currently
  only modules are scanned for payloads).
- **Multi-file temporal correlation (L6).** Today the timeline layer flags
  per-file timestomping and annotates cohort outliers. A stronger signal is
  "these N files share a ctime within a few seconds, outside the install cohort" —
  evidence of a *campaign* rather than isolated events.
- **Version coverage of unsupported branches.** The embedded catalog covers a
  bounded set of releases (exit codes `6`/`7` flag versions outside it). The most
  valuable population to cover is precisely the *unsupported* one: an end-of-life
  Joomla 3.x that nobody updated is far likelier to be compromised than an
  up-to-date 5.x — the well-patched site is the one that needs this tool least.
  Prioritizing catalog coverage of the older, abandoned branches targets the sites
  that actually need it.

### Incident-response ergonomics

- **Sensitivity / IR mode (`--sensitivity`).** The engine defaults to degrading
  toward silence — the correct posture for CI and monitoring, where noise kills
  adoption. For hands-on incident response the asymmetry inverts: the analyst wants
  to *see* the low-confidence observations and triage them, because a missed
  backdoor costs far more than a few files discarded in two minutes. Because
  verdicts are **derived by query** over the stored observations, this is nearly
  free — a change to the query threshold, not to the engine. An IR mode would
  surface the sub-threshold observations, clearly marked as such, without touching
  the conservative default that CI and monitoring rely on.

### Extending existing layers

- **More server-config surface (L5).** `php.ini` and additional `.htaccess`
  directives (beyond the current execution-loader / handler-widening / dangerous
  PHP-setting set).
- **Renamed `api/` auto-detection.** The admin directory is already auto-detected
  when renamed; the `api/` directory currently relies on an explicit flag.

### Output and integration

- **SARIF for the newer coverage blocks.** The PDF renderer already surfaces
  `foreign_roots`, `baseline_verification`, `database`, and `timeline`; the SARIF
  projection could carry the same context in its `properties`/`invocation`.
- **Drift document projections.** The scan-to-scan `diff` currently renders JSON
  and text; PDF/SARIF projections of the drift document are a natural addition.

### Platform

- **Non-Linux targets.** The code is portable Go; macOS/Windows are untested. The
  main work is validating the filesystem-metadata and timestamp semantics the
  timeline layer depends on.

### Explicit non-goals

These are deliberately *out* of scope and are not planned:

- Repairing, cleaning, quarantining, or restoring the analyzed tree.
- Connecting to a live database, live process, or the network during a scan
  (beyond the single authorized baseline fetch).
- Executing any analyzed code.
- Backdating detection (`mtime << ctime`) — indistinguishable from a normally
  extracted archive.
- **Maintaining a comprehensive hash catalog of third-party extensions.** Most
  Joomla compromises enter through a vulnerable third-party extension, so a curated
  hash database of the whole extension ecosystem would be a genuine moat — and a
  perpetual, thankless maintenance burden that would strain the offline /
  self-contained guarantee. It is a conscious out-of-scope decision: L3 verifies an
  extension against its official package **only when that package is cached**, and
  otherwise attributes and contextualizes rather than deeply verifying.
- Becoming a general-purpose AV/EDR. J0Witness is one forensic evidence source.

---

## Español

### Cerrar puntos ciegos

- **Confianza de cadena de suministro aguas arriba (GPG).** La integridad del
  baseline ya se verifica contra el catálogo embebido en tiempo de scan. El
  siguiente eje es verificar que el catálogo mismo refleja el paquete que Joomla
  realmente firmó — es decir, comprobar el paquete oficial contra la firma GPG de
  Joomla al incorporarlo. Esto estrecha el hueco de "compromiso aguas arriba del
  baseline que le das".
- **Cobertura más profunda de la capa de BD (L7).** La correlación de BD actual
  cubre anomalías de cuentas privilegiadas, estado de extensiones y payloads
  ejecutables en módulos. Extensiones naturales: `#__scheduler_tasks` y
  `#__action_logs` como señales de corroboración; contenido malicioso en
  artículos / campos personalizados (hoy solo se escanean módulos en busca de
  payloads).
- **Correlación temporal multi-archivo (L6).** Hoy la capa temporal marca
  timestomping por archivo y anota outliers de cohorte. Una señal más fuerte es
  "estos N archivos comparten un ctime en pocos segundos, fuera de la cohorte de
  instalación" — evidencia de una *campaña* en vez de eventos aislados.
- **Cobertura de versiones de ramas sin soporte.** El catálogo embebido cubre un
  conjunto acotado de releases (los códigos de salida `6`/`7` marcan versiones
  fuera de él). La población más valiosa de cubrir es justo la *sin soporte*: un
  Joomla 3.x fin-de-vida que nadie actualizó es mucho más probable que esté
  comprometido que un 5.x al día — el sitio bien parcheado es el que menos necesita
  esta herramienta. Priorizar la cobertura del catálogo hacia las ramas viejas y
  abandonadas apunta a los sitios que de verdad la necesitan.

### Ergonomía de respuesta a incidentes

- **Modo de sensibilidad / IR (`--sensitivity`).** El motor por defecto degrada
  hacia el silencio — la postura correcta para CI y monitorización, donde el ruido
  mata la adopción. En respuesta a incidentes a mano la asimetría se invierte: el
  analista quiere *ver* las observaciones de baja confianza y triarlas, porque un
  backdoor que no reportas cuesta mucho más que unos archivos que descarta en dos
  minutos. Como los veredictos se **derivan por consulta** sobre las observaciones
  almacenadas, esto es casi gratis — un cambio en el umbral de la consulta, no en el
  motor. Un modo IR sacaría las observaciones por debajo del umbral, marcadas como
  tales, sin tocar el default conservador del que dependen CI y monitorización.

### Extender capas existentes

- **Más superficie de config del servidor (L5).** `php.ini` y directivas
  adicionales de `.htaccess` (más allá del set actual de cargador-de-ejecución /
  ampliación-de-handler / ajuste-PHP-peligroso).
- **Auto-detección de `api/` renombrado.** El directorio de administración ya se
  auto-detecta cuando está renombrado; el directorio `api/` hoy depende de un flag
  explícito.

### Salida e integración

- **SARIF para los bloques de cobertura nuevos.** El renderizador PDF ya expone
  `foreign_roots`, `baseline_verification`, `database` y `timeline`; la proyección
  SARIF podría llevar el mismo contexto en sus `properties`/`invocation`.
- **Proyecciones del documento de deriva.** El `diff` scan-a-scan hoy renderiza
  JSON y texto; proyecciones PDF/SARIF del documento de deriva son una adición
  natural.

### Plataforma

- **Objetivos no-Linux.** El código es Go portable; macOS/Windows no están
  probados. El trabajo principal es validar la semántica de metadatos del sistema
  de archivos y de timestamps de la que depende la capa temporal.

### No-objetivos explícitos

Están deliberadamente *fuera* de alcance y no están planificados:

- Reparar, limpiar, poner en cuarentena o restaurar el árbol analizado.
- Conectarse a una base de datos viva, un proceso vivo o la red durante un scan
  (más allá de la única descarga autorizada del baseline).
- Ejecutar cualquier código analizado.
- Detección de backdating (`mtime << ctime`) — indistinguible de un tarball
  extraído normalmente.
- **Mantener un catálogo de hashes exhaustivo de las extensiones de terceros.** La
  mayoría de los compromisos de Joomla entran por una extensión de terceros
  vulnerable, así que una base de datos curada de hashes de todo el ecosistema de
  extensiones sería un foso real — y una carga de mantenimiento perpetua e ingrata
  que tensaría la garantía offline / autocontenida. Es una decisión consciente de
  fuera-de-alcance: L3 verifica una extensión contra su paquete oficial **solo
  cuando ese paquete está cacheado**, y si no, atribuye y contextualiza en vez de
  verificar en profundidad.
- Convertirse en un AV/EDR de propósito general. J0Witness es una fuente de
  evidencia forense.
