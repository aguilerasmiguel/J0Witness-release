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
- Convertirse en un AV/EDR de propósito general. J0Witness es una fuente de
  evidencia forense.
