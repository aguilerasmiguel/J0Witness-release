# J0Witness

![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)
![CGO](https://img.shields.io/badge/CGO-free-2ea44f)
![Binario](https://img.shields.io/badge/binario-est%C3%A1tico%20%C3%BAnico-2ea44f)
![Red](https://img.shields.io/badge/red-offline%20por%20defecto-4c9be8)
![Build](https://img.shields.io/badge/build-reproducible-2ea44f)
![Determinismo](https://img.shields.io/badge/salida-determinista-2ea44f)
![Plataforma](https://img.shields.io/badge/plataforma-linux%20amd64%20%7C%20arm64-lightgrey)
![Informes](https://img.shields.io/badge/informes-json%20%7C%20text%20%7C%20pdf%20%7C%20sarif-informational)
![i18n](https://img.shields.io/badge/i18n-es%20%7C%20en-informational)
![Licencia](https://img.shields.io/badge/licencia-MIT-2ea44f)

> **Léelo en otros idiomas:** [English](README.md)

**J0Witness es un analizador de integridad y forense *offline* para instalaciones
Joomla.**

Determina —sin que el sitio esté vivo y sin necesidad de un baseline previo
propio— en qué se diferencia una instalación Joomla en disco de la distribución
original del fabricante, y presenta esas diferencias con evidencia y procedencia
suficientes para que un humano decida si hubo compromiso.

> **J0Witness observa y testifica. No repara, no limpia, no restaura.**

---

## Por qué existe

La mayoría de las herramientas de "¿me hackearon el sitio?" o necesitan el sitio
corriendo, o llaman a casa, o mutan la propia evidencia que inspeccionan.
J0Witness se construye al revés:

- **Offline y autocontenido.** Un solo binario estático. Sin runtime de PHP, sin
  base de datos, sin red por defecto. Se copia al host y se ejecuta.
- **El árbol analizado es evidencia — jamás se escribe.** J0Witness solo lee.
- **Nunca ejecuta el código analizado.** Todo el análisis de PHP/config es análisis
  estático de texto; el árbol jamás se corre.
- **Determinista y reproducible.** El mismo (árbol, baseline, binario, flags)
  produce salida byte-idéntica, y el binario es un build reproducible — ambas
  propiedades importan cuando el informe se usa como evidencia.
- **Un falso positivo es un defecto severo.** El motor degrada hacia el silencio en
  vez de gritar; cada hallazgo pretende ser accionable.

## Qué hace

J0Witness compone capas de análisis independientes; cada una lee la evidencia ya
capturada y aporta observaciones. Los veredictos (hallazgos) se **derivan por
consulta** de esas observaciones —nunca se almacenan como verdad primaria— así que
un informe puede re-renderizarse desde un escaneo persistido sin volver a tocar el
árbol.

| Capa | Qué hace | Reglas |
|------|----------|--------|
| **L0** adquisición | Inventario determinista: hash, metadatos, tamaño. Solo lectura. | — |
| **L1** fingerprint | Huella difusa (TLSH) para emparejar modificados con su original. | — |
| **L2** core-diff | Diff contra la distribución oficial de Joomla: añadido / modificado / eliminado del core. | `J0W-CORE-*` |
| **L3** ext-map | Descubre extensiones de terceros por manifiesto y atribuye cada archivo a quien lo declara. | `J0W-EXT-*`, `J0W-LAYOUT-001` |
| **L4** code-scan | Análisis estático de contenido PHP (jamás ejecuta): webshells, ofuscación, cargadores. | `J0W-CODE-*` |
| **L5** conf-scan | Directivas peligrosas en `.htaccess` / `.user.ini` / `web.config`. | `J0W-CONFIG-*` |
| **L6** timeline | Corroboración temporal anclada en ctime (bajo el modelo de amenaza declarado). | `J0W-TIME-001` |
| **L7** db-scan | Correlación con la BD del sitio vía un `mysqldump` aportado (offline, jamás ejecutado). | `J0W-DB-*` |

Además:

- **Deriva scan-a-scan** (`j0witness diff`): compara dos escaneos persistidos del
  mismo sitio — la pregunta de monitorización / respuesta a incidentes, *"¿qué
  cambió desde el último escaneo conocido-bueno?"*.
- **Verificación del baseline en tiempo de scan**: el catálogo embebido es la única
  raíz de confianza; el baseline almacenado y el paquete oficial cacheado se
  re-verifican contra él antes de que el diff confíe, y el scan rechaza en duro
  (`BASELINE_UNTRUSTED`) ante manipulación.
- **Cuatro proyecciones de informe** desde un único JSON canónico: `json` · `text`
  · `pdf` · `sarif` (integración con CI / code-scanning).
- **Informes bilingües**: `--language es|en`.
- **Supresión de falsos positivos**: un archivo de exclusiones declarativo donde el
  motivo es obligatorio y cada supresión se refleja en el propio informe.

## Uso rápido

```sh
# 1. Incorporar el baseline oficial (una vez; offline: el paquete se descarga aparte).
j0witness baseline add Joomla_5.1.4-Stable-Full_Package.zip
#    O, con red autorizada explícitamente:
#    j0witness baseline fetch 5.1.4 --allow-network

# 2. Escanear. stdout = informe JSON canónico; stderr = progreso.
j0witness scan /var/www/mi-sitio > informe.json

# Lectura humana:
j0witness scan /var/www/mi-sitio --format text
j0witness scan /var/www/mi-sitio --format pdf > informe.pdf

# 3. Correlacionar con la base de datos (offline; el dump se parsea, jamás se ejecuta):
j0witness scan /var/www/mi-sitio --db dump.sql --format text

# 4. Monitorización / IR — qué cambió desde el último escaneo:
j0witness runs /var/www/mi-sitio          # lista los escaneos persistidos
j0witness diff /var/www/mi-sitio          # deriva entre los dos más recientes

# 5. Re-renderizar un escaneo persistido sin volver a tocar el árbol:
j0witness report ~/.local/state/j0witness --format sarif
```

Instrucciones de compilación: **[docs/BUILD.md](docs/BUILD.md)**.

## Códigos de salida (contrato estable)

`0` limpio · `1` hallazgos ≥ medium · `2` error de uso · `3` preflight ·
`4` baseline no disponible · `5` múltiples instalaciones · `6/7` versión no
soportada / no concluyente · `8` baseline no confiable (el baseline almacenado no
casa con el catálogo embebido) · `10` error interno.

## Alcance y limitaciones honestas

J0Witness es deliberadamente acotado, y es más útil cuando sabes exactamente qué
puede y qué no puede responder.

**La pregunta que responde bien:** *"¿El árbol en disco coincide con la
distribución conocida-buena del fabricante más las extensiones de terceros
declaradas — y si no, dónde, y con qué evidencia?"*

**Qué detecta:** archivos de core añadidos / modificados / eliminados; patrones de
webshell y ofuscación en PHP (heurístico, estático); ejecutables no declarados
escondidos dentro de una extensión legítimamente instalada; directivas de config
peligrosas; timestomping estructural (`mtime > ctime`); anomalías del estado de la
BD cuando aportas un dump; y deriva entre dos escaneos del mismo sitio.

**Qué *no* hace — léelo antes de confiar en él:**

- **No repara, no limpia, no pone en cuarentena, no restaura.** Observa y testifica.
- **La ausencia de hallazgos no prueba que el sitio esté limpio.** Es evidencia
  sobre el disco, acotada por las capas de abajo.
- **Es ciego al compromiso que vive solo fuera del sistema de archivos** —
  persistencia puramente en base de datos (salvo que aportes un `mysqldump`),
  implantes en memoria/runtime, o estado malicioso en servicios externos. No hay
  inspección de procesos vivos, red ni memoria.
- **El análisis estático de PHP es heurístico.** Está afinado para minimizar falsos
  positivos, lo que significa que puede pasar por alto backdoors novedosos, muy
  ofuscados o puramente lógicos. Es una señal, no una prueba de malicia ni de
  seguridad.
- **La capa de BD jamás se conecta a una base de datos viva.** Correlaciona un
  `mysqldump` offline que tú aportas; si el dump no corresponde al disco, la capa
  degrada y declara el desajuste en vez de emitir ruido.
- **Su verdad de referencia es la distribución oficial y el catálogo embebido.** Lo
  que el fabricante no distribuye (internos de extensiones de terceros, subidas,
  contenido de usuario) se atribuye y contextualiza, no se verifica en profundidad
  más allá del hash del paquete oficial de una extensión cuando está cacheado. Un
  compromiso de cadena de suministro *aguas arriba* del baseline que le das queda
  fuera de su alcance (la integridad del baseline se verifica ahora contra el
  catálogo embebido en tiempo de scan — ver L7 / `BASELINE_UNTRUSTED`).
- **La capa temporal confía en ctime bajo un modelo de amenaza declarado** (un
  atacante con privilegios de www-data, sin root). Un atacante con root que pueda
  reescribir el ctime la vence; el backdating (`mtime << ctime`) es explícitamente
  un no-objetivo porque es indistinguible de un tarball extraído normalmente.
- **Es una fuente de evidencia, no un IR/EDR/AV completo.** Trátalo como
  corroboración forense, no como un motor de veredictos.

**Modelo de amenaza declarado (primario):** un atacante que opera con los
privilegios del servidor web (`www-data`) y sin root. Bajo ese modelo el ctime es
el ancla temporal fiable. Se declara para que el lector juzgue dónde se sostiene.

## Estado y almacenamiento

J0Witness persiste en una **base de datos SQLite embebida** (Go puro
`modernc.org/sqlite` — sin CGO, sin librería del sistema; el motor se compila
dentro del binario). No hay nada que activar: cada `scan` escribe en ella
automáticamente.

Los archivos de la base viven en el **directorio de trabajo** (`--workdir`, por
defecto `~/.local/state/j0witness/`) — jamás dentro del repositorio ni del árbol
analizado:

- `state.sqlite` — el registro de baselines (lo que incorporas con `baseline add`
  / `baseline fetch`). Compartido entre objetivos.
- `inv-<hash>.sqlite` — **uno por objetivo escaneado** (clave = hash de la ruta del
  objetivo). Cada escaneo de ese objetivo añade un *run* a las tablas `runs` /
  `entries` / `observations`. Este es el substrato de eventos que permite que
  `report` re-renderice y `diff` compare **sin volver a tocar el árbol**.

Controla la ubicación con `--workdir`; lista los runs persistidos de un objetivo
con `j0witness runs <objetivo>`. Estos archivos crecen con el tamaño del inventario
y se acumulan entre runs — borrar un `inv-*.sqlite` descarta el historial de
escaneos de ese objetivo (el siguiente scan lo recrea); nunca se escribe dentro del
sitio que analizas.

## Documentación

- **[Arquitectura](docs/ARQUITECTURA.md)** ([English](docs/ARCHITECTURE.md)) — capas, flujo de datos, modelo de confianza, diagramas.
- **[Build](docs/BUILD.md)** — compilar el binario estático único y el gate de reproducibilidad.
- **[Roadmap](docs/ROADMAP.md)** — trabajo futuro planificado y posible.
- **[Fuente](src/)** — el árbol de fuentes Go completo.

## Licencia

Este proyecto se distribuye bajo la Licencia MIT — ver [LICENSE](LICENSE).
