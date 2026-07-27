# Diagrams · Diagramas

These are the [Mermaid](https://mermaid.js.org/) sources for the diagrams embedded
in [ARCHITECTURE.md](../ARCHITECTURE.md) / [ARQUITECTURA.md](../ARQUITECTURA.md).
They are provided as standalone `.mmd` files so you can render them to SVG/PNG.

Estas son las fuentes [Mermaid](https://mermaid.js.org/) de los diagramas embebidos
en [ARCHITECTURE.md](../ARCHITECTURE.md) / [ARQUITECTURA.md](../ARQUITECTURA.md). Se
proveen como archivos `.mmd` independientes para renderizarlos a SVG/PNG.

| File | Diagram |
|------|---------|
| `pipeline.mmd` | Analysis pipeline L0–L7 / Pipeline de análisis |
| `event-model.mmd` | Observations vs findings / Modelo de eventos |
| `trust-model.mmd` | Embedded catalog as root of trust / Modelo de confianza |
| `output-projections.mmd` | Canonical JSON → json/text/pdf/sarif |

## Rendering / Renderizado

- **Online:** paste any file into <https://mermaid.live>.
- **CLI:** `npx @mermaid-js/mermaid-cli -i pipeline.mmd -o pipeline.svg`
- **GitHub / Markdown viewers** render the ```mermaid``` blocks in the architecture
  docs directly — no tooling needed.
