package drift

import (
	"bytes"
	"fmt"

	"j0witness/internal/report"
)

// RenderJSON serializa el DriftReport de forma canónica (Principio IV): dos
// espacios de sangría, sin escapar HTML, LF final único — vía
// report.CanonicalMarshal, la misma garantía de determinismo que el informe
// L0-L4. Si Compare no puso SchemaVersion (o se construyó el struct a mano),
// se completa aquí con el contrato propio del doc de deriva (drift.SchemaVersion).
func (d DriftReport) RenderJSON() ([]byte, error) {
	if d.SchemaVersion == "" {
		d.SchemaVersion = SchemaVersion
	}
	return report.CanonicalMarshal(d)
}

// RenderText proyecta el DriftReport a texto legible para humano. Itera las
// listas TAL CUAL las dejó Compare (ya ordenadas por Path/Subject,ID) — nunca
// las reordena ni recorre un map, para no introducir no-determinismo aquí.
//
// v1 no es bilingüe (no-objetivo explícito del diseño): la prosa fija va en
// español, igual que el resto del doc de deriva.
func (d DriftReport) RenderText() ([]byte, error) {
	var b bytes.Buffer

	fmt.Fprintf(&b, "Deriva: %s\n", d.New.Target)
	fmt.Fprintf(&b, "  run %d (%s) -> run %d (%s)\n",
		d.Old.RunID, d.Old.FinishedAt, d.New.RunID, d.New.FinishedAt)
	b.WriteString("\n")

	fmt.Fprintf(&b, "Añadidos (%d)\n", len(d.Entries.Added))
	for _, e := range d.Entries.Added {
		fmt.Fprintf(&b, "  %s\n", e.Path)
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "Eliminados (%d)\n", len(d.Entries.Removed))
	for _, e := range d.Entries.Removed {
		fmt.Fprintf(&b, "  %s\n", e.Path)
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "Modificados (%d)\n", len(d.Entries.Changed))
	for _, e := range d.Entries.Changed {
		fmt.Fprintf(&b, "  %s\n", e.Path)
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "Movidos (%d)\n", len(d.Entries.Moved))
	for _, e := range d.Entries.Moved {
		fmt.Fprintf(&b, "  %s -> %s\n", e.OldPath, e.Path)
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "Metadatos (%d)\n", len(d.Entries.MetadataChanged))
	for _, e := range d.Entries.MetadataChanged {
		fmt.Fprintf(&b, "  %s\n", e.Path)
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "Churn de runtime: %d\n\n", d.Entries.RuntimeChurn)

	fmt.Fprintf(&b, "Hallazgos nuevos (%d)\n", len(d.Findings.New))
	for _, f := range d.Findings.New {
		fmt.Fprintf(&b, "  [%s] %s %s\n", f.Severity, f.RuleID, f.Subject)
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "Hallazgos resueltos (%d)\n", len(d.Findings.Resolved))
	for _, f := range d.Findings.Resolved {
		fmt.Fprintf(&b, "  [%s] %s %s\n", f.Severity, f.RuleID, f.Subject)
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "Persistentes: %d\n\n", d.Findings.Persistent)

	b.WriteString("Salvedades\n")
	for _, c := range d.Caveats {
		fmt.Fprintf(&b, "  - %s\n", c)
	}

	return b.Bytes(), nil
}

// ExitCode traduce el DriftReport al código de salida del subcomando de
// diff: 1 si apareció al menos un hallazgo nuevo, 0 en caso contrario. No
// depende de entries (added/removed/etc. por sí solos no son "hallazgo").
func (d DriftReport) ExitCode() int {
	if len(d.Findings.New) > 0 {
		return 1
	}
	return 0
}
