package provenance

import "testing"

// T046 (Principio VII): mtime posterior a ctime con margen = timestomping;
// con indicadores, el modelo declarado se degrada.
func TestTimestampAnomaly(t *testing.T) {
	base := int64(1_700_000_000_000_000_000)
	if TimestampAnomaly(base, base) {
		t.Fatal("timestamps iguales no son anomalía")
	}
	if TimestampAnomaly(base, base+10_000_000_000) {
		t.Fatal("mtime <= ctime es lo normal")
	}
	if !TimestampAnomaly(base+10_000_000_000, base) {
		t.Fatal("mtime muy posterior a ctime debe ser anomalía")
	}
	if TimestampAnomaly(base+1_000_000_000, base) {
		t.Fatal("1s de margen está dentro de la tolerancia")
	}
}

func TestAssess(t *testing.T) {
	if Assess(nil) != ModelPrimary {
		t.Fatal("sin indicadores el modelo es el primario")
	}
	if Assess([]ThreatIndicator{{Kind: "timestamp_anomaly"}}) != ModelDegraded {
		t.Fatal("con indicadores el modelo debe degradarse")
	}
}
