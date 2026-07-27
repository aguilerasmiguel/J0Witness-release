package cli

import "testing"

// T017: la tabla completa de contracts/exit-codes.md, código a código.
func TestExitCodeTable(t *testing.T) {
	want := map[ExitCode]string{
		0:  "OK_CLEAN",
		1:  "OK_FINDINGS",
		2:  "USAGE_ERROR",
		3:  "PREFLIGHT_FAILED",
		4:  "BASELINE_UNAVAILABLE",
		5:  "MULTIPLE_ROOTS",
		6:  "VERSION_UNSUPPORTED",
		7:  "VERSION_INCONCLUSIVE",
		8:  "BASELINE_UNTRUSTED",
		10: "INTERNAL_ERROR",
	}
	for code, name := range want {
		if got := code.Name(); got != name {
			t.Errorf("código %d: %s ≠ %s", code, got, name)
		}
	}
	if (ExitCode(99)).Name() != "UNKNOWN" {
		t.Error("código desconocido debe ser UNKNOWN")
	}
}

func TestExitErrorFormat(t *testing.T) {
	e := Exitf(ExitBaselineUnavailable, "falta %s", "5.1.4")
	want := "exit=4 reason=BASELINE_UNAVAILABLE detail=falta 5.1.4"
	if e.Error() != want {
		t.Fatalf("%q ≠ %q", e.Error(), want)
	}
}
