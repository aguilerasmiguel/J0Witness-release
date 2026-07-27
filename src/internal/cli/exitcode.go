// Package cli implementa la interfaz de línea de comandos (contrato en
// contracts/cli.md). stdout es solo el resultado; stderr lleva progreso y
// errores (FR-046, Principio X).
package cli

import "fmt"

// ExitCode implementa contracts/exit-codes.md. Contrato público estable.
type ExitCode int

const (
	ExitOKClean             ExitCode = 0
	ExitOKFindings          ExitCode = 1
	ExitUsageError          ExitCode = 2
	ExitPreflightFailed     ExitCode = 3
	ExitBaselineUnavailable ExitCode = 4
	ExitMultipleRoots       ExitCode = 5
	ExitVersionUnsupported  ExitCode = 6
	ExitVersionInconclusive ExitCode = 7
	ExitBaselineUntrusted   ExitCode = 8
	ExitInternalError       ExitCode = 10
)

// Name devuelve el nombre estable del código.
func (c ExitCode) Name() string {
	switch c {
	case ExitOKClean:
		return "OK_CLEAN"
	case ExitOKFindings:
		return "OK_FINDINGS"
	case ExitUsageError:
		return "USAGE_ERROR"
	case ExitPreflightFailed:
		return "PREFLIGHT_FAILED"
	case ExitBaselineUnavailable:
		return "BASELINE_UNAVAILABLE"
	case ExitMultipleRoots:
		return "MULTIPLE_ROOTS"
	case ExitVersionUnsupported:
		return "VERSION_UNSUPPORTED"
	case ExitVersionInconclusive:
		return "VERSION_INCONCLUSIVE"
	case ExitBaselineUntrusted:
		return "BASELINE_UNTRUSTED"
	case ExitInternalError:
		return "INTERNAL_ERROR"
	}
	return "UNKNOWN"
}

// ExitError transporta un código de salida con detalle; main lo mapea a
// os.Exit tras emitir la línea final legible por máquina.
type ExitError struct {
	Code   ExitCode
	Detail string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit=%d reason=%s detail=%s", e.Code, e.Code.Name(), e.Detail)
}

// Exitf construye un ExitError con formato.
func Exitf(code ExitCode, format string, args ...any) *ExitError {
	return &ExitError{Code: code, Detail: fmt.Sprintf(format, args...)}
}
