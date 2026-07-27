package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
)

// GlobalFlags son las banderas globales de contracts/cli.md.
type GlobalFlags struct {
	Workdir         string
	CacheDir        string
	AllowNetwork    bool
	Format          string
	Exclusions      string
	Quiet           bool
	Jobs            int
	FuzzyThreshold  int64
	CatalogPath     string // avanzada/oculta: catálogo alternativo (tests, lab)
	FlagFolderExecs bool   // C1 opt-in: ejecutables en carpeta declarada → medium
	AdminDir        string // fase 2d: nombre real de administrator/ si está renombrado
	ApiDir          string // fase 2d: nombre real de api/ si está renombrado
}

// App agrupa el estado compartido de los comandos.
type App struct {
	Flags  GlobalFlags
	Stdout io.Writer
	Stderr io.Writer
}

// Progress emite una línea de progreso parseable a stderr (FR-046).
func (a *App) Progress(format string, args ...any) {
	if a.Flags.Quiet {
		return
	}
	fmt.Fprintf(a.Stderr, "j0witness: "+format+"\n", args...)
}

// ExitLine emite la línea final legible por máquina (siempre, éxito o error).
func (a *App) ExitLine(code ExitCode, detail string) {
	fmt.Fprintf(a.Stderr, "j0witness: exit=%d reason=%s detail=%s\n", code, code.Name(), detail)
}

func defaultWorkdir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".local", "state", "j0witness")
	}
	return ".j0witness-state"
}

func defaultCacheDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".cache", "j0witness")
	}
	return ".j0witness-cache"
}

// NewRoot construye el árbol de comandos.
func NewRoot(app *App) *cobra.Command {
	root := &cobra.Command{
		Use:           "j0witness",
		Short:         "Analizador de integridad y forense offline para instalaciones Joomla",
		Long:          "J0Witness observa y testifica. No repara, no limpia, no restaura.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	pf := root.PersistentFlags()
	pf.StringVar(&app.Flags.Workdir, "workdir", defaultWorkdir(), "directorio de estado (inventario); nunca dentro del objetivo")
	pf.StringVar(&app.Flags.CacheDir, "cache-dir", defaultCacheDir(), "caché de baselines")
	pf.BoolVar(&app.Flags.AllowNetwork, "allow-network", false, "autoriza acceso a red (enumerado antes de ejecutarse)")
	pf.StringVar(&app.Flags.Format, "format", "json", "formato de salida: json|text|pdf|sarif")
	pf.StringVar(&app.Flags.Exclusions, "exclusions", "", "archivo de exclusiones declarativo (motivo obligatorio)")
	pf.BoolVar(&app.Flags.Quiet, "quiet", false, "suprime el progreso en stderr")
	pf.IntVar(&app.Flags.Jobs, "jobs", runtime.NumCPU(), "paralelismo de hashing en L0")
	pf.Int64Var(&app.Flags.FuzzyThreshold, "fuzzy-threshold", 10<<20, "umbral superior en bytes para el hash difuso")
	pf.StringVar(&app.Flags.CatalogPath, "catalog", "", "catálogo alternativo (avanzado)")
	_ = pf.MarkHidden("catalog")
	pf.BoolVar(&app.Flags.FlagFolderExecs, "flag-folder-execs", false, "marca a severidad media los ejecutables dentro de carpetas declaradas de extensiones (alta tasa de falsos positivos; opt-in)")
	pf.StringVar(&app.Flags.AdminDir, "administrator-dir", "", "nombre real del directorio de administración si está renombrado (relativo a la raíz; p.ej. adm1ng)")
	pf.StringVar(&app.Flags.ApiDir, "api-dir", "", "nombre real del directorio api/ si está renombrado (relativo a la raíz)")

	root.AddCommand(newScanCmd(app))
	root.AddCommand(newInventoryCmd(app))
	root.AddCommand(newBaselineCmd(app))
	root.AddCommand(newExtensionCmd(app))
	root.AddCommand(newReportCmd(app))
	root.AddCommand(newDiffCmd(app))
	root.AddCommand(newRunsCmd(app))
	return root
}

// Main ejecuta la CLI y devuelve el código de salida del proceso.
func Main(args []string, stdout, stderr io.Writer) int {
	app := &App{Stdout: stdout, Stderr: stderr}
	root := NewRoot(app)
	root.SetArgs(args)
	root.SetOut(stderr) // ayuda/uso van a stderr; stdout es solo el resultado
	root.SetErr(stderr)

	err := root.Execute()
	if err == nil {
		app.ExitLine(ExitOKClean, "")
		return int(ExitOKClean)
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		app.ExitLine(ee.Code, ee.Detail)
		return int(ee.Code)
	}
	// Errores de parsing de cobra → USAGE_ERROR; el resto, internos.
	if isUsageError(err) {
		app.ExitLine(ExitUsageError, err.Error())
		return int(ExitUsageError)
	}
	app.ExitLine(ExitInternalError, err.Error())
	return int(ExitInternalError)
}

func isUsageError(err error) bool {
	msg := err.Error()
	for _, s := range []string{"unknown command", "unknown flag", "invalid argument", "requires at least", "accepts"} {
		if len(msg) >= len(s) && contains(msg, s) {
			return true
		}
	}
	return false
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
