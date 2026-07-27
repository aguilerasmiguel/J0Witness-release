// Package corpus materializa el corpus de laboratorio desde recetas
// declarativas (contracts/corpus-recipe.md, Principio XI): las recetas se
// versionan; los árboles binarios se generan.
package corpus

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Recipe es una receta declarativa de caso de corpus.
type Recipe struct {
	Case string `yaml:"case"`
	Base struct {
		CMS     string `yaml:"cms"`
		Version string `yaml:"version"`
	} `yaml:"base"`
	// ScanArgs son banderas extra para el escaneo del caso (p.ej. forzar
	// versión en instalaciones mixtas).
	ScanArgs  []string   `yaml:"scan_args"`
	Expect    Expect     `yaml:"expect"`
	Mutations []Mutation `yaml:"mutations"`
}

// Expect son las aserciones del test de integración.
type Expect struct {
	ExitCode    int             `yaml:"exit_code"`
	Findings    []ExpectFinding `yaml:"findings"`
	NotFindings []ExpectFinding `yaml:"not_findings"`
}

// ExpectFinding identifica un hallazgo esperado (o prohibido). MinSeverity y
// MaxSeverity acotan la severidad: MinSeverity exige "al menos"; MaxSeverity
// exige "como mucho" (para verificar degradaciones, p.ej. un artefacto de
// runtime que debe quedar en info y no en critical).
type ExpectFinding struct {
	RuleID      string `yaml:"rule_id"`
	Subject     string `yaml:"subject"`
	MinSeverity string `yaml:"min_severity"`
	MaxSeverity string `yaml:"max_severity"`
}

// Mutation es una operación cerrada del contrato.
type Mutation struct {
	Op          string   `yaml:"op"`
	Path        string   `yaml:"path"`
	AfterLine   int      `yaml:"after_line"`
	Content     string   `yaml:"content"`
	Mode        uint32   `yaml:"mode"`
	Target      string   `yaml:"target"`
	Declared    string   `yaml:"declared"`
	FromVersion string   `yaml:"from_version"`
	Version     string   `yaml:"version"`
	Paths       []string `yaml:"paths"`
	Depth       int      `yaml:"depth"`
	At          string   `yaml:"at"`
	Declare     string   `yaml:"declare"` // tamper_manifest: ruta que el manifiesto declarará
	// Kind selecciona, para add_extension/add_extension_baseline (fase 2c,
	// Task 7), CUÁL fixture de laboratorio instalar/cachear: "" o "component"
	// (com_labext, comportamiento 2a sin cambios), "module", "plugin",
	// "template" o "library". Ver MultiExtProvider.
	Kind string `yaml:"kind"`
}

// BaseProvider abstrae la distribución base (minicms en tests herméticos,
// Joomla real desde caché en CI).
type BaseProvider interface {
	WriteBase(dir, version string) error
	FileContent(version, rel string) ([]byte, bool)
}

// ExtProvider es la capacidad opcional para las operaciones de extensión de la
// feature 002. Un provider que la implementa habilita `add_extension` y las
// mutaciones de manifiesto.
type ExtProvider interface {
	// InstallExtension instala una extensión sintética legítima en dir.
	InstallExtension(dir string) error
	// ExtManifestPath devuelve la ruta del manifiesto de esa extensión.
	ExtManifestPath() string
}

// DisplayExtProvider habilita `add_display_named_extension`: instala una
// extensión cuyo `<name>` de display difiere de su directorio instalado
// (regresión de D1).
type DisplayExtProvider interface {
	InstallDisplayExtension(dir string) error
}

// D2Provider habilita `add_d2_fixtures`: instala una librería (raíz por
// <libraryname>), un pack de idioma y un componente que comparte la carpeta de
// idioma (regresión de D2).
type D2Provider interface {
	InstallD2Fixtures(dir string) error
}

// ScriptExtProvider habilita `add_scriptfile_extension`: instala un componente
// con <scriptfile> (script de instalación declarado; regresión de D3).
type ScriptExtProvider interface {
	InstallScriptExtension(dir string) error
}

// ExtBaselineProvider habilita `add_extension_baseline` (fase 2a, Task 6):
// expone el "paquete oficial" sintético de la extensión de laboratorio para
// cachear su baseline en el store de estado del caso ANTES del escaneo.
//
// El cacheo real NO ocurre en apply()/Materialize: Materialize solo escribe
// el árbol de archivos del caso (recibe un BaseProvider y un dir), y no
// conoce el store de estado compartido (state.sqlite en el workdir de la
// CLI) contra el que el scan verifica extensiones. apply() se limita a
// validar que el provider soporta la operación; el harness de integración
// (internal/cli/harness_test.go, scanCase) inspecciona los mutations tras
// Materialize y ejecuta `extension add` (la misma vía que un operador real)
// con el paquete que ExtPackage produce, escribiendo en el MISMO
// state.sqlite que la CLI abrirá al escanear.
type ExtBaselineProvider interface {
	// ExtPackage devuelve el zip del paquete oficial. version, si no está
	// vacío, sustituye la versión declarada en el manifiesto del paquete
	// (recipe de "versión no coincidente": cachea un baseline que nunca
	// calzará con la versión realmente instalada).
	ExtPackage(version string) []byte
}

// MultiExtProvider generaliza ExtProvider/ExtBaselineProvider a los 5 tipos de
// extensión verificables (fase 2c, Task 7): en vez de duplicar add_extension/
// add_extension_baseline por tipo, cada mutación lleva un `kind` opcional
// ("" o "component" preserva EXACTAMENTE el camino 2a de com_labext) que estos
// métodos despachan. Un provider que NO implementa esta interfaz sigue
// funcionando con kind="" vía ExtProvider/ExtBaselineProvider (comportamiento
// sin cambios); solo kind != "" la requiere.
type MultiExtProvider interface {
	// InstallExtensionKind instala la fixture de kind en dir.
	InstallExtensionKind(kind, dir string) error
	// ExtPackageKind devuelve el paquete oficial de la fixture de kind (con
	// sustitución de versión opcional, igual que ExtBaselineProvider.ExtPackage).
	ExtPackageKind(kind, version string) ([]byte, error)
}

// Load parsea una receta.
func Load(path string) (*Recipe, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Recipe
	if err := yaml.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("receta %s: %w", path, err)
	}
	if r.Case == "" || r.Base.Version == "" {
		return nil, fmt.Errorf("receta %s: case y base.version son obligatorios", path)
	}
	return &r, nil
}

// Materialize construye el árbol del caso en dir.
func (r *Recipe) Materialize(p BaseProvider, dir string) error {
	if err := p.WriteBase(dir, r.Base.Version); err != nil {
		return err
	}
	for i, m := range r.Mutations {
		if err := apply(p, dir, m); err != nil {
			return fmt.Errorf("caso %s, mutación %d (%s): %w", r.Case, i+1, m.Op, err)
		}
	}
	return nil
}

// requireWithinCase rechaza una ruta cuyo destino resuelto (full) escape del
// directorio del caso (dir), p.ej. por un path relativo con ".." en la
// receta. Defensa contra una receta malformada, no contra un atacante.
func requireWithinCase(dir, full, rawPath string) error {
	rel, err := filepath.Rel(dir, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("ruta fuera del caso: %s", rawPath)
	}
	return nil
}

func apply(p BaseProvider, dir string, m Mutation) error {
	full := filepath.Join(dir, m.Path)
	if err := requireWithinCase(dir, full, m.Path); err != nil {
		return err
	}
	switch m.Op {
	case "inject_line":
		raw, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		lines := strings.SplitAfter(string(raw), "\n")
		if m.AfterLine < 0 || m.AfterLine > len(lines) {
			return fmt.Errorf("after_line %d fuera de rango", m.AfterLine)
		}
		var b strings.Builder
		for i, l := range lines {
			b.WriteString(l)
			if i+1 == m.AfterLine {
				b.WriteString(m.Content + "\n")
			}
		}
		return os.WriteFile(full, []byte(b.String()), 0o644)
	case "replace_file":
		return os.WriteFile(full, []byte(m.Content), 0o644)
	case "add_file":
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if m.Mode != 0 {
			mode = os.FileMode(m.Mode)
		}
		return os.WriteFile(full, []byte(m.Content), mode)
	case "delete_file":
		return os.Remove(full)
	case "delete_dir":
		// Borra un subárbol ENTERO del árbol del caso (D5c): a diferencia de
		// N delete_file, una sola mutación deja el directorio COMPLETAMENTE
		// ausente (ningún archivo hermano sobrevive), condición que
		// CollapseMissingSubtrees exige para colapsar. Recursivo.
		return os.RemoveAll(full)
	case "crlf":
		raw, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		out := strings.ReplaceAll(string(raw), "\n", "\r\n")
		return os.WriteFile(full, []byte(out), 0o644)
	case "tamper_version":
		// Reescribe las fuentes de versión declarada (US2).
		parts := strings.SplitN(m.Declared, ".", 3)
		if len(parts) != 3 {
			return fmt.Errorf("declared %q no es x.y.z", m.Declared)
		}
		vphp := fmt.Sprintf("<?php\nclass Version {\n    const MAJOR_VERSION = %s;\n    const MINOR_VERSION = %s;\n    const PATCH_VERSION = %s;\n}\n", parts[0], parts[1], parts[2])
		if err := os.WriteFile(filepath.Join(dir, "libraries/src/Version.php"), []byte(vphp), 0o644); err != nil {
			return err
		}
		xml := "<?xml version=\"1.0\"?>\n<extension><version>" + m.Declared + "</version></extension>\n"
		return os.WriteFile(filepath.Join(dir, "administrator/manifests/files/joomla.xml"), []byte(xml), 0o644)
	case "leftover_obsolete":
		content, ok := p.FileContent(m.FromVersion, m.Path)
		if !ok {
			return fmt.Errorf("%s no existe en la versión %s", m.Path, m.FromVersion)
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		return os.WriteFile(full, content, 0o644)
	case "chmod":
		return os.Chmod(full, os.FileMode(m.Mode))
	case "symlink":
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		return os.Symlink(m.Target, full)
	case "overlay_version":
		for _, rel := range m.Paths {
			dst := filepath.Join(dir, rel)
			if err := requireWithinCase(dir, dst, rel); err != nil {
				return err
			}
			content, ok := p.FileContent(m.Version, rel)
			if !ok {
				return fmt.Errorf("%s no existe en la versión %s", rel, m.Version)
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(dst, content, 0o644); err != nil {
				return err
			}
		}
		return nil
	case "deep_tree":
		at := filepath.Join(dir, m.At)
		if err := requireWithinCase(dir, at, m.At); err != nil {
			return err
		}
		for i := 0; i < m.Depth; i++ {
			at = filepath.Join(at, "d")
		}
		if err := os.MkdirAll(at, 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(at, "hoja.txt"), []byte("x"), 0o644)
	case "weird_names":
		at := filepath.Join(dir, m.At)
		if err := requireWithinCase(dir, at, m.At); err != nil {
			return err
		}
		if err := os.MkdirAll(at, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(at, "con\nsalto.txt"), []byte("x"), 0o644); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(at, string([]byte{0xff, 0xfe})+".bin"), []byte("x"), 0o644)

	// Operaciones de extensión (feature 002).
	case "add_extension":
		if m.Kind != "" && m.Kind != "component" {
			mp, ok := p.(MultiExtProvider)
			if !ok {
				return fmt.Errorf("el provider no soporta extensiones de tipo %q", m.Kind)
			}
			return mp.InstallExtensionKind(m.Kind, dir)
		}
		ep, ok := p.(ExtProvider)
		if !ok {
			return fmt.Errorf("el provider no soporta extensiones")
		}
		return ep.InstallExtension(dir)
	case "add_display_named_extension":
		ep, ok := p.(DisplayExtProvider)
		if !ok {
			return fmt.Errorf("el provider no soporta extensiones de nombre de display")
		}
		return ep.InstallDisplayExtension(dir)
	case "add_d2_fixtures":
		ep, ok := p.(D2Provider)
		if !ok {
			return fmt.Errorf("el provider no soporta las fixtures de D2")
		}
		return ep.InstallD2Fixtures(dir)
	case "add_scriptfile_extension":
		ep, ok := p.(ScriptExtProvider)
		if !ok {
			return fmt.Errorf("el provider no soporta extensiones con scriptfile")
		}
		return ep.InstallScriptExtension(dir)
	case "undeclared_file", "undeclared_in_folder":
		// Archivo (webshell) dentro del árbol de la extensión que su manifiesto
		// no declara. La ruta la fija la receta.
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		return os.WriteFile(full, []byte(m.Content), 0o644)
	case "tamper_manifest":
		ep, ok := p.(ExtProvider)
		if !ok {
			return fmt.Errorf("el provider no soporta extensiones")
		}
		return tamperManifest(filepath.Join(dir, ep.ExtManifestPath()), m.Declare)
	case "corrupt_manifest":
		ep, ok := p.(ExtProvider)
		if !ok {
			return fmt.Errorf("el provider no soporta extensiones")
		}
		return os.WriteFile(filepath.Join(dir, ep.ExtManifestPath()), []byte("<extension type=\"component\"><name>roto"), 0o644)
	case "remove_manifest":
		ep, ok := p.(ExtProvider)
		if !ok {
			return fmt.Errorf("el provider no soporta extensiones")
		}
		return os.Remove(filepath.Join(dir, ep.ExtManifestPath()))
	case "add_extension_baseline":
		// No-op a nivel de árbol de archivos (ver ExtBaselineProvider): solo
		// valida que el provider soporta la operación. El cacheo real en el
		// store de estado lo hace el harness de integración tras Materialize.
		if m.Kind != "" && m.Kind != "component" {
			if _, ok := p.(MultiExtProvider); !ok {
				return fmt.Errorf("el provider no soporta baselines de extensión de tipo %q", m.Kind)
			}
			return nil
		}
		if _, ok := p.(ExtBaselineProvider); !ok {
			return fmt.Errorf("el provider no soporta baselines de extensión")
		}
		return nil
	case "rename_dir":
		// Renombra/mueve un directorio completo del árbol (fase 2c, Task 7):
		// la receta de layout-nonstandard lo usa para simular un directorio de
		// administración renombrado (m.Path → m.Target), preservando TODO su
		// contenido (J0W-LAYOUT-001).
		if m.Target == "" {
			return fmt.Errorf("rename_dir: target vacío")
		}
		dst := filepath.Join(dir, m.Target)
		if err := requireWithinCase(dir, dst, m.Target); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.Rename(full, dst)
	}
	return fmt.Errorf("operación desconocida: %s", m.Op)
}

// tamperManifest inserta una declaración <filename> anómala en el manifiesto
// (fuera de las secciones normales, apuntando a un archivo plantado).
func tamperManifest(manifestPath, declarePath string) error {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	inject := "<files folder=\"site\"><filename>" + declarePath + "</filename></files>"
	out := strings.Replace(string(raw), "</extension>", inject+"</extension>", 1)
	return os.WriteFile(manifestPath, []byte(out), 0o644)
}

// LoadDir carga todas las recetas de un directorio, en orden estable.
func LoadDir(dir string) ([]*Recipe, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	var out []*Recipe
	for _, m := range matches {
		r, err := Load(m)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
