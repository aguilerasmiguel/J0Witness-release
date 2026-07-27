package layout

import (
	"fmt"
	"strings"

	"j0witness/internal/safefs"
)

// Source indica la procedencia del AdminDir resuelto.
type Source string

const (
	SourceNone     Source = ""              // sin remapeo
	SourceOperator Source = "operator"      // --administrator-dir
	SourceAuto     Source = "auto-detected" // DetectAdmin confiado
)

// Config describe el remapeo del layout resuelto para un árbol.
type Config struct {
	AdminDir string // dir real de admin ("" = estándar/sin remapeo). p.ej. "adm1ng"
	ApiDir   string // dir real de api ("" = estándar). Solo por flag.
	Source   Source // procedencia del AdminDir
	// NonstandardUnresolved: DetectAdmin halló que administrator/ no es estándar
	// pero NO se pudo remapear (ambiguo/ninguno y sin flag) → J0W-LAYOUT-001.
	NonstandardUnresolved bool
	AdminDirFound         string // candidato hallado por DetectAdmin (para el aviso 2c)
}

// RemapApplied indica si este Config remapea algún directorio real a su forma
// canónica (admin y/o api).
func (c Config) RemapApplied() bool { return c.AdminDir != "" || c.ApiDir != "" }

// Canonicalize reescribe una ruta REAL del árbol a su forma canónica
// (<adm>/… → administrator/…, <api>/… → api/…). Identidad si no hay remapeo,
// y también para cualquier ruta fuera del/los dir(es) remapeados.
func (c Config) Canonicalize(rel string) string {
	if c.AdminDir != "" {
		if remapped, ok := rewritePrefix(rel, c.AdminDir, "administrator"); ok {
			return remapped
		}
	}
	if c.ApiDir != "" {
		if remapped, ok := rewritePrefix(rel, c.ApiDir, "api"); ok {
			return remapped
		}
	}
	return rel
}

// Realize es la inversa de Canonicalize: canónica → real (administrator/… →
// <adm>/…). Solo la usa el renderizador del informe e inventory.
func (c Config) Realize(rel string) string {
	if c.AdminDir != "" {
		if remapped, ok := rewritePrefix(rel, "administrator", c.AdminDir); ok {
			return remapped
		}
	}
	if c.ApiDir != "" {
		if remapped, ok := rewritePrefix(rel, "api", c.ApiDir); ok {
			return remapped
		}
	}
	return rel
}

// rewritePrefix reescribe rel de from a to, respetando el límite de
// directorio: solo casa si rel==from o rel tiene el prefijo "from/" exacto
// (p.ej. "adm1ngtail/x" NO casa con from="adm1ng").
func rewritePrefix(rel, from, to string) (string, bool) {
	if rel == from {
		return to, true
	}
	if strings.HasPrefix(rel, from+"/") {
		return to + rel[len(from):], true
	}
	return "", false
}

// Resolve determina el Config desde los flags y el árbol. adminFlag/apiFlag
// vacíos = no forzado. Valida existencia/esqueleto y detecta colisión.
// Error = fallo de uso (el operador aseveró algo falso, o el árbol es
// ambiguo).
func Resolve(fsys *safefs.FS, adminFlag, apiFlag string) (Config, error) {
	var cfg Config

	// adminFlag == "administrator" es explícitamente el nombre canónico: no
	// hay remapeo que hacer (Canonicalize sería identidad de todos modos), así
	// que se trata igual que "sin flag" — corre auto-detección/estándar en vez
	// de fijar AdminDir/Source y disparar RemapApplied()==true de forma
	// espuria (guardia de byte-identidad para árboles estándar).
	if adminFlag != "" && adminFlag != "administrator" {
		if !hasSkeleton(fsys, adminFlag) {
			return Config{}, fmt.Errorf("layout: --administrator-dir=%q no existe o no tiene el esqueleto admin (components/, manifests/, includes/)", adminFlag)
		}
		cfg.AdminDir = adminFlag
		cfg.Source = SourceOperator
	} else {
		res := DetectAdmin(fsys)
		switch {
		case res.Standard:
			// Config{} — sin remapeo.
		case res.AdminDirFound != "":
			cfg.AdminDir = res.AdminDirFound
			cfg.Source = SourceAuto
			cfg.AdminDirFound = res.AdminDirFound
		default:
			cfg.NonstandardUnresolved = true
		}
	}

	// Colisión (Principio VI): si AdminDir apunta a algo distinto de
	// "administrator" y además existe un administrator/ literal en el árbol,
	// canonicalizar chocaría dos directorios reales en un mismo namespace.
	if cfg.AdminDir != "" && cfg.AdminDir != "administrator" {
		if _, err := fsys.ReadDir("administrator"); err == nil {
			return Config{}, fmt.Errorf("layout: colisión — %q se resolvió como dir de admin pero también existe un administrator/ literal en el árbol; no se puede canonicalizar sin ambigüedad", cfg.AdminDir)
		}
	}

	// apiFlag == "api" es el nombre canónico: idéntico razonamiento que arriba
	// para administrator — no fijar ApiDir evita RemapApplied()==true espurio
	// en un árbol por lo demás estándar.
	if apiFlag != "" && apiFlag != "api" {
		if _, err := fsys.ReadDir(apiFlag); err != nil {
			return Config{}, fmt.Errorf("layout: --api-dir=%q no existe: %w", apiFlag, err)
		}
		cfg.ApiDir = apiFlag
		// api es solo-por-flag (no hay auto-detección): si el remapeo de admin
		// no fijó ya una fuente, el operador es siempre la fuente correcta
		// (Principio VII: coverage.layout no debe declarar remap_applied:true
		// con remap_source vacío).
		if cfg.Source == SourceNone {
			cfg.Source = SourceOperator
		}
	}

	// Colisión (Principio VI): análoga a la de admin — si ApiDir apunta a
	// algo distinto de "api" y además existe un api/ literal en el árbol,
	// canonicalizar chocaría dos directorios reales en un mismo namespace.
	if cfg.ApiDir != "" && cfg.ApiDir != "api" {
		if _, err := fsys.ReadDir("api"); err == nil {
			return Config{}, fmt.Errorf("layout: colisión — %q se resolvió como dir de api pero también existe un api/ literal en el árbol; no se puede canonicalizar sin ambigüedad", cfg.ApiDir)
		}
	}

	return cfg, nil
}
