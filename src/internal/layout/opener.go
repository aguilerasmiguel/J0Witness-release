package layout

import (
	"os"

	"j0witness/internal/safefs"
)

// Opener abre una ruta relativa de solo lectura. *safefs.FS ya satisface
// esta interfaz (mismo método, mismo tipo de retorno); RealizingOpener
// también, envolviéndolo. Los paquetes consumidores (extmap, fingerprint)
// declaran su propia interfaz estructuralmente idéntica en vez de importar
// layout (evita que capas de análisis genéricas dependan del concepto de
// layout), pero el tipo concreto que de verdad hace el trabajo vive aquí,
// junto a Config/Realize, para no repetir la envoltura en cada sitio de
// lectura (fase 2d, Task 6, fix round 1).
type Opener interface {
	Open(rel string) (*os.File, error)
}

// RealizingOpener envuelve un Opener del árbol REAL (típicamente
// *safefs.FS) revirtiendo con Cfg.Realize cualquier ruta CANÓNICA antes de
// abrirla. Tras la adquisición (fase 2d, Task 1-3), toda ruta que circula
// por las capas de análisis (corediff, extmap, fingerprint, codescan) es
// canónica (administrator/…, api/…); si hubo remapeo, esas rutas no existen
// tal cual en disco (el árbol real tiene adm1ng/…, <api>/…), así que
// cualquier relectura de contenido posterior a la adquisición DEBE pasar
// por aquí — abrir la ruta canónica directamente contra el árbol real falla
// silenciosamente (o, peor, se malinterpreta como manifiesto ilegible/
// archivo binario) en cualquier árbol renombrado.
//
// Cuando Cfg no remapea nada (Config{}, el caso estándar), Realize es
// identidad: RealizingOpener es un passthrough transparente y el
// comportamiento es byte-idéntico al de abrir Under directamente.
type RealizingOpener struct {
	Under Opener
	Cfg   Config
}

// NewRealizingOpener construye un RealizingOpener sobre fsys con cfg.
func NewRealizingOpener(fsys *safefs.FS, cfg Config) *RealizingOpener {
	return &RealizingOpener{Under: fsys, Cfg: cfg}
}

// Open revierte rel (canónica) a la ruta real (Cfg.Realize) y la abre en
// Under.
func (r *RealizingOpener) Open(rel string) (*os.File, error) {
	return r.Under.Open(r.Cfg.Realize(rel))
}
