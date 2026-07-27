// Package observe define la unidad atómica del modelo de datos (Principio II):
// la observación. Una observación es un hecho constatado sobre un sujeto, con
// fuente, evidencia, confianza y momento. Las observaciones contradictorias
// coexisten; la resolución es de la capa de análisis.
package observe

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Type es la taxonomía cerrada de tipos de observación (data-model.md).
type Type string

const (
	EntryStat           Type = "entry_stat"
	EntryHashed         Type = "entry_hashed"
	FuzzyHashSkipped    Type = "fuzzy_hash_skipped"
	ReadDenied          Type = "read_denied"
	SymlinkOutOfTree    Type = "symlink_out_of_tree"
	HardlinkCycle       Type = "hardlink_cycle"
	TypeMismatch        Type = "type_mismatch"
	NonUTF8Path         Type = "non_utf8_path"
	VersionWitnessMatch Type = "version_witness_match"
	VersionDeclared     Type = "version_declared"
	VersionInferred     Type = "version_inferred"
	MixedVersions       Type = "mixed_versions_detected"
	BaselineVerified    Type = "baseline_verified"
	BaselineMissing     Type = "baseline_missing"
	FileIdentical       Type = "file_identical"
	FileModified        Type = "file_modified"
	FileMissing         Type = "file_missing"
	FileUnexpected      Type = "file_unexpected"
	FileObsoleteKnown   Type = "file_obsolete_known"
	EOLNormalization    Type = "eol_normalization_only"
	ConfigStructure     Type = "config_structure"
	MultipleRoots       Type = "multiple_roots_detected"

	// L3 (feature 002): extensiones y mapa de propiedad.
	ExtDiscovered         Type = "ext_discovered"
	ExtOwnsPath           Type = "ext_owns_path"
	ExtOwnsFolderExec     Type = "ext_owns_folder_exec"
	ExtUndeclared         Type = "ext_undeclared"
	ExtDeclaredMissing    Type = "ext_declared_missing"
	ExtManifestMissing    Type = "ext_manifest_missing"
	ExtManifestMalformed  Type = "ext_manifest_malformed"
	ExtManifestSuspicious Type = "ext_manifest_suspicious"
	ExtOwnershipConflict  Type = "ext_ownership_conflict"
	ExtCoreBundled        Type = "ext_core_bundled"

	// L4 (feature 003): análisis estático de contenido.
	CodeSuspicious Type = "code_suspicious"

	// L5 (feature 008): análisis de directivas de config del servidor.
	ConfigDirective Type = "config_directive_suspicious"

	// L6 (feature 009): análisis temporal (timeline).
	TimeManipulation Type = "time_manipulation"
	CtimeOutlier     Type = "ctime_outlier"

	// Fase 2a: verificación de extensiones contra el paquete oficial.
	ExtFileVerified    Type = "ext_file_verified"
	ExtFileModified    Type = "ext_file_modified"
	ExtOfficialMissing Type = "ext_official_missing"

	// Fase 2d (task 4): resolución de layout (operador o auto-detect) sobre el
	// árbol completo (sujeto vacío), no sobre un archivo concreto. Reemplaza a
	// la layout_nonstandard de fase 2c: ahora declara también el remapeo
	// (admin_dir/api_dir/remap_source), no solo el hecho de ser no estándar.
	LayoutRemap Type = "layout_remap"

	// capa L7 (dbscan): correlación con el estado de la BD.
	DBPrivilegedAnomaly Type = "db_privileged_anomaly"
	DBExtensionState    Type = "db_extension_state"
	DBContentPayload    Type = "db_content_payload"
)

// Confidence es el nivel de confianza obligatorio (Principio V).
type Confidence string

const (
	High   Confidence = "high"
	Medium Confidence = "medium"
	Low    Confidence = "low"
)

// Source identifica la capa emisora.
type Source string

const (
	SrcAcquire     Source = "acquire"
	SrcFingerprint Source = "fingerprint"
	SrcBaseline    Source = "baseline"
	SrcCorediff    Source = "corediff"
	SrcExtmap      Source = "extmap"
	SrcCodescan    Source = "codescan"
	SrcConfscan    Source = "confscan"
	SrcTimeline    Source = "timeline"
	SrcDB          Source = "db"
)

// Observation es la tupla (sujeto, tipo, evidencia, fuente, confianza,
// momento_observado). NUNCA archivo → {modificado: true}.
type Observation struct {
	ID             int64
	Subject        []byte // normalmente rel_path crudo; vacío = la instalación
	SubjectDisplay string
	Type           Type
	EvidenceJSON   string // JSON canónico, ya redactado antes de construirse
	Source         Source
	Confidence     Confidence
	ObservedAtNS   int64
}

// New construye una observación con la evidencia serializada canónicamente
// (encoding/json ordena las claves de mapa: determinista). La evidencia DEBE
// llegar ya redactada: este constructor es posterior a la barrera de
// redacción, no la sustituye.
func New(subject []byte, typ Type, evidence map[string]any, src Source, conf Confidence, atNS int64) (Observation, error) {
	if evidence == nil {
		evidence = map[string]any{}
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return Observation{}, fmt.Errorf("evidencia no serializable para %s: %w", typ, err)
	}
	return Observation{
		Subject:        subject,
		SubjectDisplay: DisplayPath(subject),
		Type:           typ,
		EvidenceJSON:   string(raw),
		Source:         src,
		Confidence:     conf,
		ObservedAtNS:   atNS,
	}, nil
}

// DisplayPath convierte una ruta cruda (posiblemente no UTF-8 o con saltos de
// línea) en una representación segura para salida, sin romper el informe.
func DisplayPath(raw []byte) string {
	if utf8.Valid(raw) && !strings.ContainsAny(string(raw), "\n\r") {
		return string(raw)
	}
	var b strings.Builder
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRune(raw[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, "\\x%02x", raw[i])
			i++
		case r == '\n':
			b.WriteString("\\n")
			i += size
		case r == '\r':
			b.WriteString("\\r")
			i += size
		default:
			b.WriteRune(r)
			i += size
		}
	}
	return b.String()
}
