package inventory

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite" // driver puro Go, sin CGO (Principio IX)

	"j0witness/internal/observe"
)

const batchSize = 1000

// Entry es una entrada del árbol capturada por L0 (stat completo + hashes).
type Entry struct {
	ID            int64
	RelPath       []byte
	PathDisplay   string
	Type          string // file | dir | symlink | other
	Size          int64
	MtimeNS       int64
	CtimeNS       int64
	AtimeNS       int64
	UID           uint32
	GID           uint32
	Mode          uint32
	Inode         uint64
	Nlink         uint64
	SHA256        string
	TLSH          string
	MagicType     string
	ExtType       string
	SymlinkTarget []byte
	ReadError     string
}

// Store es el almacén SQLite del inventario. Una sola conexión de escritura.
type Store struct {
	db   *sql.DB
	Path string
}

// Open abre (creando si hace falta) el almacén en path.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("aplicando esquema: %w", err)
	}
	return &Store{db: db, Path: path}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// CreateRun registra una ejecución nueva.
func (s *Store) CreateRun(kind, toolVersion, toolHash string, targetPath []byte, targetDisplay, argsJSON, threatModel string, startedNS int64) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO runs
		(kind, tool_version, tool_hash, target_path, target_display, args_json, threat_model, started_at_ns, schema_version)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		kind, toolVersion, toolHash, targetPath, targetDisplay, argsJSON, threatModel, startedNS, SchemaVersion)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishRun sella el fin de una ejecución.
func (s *Store) FinishRun(runID, finishedNS int64) error {
	_, err := s.db.Exec(`UPDATE runs SET finished_at_ns=? WHERE id=?`, finishedNS, runID)
	return err
}

// InsertEntries inserta entradas por lotes en transacciones de batchSize.
func (s *Store) InsertEntries(runID int64, entries []Entry) error {
	for start := 0; start < len(entries); start += batchSize {
		end := min(start+batchSize, len(entries))
		if err := s.insertEntryBatch(runID, entries[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) insertEntryBatch(runID int64, entries []Entry) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.Prepare(`INSERT INTO entries
		(run_id, rel_path, path_display, entry_type, size, mtime_ns, ctime_ns, atime_ns,
		 uid, gid, mode, inode, nlink, sha256, tlsh, magic_type, ext_type, symlink_target, read_error)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.Exec(runID, e.RelPath, e.PathDisplay, e.Type, e.Size,
			e.MtimeNS, e.CtimeNS, e.AtimeNS, e.UID, e.GID, e.Mode, e.Inode, e.Nlink,
			nullStr(e.SHA256), nullStr(e.TLSH), nullStr(e.MagicType), nullStr(e.ExtType),
			e.SymlinkTarget, nullStr(e.ReadError)); err != nil {
			return fmt.Errorf("insertando %s: %w", e.PathDisplay, err)
		}
	}
	return tx.Commit()
}

// InsertObservations persiste observaciones y devuelve sus IDs asignados, en
// el mismo orden de entrada.
func (s *Store) InsertObservations(runID int64, obs []observe.Observation) ([]int64, error) {
	ids := make([]int64, 0, len(obs))
	for start := 0; start < len(obs); start += batchSize {
		end := min(start+batchSize, len(obs))
		batchIDs, err := s.insertObsBatch(runID, obs[start:end])
		if err != nil {
			return nil, err
		}
		ids = append(ids, batchIDs...)
	}
	return ids, nil
}

func (s *Store) insertObsBatch(runID int64, obs []observe.Observation) ([]int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.Prepare(`INSERT INTO observations
		(run_id, subject, subject_display, obs_type, evidence_json, source, confidence, observed_at_ns)
		VALUES (?,?,?,?,?,?,?,?)`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	ids := make([]int64, 0, len(obs))
	for _, o := range obs {
		if o.Subject == nil {
			o.Subject = []byte{} // sujeto vacío = la instalación (NOT NULL)
		}
		res, err := stmt.Exec(runID, o.Subject, o.SubjectDisplay, string(o.Type),
			o.EvidenceJSON, string(o.Source), string(o.Confidence), o.ObservedAtNS)
		if err != nil {
			return nil, err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ids, nil
}

// EntriesByRun devuelve las entradas de un run en orden estable por rel_path
// (Principio IV: toda consulta de salida lleva ORDER BY explícito).
func (s *Store) EntriesByRun(runID int64) ([]Entry, error) {
	rows, err := s.db.Query(`SELECT id, rel_path, path_display, entry_type,
		COALESCE(size,0), COALESCE(mtime_ns,0), COALESCE(ctime_ns,0), COALESCE(atime_ns,0),
		COALESCE(uid,0), COALESCE(gid,0), COALESCE(mode,0), COALESCE(inode,0), COALESCE(nlink,0),
		COALESCE(sha256,''), COALESCE(tlsh,''), COALESCE(magic_type,''), COALESCE(ext_type,''),
		COALESCE(symlink_target, X''), COALESCE(read_error,'')
		FROM entries WHERE run_id=? ORDER BY rel_path`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.RelPath, &e.PathDisplay, &e.Type, &e.Size,
			&e.MtimeNS, &e.CtimeNS, &e.AtimeNS, &e.UID, &e.GID, &e.Mode, &e.Inode, &e.Nlink,
			&e.SHA256, &e.TLSH, &e.MagicType, &e.ExtType, &e.SymlinkTarget, &e.ReadError); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ObservationsByRun devuelve las observaciones en orden estable.
func (s *Store) ObservationsByRun(runID int64) ([]observe.Observation, error) {
	rows, err := s.db.Query(`SELECT id, subject, subject_display, obs_type,
		evidence_json, source, confidence, observed_at_ns
		FROM observations WHERE run_id=? ORDER BY subject, obs_type, id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []observe.Observation
	for rows.Next() {
		var o observe.Observation
		var typ, src, conf string
		if err := rows.Scan(&o.ID, &o.Subject, &o.SubjectDisplay, &typ,
			&o.EvidenceJSON, &src, &conf, &o.ObservedAtNS); err != nil {
			return nil, err
		}
		o.Type, o.Source, o.Confidence = observe.Type(typ), observe.Source(src), observe.Confidence(conf)
		out = append(out, o)
	}
	return out, rows.Err()
}

// LatestRun devuelve el último run de un tipo (para `report`).
func (s *Store) LatestRun(kind string) (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM runs WHERE kind=? ORDER BY id DESC LIMIT 1`, kind).Scan(&id)
	return id, err
}

// RunInfo recupera los metadatos de un run.
type RunInfo struct {
	ID            int64
	Kind          string
	ToolVersion   string
	ToolHash      string
	TargetPath    []byte
	TargetDisplay string
	ArgsJSON      string
	ThreatModel   string
	StartedAtNS   int64
	FinishedAtNS  int64
}

func (s *Store) Run(runID int64) (RunInfo, error) {
	var r RunInfo
	err := s.db.QueryRow(`SELECT id, kind, tool_version, tool_hash, target_path,
		target_display, args_json, threat_model, started_at_ns, COALESCE(finished_at_ns,0)
		FROM runs WHERE id=?`, runID).Scan(&r.ID, &r.Kind, &r.ToolVersion, &r.ToolHash,
		&r.TargetPath, &r.TargetDisplay, &r.ArgsJSON, &r.ThreatModel, &r.StartedAtNS, &r.FinishedAtNS)
	return r, err
}

// ListRuns devuelve los runs del kind dado, ordenados por inicio ascendente.
func (s *Store) ListRuns(kind string) ([]RunInfo, error) {
	rows, err := s.db.Query(`SELECT id, kind, tool_version, tool_hash, target_path,
		target_display, args_json, threat_model, started_at_ns, COALESCE(finished_at_ns,0)
		FROM runs WHERE kind=? ORDER BY started_at_ns ASC, id ASC`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunInfo
	for rows.Next() {
		var r RunInfo
		if err := rows.Scan(&r.ID, &r.Kind, &r.ToolVersion, &r.ToolHash, &r.TargetPath,
			&r.TargetDisplay, &r.ArgsJSON, &r.ThreatModel, &r.StartedAtNS, &r.FinishedAtNS); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SaveBaseline registra un baseline verificado y su manifiesto.
func (s *Store) SaveBaseline(cms, version, packageSHA, manifestSHA, source string, addedNS int64, files []Entry) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.Exec(`INSERT OR REPLACE INTO baselines
		(cms, version, package_sha256, manifest_sha256, source, added_at_ns)
		VALUES (?,?,?,?,?,?)`, cms, version, packageSHA, manifestSHA, source, addedNS)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM baseline_files WHERE baseline_id=?`, id); err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare(`INSERT INTO baseline_files (baseline_id, rel_path, path_display, sha256, size) VALUES (?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	for _, f := range files {
		if _, err := stmt.Exec(id, f.RelPath, f.PathDisplay, f.SHA256, f.Size); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

// BaselineFiles devuelve el manifiesto de un baseline en orden estable.
func (s *Store) BaselineFiles(baselineID int64) ([]Entry, error) {
	rows, err := s.db.Query(`SELECT rel_path, path_display, sha256, size
		FROM baseline_files WHERE baseline_id=? ORDER BY rel_path`, baselineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.RelPath, &e.PathDisplay, &e.SHA256, &e.Size); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// FindBaseline localiza un baseline por versión.
func (s *Store) FindBaseline(cms, version string) (id int64, packageSHA, manifestSHA, source string, err error) {
	err = s.db.QueryRow(`SELECT id, package_sha256, manifest_sha256, source
		FROM baselines WHERE cms=? AND version=?`, cms, version).
		Scan(&id, &packageSHA, &manifestSHA, &source)
	return
}

// SaveExtensionBaseline registra el baseline oficial de una extensión+versión.
//
// Re-guardar el mismo (element, version) es una operación normal del operador
// (`extension add` repetido, p.ej. tras corregir la fuente). Por eso el id se
// mantiene ESTABLE entre re-guardados: buscamos la fila existente y hacemos
// UPDATE en vez de INSERT OR REPLACE. Con INSERT OR REPLACE, el conflicto en
// UNIQUE(element,version) borra la fila vieja y el INSERT reasigna un rowid
// nuevo; el DELETE posterior de extension_baseline_files filtra por ese id
// nuevo y no toca las filas del id viejo, que quedan huérfanas para siempre.
func (s *Store) SaveExtensionBaseline(element, version, packageSHA, source string, addedNS int64, files []Entry) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	var id int64
	err = tx.QueryRow(`SELECT id FROM extension_baselines WHERE element=? AND version=?`, element, version).Scan(&id)
	switch {
	case err == sql.ErrNoRows:
		res, e := tx.Exec(`INSERT INTO extension_baselines
			(element, version, package_sha256, source, added_at_ns) VALUES (?,?,?,?,?)`,
			element, version, packageSHA, source, addedNS)
		if e != nil {
			return 0, e
		}
		id, e = res.LastInsertId()
		if e != nil {
			return 0, e
		}
	case err != nil:
		return 0, err
	default:
		if _, e := tx.Exec(`UPDATE extension_baselines SET package_sha256=?, source=?, added_at_ns=? WHERE id=?`,
			packageSHA, source, addedNS, id); e != nil {
			return 0, e
		}
	}

	if _, err := tx.Exec(`DELETE FROM extension_baseline_files WHERE ext_baseline_id=?`, id); err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare(`INSERT INTO extension_baseline_files (ext_baseline_id, rel_path, path_display, sha256, size) VALUES (?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	for _, f := range files {
		if _, err := stmt.Exec(id, f.RelPath, f.PathDisplay, f.SHA256, f.Size); err != nil {
			return 0, err
		}
	}
	return id, tx.Commit()
}

// FindExtensionBaseline localiza el baseline de una extensión por (element, version).
func (s *Store) FindExtensionBaseline(element, version string) (int64, string, string, error) {
	var id int64
	var pkg, src string
	err := s.db.QueryRow(`SELECT id, package_sha256, source FROM extension_baselines
		WHERE element=? AND version=?`, element, version).Scan(&id, &pkg, &src)
	if err != nil {
		return 0, "", "", err
	}
	return id, pkg, src, nil
}

// ExtensionBaselineFiles devuelve el manifiesto oficial de una extensión, en orden estable.
func (s *Store) ExtensionBaselineFiles(id int64) ([]Entry, error) {
	rows, err := s.db.Query(`SELECT rel_path, path_display, sha256, size
		FROM extension_baseline_files WHERE ext_baseline_id=? ORDER BY rel_path`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.RelPath, &e.PathDisplay, &e.SHA256, &e.Size); err != nil {
			return nil, err
		}
		e.Type = "file"
		out = append(out, e)
	}
	return out, rows.Err()
}

// ExtensionBaselineRow resume una fila de extension_baselines para listados.
type ExtensionBaselineRow struct {
	Element string `json:"element"`
	Version string `json:"version"`
	Source  string `json:"source"`
}

// ListExtensionBaselines enumera los baselines de extensión cacheados, en
// orden estable (element, version).
func (s *Store) ListExtensionBaselines() ([]ExtensionBaselineRow, error) {
	rows, err := s.db.Query(`SELECT element, version, source FROM extension_baselines ORDER BY element, version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExtensionBaselineRow{}
	for rows.Next() {
		var r ExtensionBaselineRow
		if err := rows.Scan(&r.Element, &r.Version, &r.Source); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
