// Package inventory implementa el almacén local del inventario (SQLite puro
// Go). Vive siempre fuera del árbol objetivo (Principio I) y es append-only:
// las observaciones y entradas nunca se actualizan (Principio II).
package inventory

// SchemaVersion versiona el esquema del almacén.
const SchemaVersion = 1

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS runs (
    id              INTEGER PRIMARY KEY,
    kind            TEXT NOT NULL CHECK (kind IN ('inventory','analyze','report')),
    tool_version    TEXT NOT NULL,
    tool_hash       TEXT NOT NULL,
    target_path     BLOB NOT NULL,
    target_display  TEXT NOT NULL,
    args_json       TEXT NOT NULL,
    threat_model    TEXT NOT NULL DEFAULT 'webserver-user-no-root',
    started_at_ns   INTEGER NOT NULL,
    finished_at_ns  INTEGER,
    schema_version  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    id              INTEGER PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    rel_path        BLOB NOT NULL,
    path_display    TEXT NOT NULL,
    entry_type      TEXT NOT NULL CHECK (entry_type IN ('file','dir','symlink','other')),
    size            INTEGER,
    mtime_ns        INTEGER,
    ctime_ns        INTEGER,
    atime_ns        INTEGER,
    uid             INTEGER,
    gid             INTEGER,
    mode            INTEGER,
    inode           INTEGER,
    nlink           INTEGER,
    sha256          TEXT,
    tlsh            TEXT,
    magic_type      TEXT,
    ext_type        TEXT,
    symlink_target  BLOB,
    read_error      TEXT,
    UNIQUE (run_id, rel_path)
);
CREATE INDEX IF NOT EXISTS idx_entries_run_sha  ON entries(run_id, sha256);
CREATE INDEX IF NOT EXISTS idx_entries_run_type ON entries(run_id, entry_type);

CREATE TABLE IF NOT EXISTS observations (
    id              INTEGER PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    subject         BLOB NOT NULL,
    subject_display TEXT NOT NULL,
    obs_type        TEXT NOT NULL,
    evidence_json   TEXT NOT NULL,
    source          TEXT NOT NULL,
    confidence      TEXT NOT NULL CHECK (confidence IN ('high','medium','low')),
    observed_at_ns  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_obs_run_subject ON observations(run_id, subject);
CREATE INDEX IF NOT EXISTS idx_obs_run_type    ON observations(run_id, obs_type);

CREATE TABLE IF NOT EXISTS baselines (
    id              INTEGER PRIMARY KEY,
    cms             TEXT NOT NULL DEFAULT 'joomla',
    version         TEXT NOT NULL,
    package_sha256  TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    source          TEXT NOT NULL CHECK (source IN ('catalog-fetch','local-add')),
    added_at_ns     INTEGER NOT NULL,
    UNIQUE (cms, version)
);

CREATE TABLE IF NOT EXISTS baseline_files (
    baseline_id     INTEGER NOT NULL REFERENCES baselines(id),
    rel_path        BLOB NOT NULL,
    path_display    TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    size            INTEGER NOT NULL,
    PRIMARY KEY (baseline_id, rel_path)
);

CREATE TABLE IF NOT EXISTS extension_baselines (
    id              INTEGER PRIMARY KEY,
    element         TEXT NOT NULL,
    version         TEXT NOT NULL,
    package_sha256  TEXT NOT NULL,
    source          TEXT NOT NULL CHECK (source IN ('package','updateserver')),
    added_at_ns     INTEGER NOT NULL,
    UNIQUE (element, version)
);

CREATE TABLE IF NOT EXISTS extension_baseline_files (
    ext_baseline_id INTEGER NOT NULL REFERENCES extension_baselines(id),
    rel_path        BLOB NOT NULL,
    path_display    TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    size            INTEGER NOT NULL,
    PRIMARY KEY (ext_baseline_id, rel_path)
);

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT NOT NULL,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    rule_id         TEXT NOT NULL,
    subject         BLOB NOT NULL,
    subject_display TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    confidence      TEXT NOT NULL CHECK (confidence IN ('high','medium','low')),
    observed        TEXT NOT NULL,
    compared_to     TEXT NOT NULL,
    rationale       TEXT NOT NULL,
    alternative     TEXT,
    evidence_json   TEXT NOT NULL,
    observation_ids TEXT NOT NULL,
    suppressed_by   INTEGER REFERENCES suppressions(id),
    PRIMARY KEY (run_id, id)
);

CREATE TABLE IF NOT EXISTS suppressions (
    id              INTEGER PRIMARY KEY,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    rule_id         TEXT NOT NULL,
    path_glob       TEXT NOT NULL,
    reason          TEXT NOT NULL CHECK (length(reason) > 0),
    source_file     TEXT NOT NULL
);
`
