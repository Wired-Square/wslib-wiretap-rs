//! Recorded, run-once migrations. `PRAGMA user_version` is the authoritative
//! gate and `schema_migrations` the audit trail; each migration applies in one
//! transaction with its audit row and version stamp, so a crash can never leave
//! a step half-applied or applied but unrecorded. The rules are in the README.

use rusqlite::{params, Connection, Transaction};

use crate::error::{CaptureError, Result};

/// Tables only: a legacy database's `buffer_id` columns can't carry the indexes
/// until the baseline has renamed them.
const SCHEMA_TABLES_SQL: &str = "
CREATE TABLE IF NOT EXISTS frames (
    rowid INTEGER PRIMARY KEY,
    capture_id TEXT NOT NULL,
    protocol TEXT NOT NULL,
    timestamp_us INTEGER NOT NULL,
    frame_id INTEGER NOT NULL,
    bus INTEGER NOT NULL,
    dlc INTEGER NOT NULL,
    payload BLOB NOT NULL,
    is_extended INTEGER NOT NULL DEFAULT 0,
    is_fd INTEGER NOT NULL DEFAULT 0,
    source_address INTEGER,
    incomplete INTEGER,
    direction TEXT
);

CREATE TABLE IF NOT EXISTS bytes (
    rowid INTEGER PRIMARY KEY,
    capture_id TEXT NOT NULL,
    byte_val INTEGER NOT NULL,
    timestamp_us INTEGER NOT NULL,
    bus INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS capture_metadata (
    capture_id TEXT PRIMARY KEY,
    capture_kind TEXT NOT NULL,
    name TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    start_time_us INTEGER,
    end_time_us INTEGER,
    created_at INTEGER NOT NULL,
    owning_session_id TEXT
);
";

const SCHEMA_INDEXES_SQL: &str = "
CREATE INDEX IF NOT EXISTS idx_frames_capture_ts ON frames (capture_id, timestamp_us);
CREATE INDEX IF NOT EXISTS idx_frames_capture_fid ON frames (capture_id, frame_id);
CREATE INDEX IF NOT EXISTS idx_bytes_capture_ts ON bytes (capture_id, timestamp_us);
";

enum MigrationStep {
    /// Conditional logic SQL can't express; prefer `Sql`.
    Rust(fn(&Transaction) -> rusqlite::Result<()>),
    Sql(&'static str),
}

struct Migration {
    version: i64,
    name: &'static str,
    step: MigrationStep,
}

/// The `user_version` [`migrate`] leaves a database at.
pub const SCHEMA_VERSION: i64 = 6;

/// Ascending and contiguous from 1; `user_version` 0 is any unstamped shape.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "baseline_capture_schema",
        step: MigrationStep::Rust(baseline_capture_schema),
    },
    Migration {
        version: 2,
        name: "frames_capture_rowid_index",
        step: MigrationStep::Sql(include_str!(
            "../migrations/0002_frames_capture_rowid_index.sql"
        )),
    },
    Migration {
        version: 3,
        name: "frames_fid_protocol_index",
        step: MigrationStep::Sql(include_str!(
            "../migrations/0003_frames_fid_protocol_index.sql"
        )),
    },
    Migration {
        version: 4,
        name: "capture_events",
        step: MigrationStep::Sql(include_str!("../migrations/0004_capture_events.sql")),
    },
    Migration {
        version: 5,
        name: "frames_can_flags",
        step: MigrationStep::Sql(include_str!("../migrations/0005_frames_can_flags.sql")),
    },
    Migration {
        version: 6,
        name: "frames_crc_valid",
        step: MigrationStep::Sql(include_str!("../migrations/0006_frames_crc_valid.sql")),
    },
];

/// A migration [`migrate`] applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    pub version: i64,
    pub name: &'static str,
}

fn has_column(conn: &Connection, table: &str, col: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
        params![table, col],
        |row| row.get(0),
    )
}

fn schema_version(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
}

/// Apply every migration newer than the database's stamped version.
pub fn migrate(conn: &mut Connection) -> Result<Vec<Applied>> {
    apply_migrations(conn, MIGRATIONS)
}

fn apply_migrations(conn: &mut Connection, migrations: &[Migration]) -> Result<Vec<Applied>> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             version INTEGER PRIMARY KEY,
             name TEXT NOT NULL,
             applied_at INTEGER NOT NULL
         );",
    )?;

    let current = schema_version(conn)?;
    let mut applied = Vec::new();
    for m in migrations.iter().filter(|m| m.version > current) {
        apply(conn, m).map_err(|source| CaptureError::Migration {
            version: m.version,
            name: m.name,
            source,
        })?;
        applied.push(Applied {
            version: m.version,
            name: m.name,
        });
    }
    Ok(applied)
}

fn apply(conn: &mut Connection, m: &Migration) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    match m.step {
        MigrationStep::Rust(f) => f(&tx)?,
        MigrationStep::Sql(sql) => tx.execute_batch(sql)?,
    }
    tx.execute(
        "INSERT INTO schema_migrations (version, name, applied_at)
         VALUES (?1, ?2, strftime('%s','now'))",
        params![m.version, m.name],
    )?;
    tx.pragma_update(None, "user_version", m.version)?;
    tx.commit()
}

/// Migration 1 normalises any unstamped database (fresh, legacy `buffer_*`,
/// fully migrated or mixed-generation) to the v1 shape. It alone infers state
/// from the schema, and does so per object: a pre-rename build re-creates an
/// empty `buffer_metadata` beside renamed tables, and a blanket "legacy, rename
/// everything" aborts on the first renamed column on every launch.
fn baseline_capture_schema(tx: &Transaction) -> rusqlite::Result<()> {
    tx.execute_batch(SCHEMA_TABLES_SQL)?;

    let has_legacy: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='buffer_metadata')",
        [],
        |row| row.get(0),
    )?;

    if has_legacy {
        if has_column(tx, "frames", "buffer_id")? {
            tx.execute_batch(
                "ALTER TABLE frames RENAME COLUMN buffer_id TO capture_id;
                 DROP INDEX IF EXISTS idx_frames_buffer_ts;
                 DROP INDEX IF EXISTS idx_frames_buffer_fid;",
            )?;
        }
        if has_column(tx, "bytes", "buffer_id")? {
            tx.execute_batch(
                "ALTER TABLE bytes RENAME COLUMN buffer_id TO capture_id;
                 DROP INDEX IF EXISTS idx_bytes_buffer_ts;",
            )?;
        }
        // Rows, not a table rename: in the mixed case `capture_metadata` already
        // holds migrated, possibly pinned, captures.
        tx.execute_batch(
            "INSERT OR IGNORE INTO capture_metadata
                 (capture_id, capture_kind, name, count, start_time_us, end_time_us,
                  created_at, owning_session_id)
             SELECT buffer_id, buffer_type, name, count, start_time_us, end_time_us,
                    created_at, owning_session_id
             FROM buffer_metadata;
             DROP TABLE buffer_metadata;",
        )?;
    }

    tx.execute_batch(SCHEMA_INDEXES_SQL)?;

    if !has_column(tx, "capture_metadata", "persistent")? {
        tx.execute(
            "ALTER TABLE capture_metadata ADD COLUMN persistent INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !has_column(tx, "capture_metadata", "buses")? {
        tx.execute(
            "ALTER TABLE capture_metadata ADD COLUMN buses TEXT NOT NULL DEFAULT '[]'",
            [],
        )?;
    }
    Ok(())
}

/// The pragmas a live capture database runs under: WAL, `synchronous=NORMAL`, a
/// 64 MiB page cache and in-memory temporaries.
pub fn tune(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA cache_size=-65536;
         PRAGMA temp_store=MEMORY;",
    )?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn migrated() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate(&mut conn).unwrap();
    conn
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pre-rename schema as shipped before April 2026.
    const LEGACY_SCHEMA_SQL: &str = "
        CREATE TABLE buffer_metadata (
            buffer_id TEXT PRIMARY KEY,
            buffer_type TEXT NOT NULL,
            name TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 0,
            start_time_us INTEGER,
            end_time_us INTEGER,
            created_at INTEGER NOT NULL,
            owning_session_id TEXT
        );
        CREATE TABLE frames (
            rowid INTEGER PRIMARY KEY,
            buffer_id TEXT NOT NULL,
            protocol TEXT NOT NULL,
            timestamp_us INTEGER NOT NULL,
            frame_id INTEGER NOT NULL,
            bus INTEGER NOT NULL,
            dlc INTEGER NOT NULL,
            payload BLOB NOT NULL,
            is_extended INTEGER NOT NULL DEFAULT 0,
            is_fd INTEGER NOT NULL DEFAULT 0,
            source_address INTEGER,
            incomplete INTEGER,
            direction TEXT
        );
        CREATE TABLE bytes (
            rowid INTEGER PRIMARY KEY,
            buffer_id TEXT NOT NULL,
            byte_val INTEGER NOT NULL,
            timestamp_us INTEGER NOT NULL,
            bus INTEGER NOT NULL DEFAULT 0
        );
    ";

    fn version_of(conn: &Connection) -> i64 {
        schema_version(conn).unwrap()
    }

    fn count(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn audit_rows(conn: &Connection) -> Vec<(i64, String)> {
        let mut stmt = conn
            .prepare("SELECT version, name FROM schema_migrations ORDER BY version")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    fn index_columns(conn: &Connection, index: &str) -> Vec<String> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA index_info({index})"))
            .unwrap();
        stmt.query_map([], |r| r.get::<_, String>(2))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    #[test]
    fn fresh_database_migrates_to_current_version() {
        let mut conn = Connection::open_in_memory().unwrap();
        let applied = migrate(&mut conn).unwrap();

        let expected: Vec<(i64, &str)> = [
            "baseline_capture_schema",
            "frames_capture_rowid_index",
            "frames_fid_protocol_index",
            "capture_events",
            "frames_can_flags",
            "frames_crc_valid",
        ]
        .into_iter()
        .zip(1..)
        .map(|(name, version)| (version, name))
        .collect();
        assert_eq!(version_of(&conn), 6);
        assert_eq!(
            applied
                .iter()
                .map(|a| (a.version, a.name))
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            audit_rows(&conn)
                .iter()
                .map(|(v, n)| (*v, n.as_str()))
                .collect::<Vec<_>>(),
            expected
        );
        assert!(has_column(&conn, "frames", "capture_id").unwrap());
        assert!(has_column(&conn, "capture_metadata", "persistent").unwrap());
        assert!(has_column(&conn, "capture_metadata", "buses").unwrap());
        assert!(has_column(&conn, "capture_events", "duration_us").unwrap());
        for flag in ["is_rtr", "is_brs", "is_esi", "crc_valid"] {
            assert!(has_column(&conn, "frames", flag).unwrap(), "{flag}");
        }
    }

    #[test]
    fn rerunning_migrations_is_a_recorded_noop() {
        let mut conn = migrated();
        assert!(migrate(&mut conn).unwrap().is_empty());

        assert_eq!(version_of(&conn), SCHEMA_VERSION);
        assert_eq!(audit_rows(&conn).len(), MIGRATIONS.len());
    }

    #[test]
    fn migration_versions_are_ascending_and_contiguous() {
        for (i, m) in MIGRATIONS.iter().enumerate() {
            assert_eq!(
                m.version,
                i as i64 + 1,
                "MIGRATIONS must be contiguous from 1"
            );
        }
        assert_eq!(MIGRATIONS.len() as i64, SCHEMA_VERSION);
    }

    #[test]
    fn legacy_database_is_renamed_and_data_preserved() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(LEGACY_SCHEMA_SQL).unwrap();
        conn.execute_batch(
            "INSERT INTO buffer_metadata (buffer_id, buffer_type, name, count, created_at)
             VALUES ('b1', 'frames', 'old capture', 2, 1700000000);
             INSERT INTO frames (buffer_id, protocol, timestamp_us, frame_id, bus, dlc, payload)
             VALUES ('b1', 'can', 1, 256, 0, 4, x'DEADBEEF'),
                    ('b1', 'can', 2, 257, 0, 4, x'01020304');",
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(version_of(&conn), SCHEMA_VERSION);
        assert!(!has_column(&conn, "frames", "buffer_id").unwrap());
        let (name, n): (String, i64) = conn
            .query_row(
                "SELECT name, count FROM capture_metadata WHERE capture_id = 'b1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((name.as_str(), n), ("old capture", 2));
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM frames WHERE capture_id = 'b1'"),
            2
        );
    }

    /// New-schema tables beside a stale `buffer_metadata` a pre-rename build
    /// re-created: folded without touching the renamed tables.
    #[test]
    fn mixed_generation_database_is_normalised() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_TABLES_SQL).unwrap();
        conn.execute_batch(
            "ALTER TABLE capture_metadata ADD COLUMN persistent INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE capture_metadata ADD COLUMN buses TEXT NOT NULL DEFAULT '[]';
             INSERT INTO capture_metadata (capture_id, capture_kind, name, count, created_at, persistent)
             VALUES ('pinned', 'frames', 'keep me', 1, 1700000000, 1);
             CREATE TABLE buffer_metadata (
                 buffer_id TEXT PRIMARY KEY,
                 buffer_type TEXT NOT NULL,
                 name TEXT NOT NULL,
                 count INTEGER NOT NULL DEFAULT 0,
                 start_time_us INTEGER,
                 end_time_us INTEGER,
                 created_at INTEGER NOT NULL,
                 owning_session_id TEXT
             );",
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        assert_eq!(version_of(&conn), SCHEMA_VERSION);
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='buffer_metadata'"
            ),
            0
        );
        assert_eq!(
            count(
                &conn,
                "SELECT persistent FROM capture_metadata WHERE capture_id = 'pinned'"
            ),
            1
        );
    }

    #[test]
    fn a_failing_migration_applies_nothing_of_itself() {
        let mut conn = Connection::open_in_memory().unwrap();
        let broken = [
            Migration {
                version: 1,
                name: "baseline_capture_schema",
                step: MigrationStep::Rust(baseline_capture_schema),
            },
            Migration {
                version: 2,
                name: "broken",
                step: MigrationStep::Sql("CREATE TABLE half (x); SELECT * FROM no_such_table;"),
            },
        ];

        let err = apply_migrations(&mut conn, &broken).unwrap_err();

        assert!(matches!(
            err,
            CaptureError::Migration {
                version: 2,
                name: "broken",
                ..
            }
        ));
        assert_eq!(version_of(&conn), 1);
        assert_eq!(audit_rows(&conn).len(), 1);
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'half'"
            ),
            0
        );
    }

    #[test]
    fn a_v4_database_migrates_to_v5_with_its_frames_unflagged() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations(&mut conn, &MIGRATIONS[..4]).unwrap();
        conn.execute_batch(
            "INSERT INTO frames (capture_id, protocol, timestamp_us, frame_id, bus, dlc, payload, is_fd)
             VALUES ('c1', 'can', 1, 256, 0, 2, x'AABB', 1);",
        )
        .unwrap();

        let applied = apply_migrations(&mut conn, &MIGRATIONS[..5]).unwrap();

        assert_eq!(
            applied,
            [Applied {
                version: 5,
                name: "frames_can_flags"
            }]
        );
        assert_eq!(
            count(
                &conn,
                "SELECT is_fd * 1000 + is_rtr * 100 + is_brs * 10 + is_esi FROM frames"
            ),
            1000
        );
    }

    #[test]
    fn a_v5_database_migrates_to_v6_and_reads_its_frames_crc_unchecked() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations(&mut conn, &MIGRATIONS[..5]).unwrap();
        conn.execute_batch(
            "INSERT INTO frames (capture_id, protocol, timestamp_us, frame_id, bus, dlc, payload)
             VALUES ('c1', 'modbus_rtu', 1, 259, 0, 4, x'01030000');",
        )
        .unwrap();

        let applied = migrate(&mut conn).unwrap();

        assert_eq!(
            applied,
            [Applied {
                version: 6,
                name: "frames_crc_valid"
            }]
        );
        let frames = crate::get_all_frames(&conn, "c1").unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].crc_valid, None);
    }

    #[test]
    fn the_index_names_are_the_contract() {
        let conn = migrated();
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%' ORDER BY name")
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            names,
            [
                "idx_bytes_capture_ts",
                "idx_capture_events_capture_ts",
                "idx_frames_capture_fid",
                "idx_frames_capture_rowid",
                "idx_frames_capture_ts",
            ]
        );
    }

    /// Migration 3 replaces the v1 frame-id index rather than adding one, so the
    /// filtered COUNT, which tests the protocol too, stays covering.
    #[test]
    fn frame_id_index_is_widened_to_carry_protocol() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_TABLES_SQL).unwrap();
        conn.execute_batch(SCHEMA_INDEXES_SQL).unwrap();
        assert_eq!(
            index_columns(&conn, "idx_frames_capture_fid"),
            ["capture_id", "frame_id"]
        );

        migrate(&mut conn).unwrap();

        assert_eq!(
            index_columns(&conn, "idx_frames_capture_fid"),
            ["capture_id", "frame_id", "protocol"]
        );
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'index' AND tbl_name = 'frames' AND name LIKE 'idx_frames_capture_fid%'"
            ),
            1
        );
    }

    #[test]
    fn tuning_a_file_database_puts_it_in_wal() {
        let dir = std::env::temp_dir().join(format!("wiretap-capture-tune-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tune.db");
        let mut conn = Connection::open(&path).unwrap();
        migrate(&mut conn).unwrap();

        tune(&conn).unwrap();

        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        drop(conn);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
