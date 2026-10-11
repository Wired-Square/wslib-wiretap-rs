use rusqlite::{params, Connection};

use crate::error::Result;
use crate::model::{CaptureKind, CaptureMetadata};

/// Insert or replace a capture's metadata row; `is_streaming` isn't stored.
pub fn save_capture_metadata(conn: &Connection, meta: &CaptureMetadata) -> Result<()> {
    let buses = serde_json::to_string(&meta.buses).unwrap_or_else(|_| "[]".into());
    conn.execute(
        "INSERT OR REPLACE INTO capture_metadata (capture_id, capture_kind, name, count, start_time_us, end_time_us, created_at, owning_session_id, persistent, buses)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            meta.id,
            meta.kind.as_str(),
            meta.name,
            meta.count as i64,
            meta.start_time_us.map(|v| v as i64),
            meta.end_time_us.map(|v| v as i64),
            meta.created_at as i64,
            meta.owning_session_id,
            meta.persistent,
            buses,
        ],
    )?;
    Ok(())
}

/// Every capture's metadata, each loading as not streaming.
pub fn load_all_capture_metadata(conn: &Connection) -> Result<Vec<CaptureMetadata>> {
    let mut stmt = conn.prepare(
        "SELECT capture_id, capture_kind, name, count, start_time_us, end_time_us, created_at, owning_session_id, persistent, buses FROM capture_metadata",
    )?;
    let metadata = stmt
        .query_map([], |row| {
            Ok(CaptureMetadata {
                id: row.get("capture_id")?,
                kind: CaptureKind::from_stored(&row.get::<_, String>("capture_kind")?),
                name: row.get("name")?,
                count: row.get::<_, i64>("count")? as usize,
                start_time_us: row
                    .get::<_, Option<i64>>("start_time_us")?
                    .map(|v| v as u64),
                end_time_us: row.get::<_, Option<i64>>("end_time_us")?.map(|v| v as u64),
                created_at: row.get::<_, i64>("created_at")? as u64,
                is_streaming: false,
                owning_session_id: row.get("owning_session_id")?,
                persistent: row.get::<_, i64>("persistent")? != 0,
                buses: serde_json::from_str(&row.get::<_, String>("buses")?).unwrap_or_default(),
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(metadata)
}

pub fn update_capture_name(conn: &Connection, capture_id: &str, new_name: &str) -> Result<()> {
    conn.execute(
        "UPDATE capture_metadata SET name = ?2 WHERE capture_id = ?1",
        params![capture_id, new_name],
    )?;
    Ok(())
}

pub fn update_capture_persistent(
    conn: &Connection,
    capture_id: &str,
    persistent: bool,
) -> Result<()> {
    conn.execute(
        "UPDATE capture_metadata SET persistent = ?2 WHERE capture_id = ?1",
        params![capture_id, persistent],
    )?;
    Ok(())
}

/// The distinct buses in a capture's data, ascending; backfills metadata stored
/// before buses were tracked.
pub fn get_distinct_buses(
    conn: &Connection,
    capture_id: &str,
    kind: CaptureKind,
) -> Result<Vec<u8>> {
    let sql = match kind {
        CaptureKind::Frames => "SELECT DISTINCT bus FROM frames WHERE capture_id = ?1 ORDER BY bus",
        CaptureKind::Bytes => "SELECT DISTINCT bus FROM bytes WHERE capture_id = ?1 ORDER BY bus",
    };
    let mut stmt = conn.prepare_cached(sql)?;
    let buses = stmt
        .query_map(params![capture_id], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(buses)
}

/// Delete a capture's metadata and its events.
pub fn delete_capture_metadata(conn: &Connection, capture_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM capture_metadata WHERE capture_id = ?1",
        params![capture_id],
    )?;
    conn.execute(
        "DELETE FROM capture_events WHERE capture_id = ?1",
        params![capture_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames::{can_frame, insert_frames, StoredFrame};

    fn meta(id: &str) -> CaptureMetadata {
        CaptureMetadata {
            id: id.into(),
            kind: CaptureKind::Bytes,
            name: "Serial dump".into(),
            count: 12,
            start_time_us: Some(1),
            end_time_us: None,
            created_at: 1_700_000_000,
            is_streaming: true,
            owning_session_id: Some("s1".into()),
            persistent: true,
            buses: vec![0, 3],
        }
    }

    #[test]
    fn metadata_round_trips_except_streaming() {
        let conn = crate::schema::migrated();
        save_capture_metadata(&conn, &meta("m1")).unwrap();

        let loaded = load_all_capture_metadata(&conn).unwrap();

        assert_eq!(
            loaded,
            [CaptureMetadata {
                is_streaming: false,
                ..meta("m1")
            }]
        );
    }

    #[test]
    fn saving_again_replaces_and_updates_touch_one_capture() {
        let conn = crate::schema::migrated();
        save_capture_metadata(&conn, &meta("m1")).unwrap();
        save_capture_metadata(
            &conn,
            &CaptureMetadata {
                count: 13,
                ..meta("m1")
            },
        )
        .unwrap();
        save_capture_metadata(&conn, &meta("m2")).unwrap();

        update_capture_name(&conn, "m1", "renamed").unwrap();
        update_capture_persistent(&conn, "m1", false).unwrap();

        let mut loaded = load_all_capture_metadata(&conn).unwrap();
        loaded.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(
            loaded
                .iter()
                .map(|m| (m.name.as_str(), m.count, m.persistent))
                .collect::<Vec<_>>(),
            [("renamed", 13, false), ("Serial dump", 12, true)]
        );
    }

    #[test]
    fn a_legacy_row_loads_with_defaults() {
        let conn = crate::schema::migrated();
        conn.execute_batch(
            "INSERT INTO capture_metadata (capture_id, capture_kind, name, created_at, buses)
             VALUES ('old', 'buffer_type_from_before', 'old', 5, 'not json')",
        )
        .unwrap();

        let loaded = load_all_capture_metadata(&conn).unwrap();

        assert_eq!(loaded[0].kind, CaptureKind::Frames);
        assert!(loaded[0].buses.is_empty() && !loaded[0].persistent);
    }

    #[test]
    fn distinct_buses_read_the_kinds_own_table() {
        let mut conn = crate::schema::migrated();
        insert_frames(
            &mut conn,
            "c1",
            &[
                StoredFrame {
                    bus: 2,
                    ..can_frame(1, &[])
                },
                StoredFrame {
                    bus: 0,
                    ..can_frame(1, &[])
                },
            ],
        )
        .unwrap();

        assert_eq!(
            get_distinct_buses(&conn, "c1", CaptureKind::Frames).unwrap(),
            [0, 2]
        );
        assert!(get_distinct_buses(&conn, "c1", CaptureKind::Bytes)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn deleting_metadata_deletes_its_events() {
        let conn = crate::schema::migrated();
        save_capture_metadata(&conn, &meta("m1")).unwrap();
        conn.execute_batch(
            "INSERT INTO capture_events (capture_id, timestamp_us, created_at_us, updated_at_us)
             VALUES ('m1', 1, 1, 1), ('m2', 1, 1, 1)",
        )
        .unwrap();

        delete_capture_metadata(&conn, "m1").unwrap();

        assert!(load_all_capture_metadata(&conn).unwrap().is_empty());
        let left: i64 = conn
            .query_row("SELECT COUNT(*) FROM capture_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 1);
    }
}
