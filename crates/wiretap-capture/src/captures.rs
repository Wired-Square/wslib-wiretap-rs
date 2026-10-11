use rusqlite::{params, Connection};

use crate::error::Result;

/// Copy a capture's frames, bytes and events to `dest_id` in one transaction; the
/// count is of frames and bytes.
pub fn copy_capture_data(conn: &mut Connection, source_id: &str, dest_id: &str) -> Result<usize> {
    let tx = conn.transaction()?;
    let frames = tx.execute(
        "INSERT INTO frames (capture_id, protocol, timestamp_us, frame_id, bus, dlc, payload, is_extended, is_fd, is_rtr, is_brs, is_esi, source_address, incomplete, direction)
         SELECT ?2, protocol, timestamp_us, frame_id, bus, dlc, payload, is_extended, is_fd, is_rtr, is_brs, is_esi, source_address, incomplete, direction
         FROM frames WHERE capture_id = ?1 ORDER BY rowid",
        params![source_id, dest_id],
    )?;
    let bytes = tx.execute(
        "INSERT INTO bytes (capture_id, byte_val, timestamp_us, bus)
         SELECT ?2, byte_val, timestamp_us, bus
         FROM bytes WHERE capture_id = ?1 ORDER BY rowid",
        params![source_id, dest_id],
    )?;
    tx.execute(
        "INSERT INTO capture_events (capture_id, timestamp_us, duration_us, note, created_at_us, updated_at_us)
         SELECT ?2, timestamp_us, duration_us, note, created_at_us, updated_at_us
         FROM capture_events WHERE capture_id = ?1 ORDER BY id",
        params![source_id, dest_id],
    )?;
    tx.commit()?;
    Ok(frames + bytes)
}

/// Delete a capture's frames, bytes and events, leaving its metadata.
pub fn delete_capture_data(conn: &Connection, capture_id: &str) -> Result<()> {
    for table in ["frames", "bytes", "capture_events"] {
        conn.execute(
            &format!("DELETE FROM {table} WHERE capture_id = ?1"),
            params![capture_id],
        )?;
    }
    Ok(())
}

/// Delete every capture not marked persistent, then rows with no metadata at all, and
/// vacuum. Leaves the database in `DELETE` journal mode, since `VACUUM` can't shrink a
/// WAL database; [`tune`](crate::tune) after.
pub fn sweep_non_persistent(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode=DELETE;
         DELETE FROM frames WHERE capture_id IN (SELECT capture_id FROM capture_metadata WHERE persistent = 0);
         DELETE FROM bytes WHERE capture_id IN (SELECT capture_id FROM capture_metadata WHERE persistent = 0);
         DELETE FROM capture_events WHERE capture_id IN (SELECT capture_id FROM capture_metadata WHERE persistent = 0);
         DELETE FROM capture_metadata WHERE persistent = 0;
         DELETE FROM frames WHERE capture_id NOT IN (SELECT capture_id FROM capture_metadata);
         DELETE FROM bytes WHERE capture_id NOT IN (SELECT capture_id FROM capture_metadata);
         DELETE FROM capture_events WHERE capture_id NOT IN (SELECT capture_id FROM capture_metadata);
         VACUUM;",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{event, insert_capture_event, list_capture_events};
    use crate::frames::{can_frame, insert_frames, StoredFrame};
    use crate::read::{get_frames_paginated_filtered, multi_protocol_capture, whole};

    fn count(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn event_count(conn: &Connection, capture_id: &str) -> usize {
        list_capture_events(conn, capture_id).unwrap().len()
    }

    #[test]
    fn a_frame_keeps_rtr_brs_and_esi_through_insert_select_and_copy() {
        let mut conn = crate::schema::migrated();
        let frames = [
            StoredFrame {
                rtr: true,
                len: 6,
                ..can_frame(0x100, &[])
            },
            StoredFrame {
                fd: true,
                brs: true,
                esi: true,
                ..can_frame(0x101, &[1, 2])
            },
            can_frame(0x102, &[3]),
        ];
        insert_frames(&mut conn, "c1", &frames).unwrap();
        copy_capture_data(&mut conn, "c1", "c2").unwrap();

        for capture in ["c1", "c2"] {
            let (read, _, _) =
                get_frames_paginated_filtered(&conn, capture, 0, 10, &whole("can")).unwrap();
            assert_eq!(
                read.iter()
                    .map(|f| (f.rtr, f.fd, f.brs, f.esi, f.len))
                    .collect::<Vec<_>>(),
                [
                    (true, false, false, false, 6),
                    (false, true, true, true, 2),
                    (false, false, false, false, 1)
                ],
                "{capture}"
            );
        }
    }

    #[test]
    fn deleting_capture_data_removes_its_events() {
        let conn = multi_protocol_capture();
        insert_capture_event(&conn, "c1", &event(10, 0, "gone")).unwrap();
        insert_capture_event(&conn, "c2", &event(10, 0, "kept")).unwrap();

        delete_capture_data(&conn, "c1").unwrap();

        assert_eq!(event_count(&conn, "c1"), 0);
        assert_eq!(event_count(&conn, "c2"), 1);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM frames"), 0);
    }

    #[test]
    fn copying_a_capture_copies_its_events() {
        let mut conn = multi_protocol_capture();
        insert_capture_event(&conn, "c1", &event(10, 3, "first")).unwrap();
        insert_capture_event(&conn, "c1", &event(40, 0, "second")).unwrap();

        let copied_rows = copy_capture_data(&mut conn, "c1", "c1_copy").unwrap();
        assert_eq!(copied_rows, 4, "events are not counted as data rows");

        let copied = list_capture_events(&conn, "c1_copy").unwrap();
        assert_eq!(
            copied.iter().map(|e| e.note.as_str()).collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert_eq!(copied[0].duration_us, 3);
        assert_eq!(event_count(&conn, "c1"), 2);
    }

    #[test]
    fn clear_on_start_sweeps_non_persistent_events() {
        let conn = multi_protocol_capture();
        conn.execute_batch(
            "INSERT INTO capture_metadata (capture_id, capture_kind, name, created_at, persistent)
             VALUES ('pinned', 'frames', 'pinned', 0, 1), ('ephemeral', 'frames', 'ephemeral', 0, 0);
             INSERT INTO bytes (capture_id, byte_val, timestamp_us) VALUES ('pinned', 1, 1), ('ephemeral', 2, 2);",
        )
        .unwrap();
        insert_capture_event(&conn, "pinned", &event(1, 0, "survives")).unwrap();
        insert_capture_event(&conn, "ephemeral", &event(1, 0, "swept")).unwrap();
        insert_capture_event(&conn, "no_metadata", &event(1, 0, "orphan")).unwrap();

        sweep_non_persistent(&conn).unwrap();

        assert_eq!(event_count(&conn, "pinned"), 1);
        assert_eq!(event_count(&conn, "ephemeral"), 0);
        assert_eq!(event_count(&conn, "no_metadata"), 0);
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM frames WHERE capture_id = 'c1'"),
            0,
            "c1 has no metadata row"
        );
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM bytes"), 1);
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM capture_metadata"), 1);
    }
}
