use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use wiretap_gateway::{Event, NewEvent};

use crate::error::{CaptureError, Result};

const EVENT_COLUMNS: &str = "id, timestamp_us, duration_us, note, created_at_us, updated_at_us";

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as i64)
}

fn row_to_event(row: &rusqlite::Row) -> rusqlite::Result<Event> {
    Ok(Event {
        id: row.get(0)?,
        ts_us: row.get(1)?,
        duration_us: row.get(2)?,
        note: row.get(3)?,
        created_at_us: row.get(4)?,
        updated_at_us: row.get(5)?,
    })
}

/// A capture's events by time, then by id.
pub fn list_capture_events(conn: &Connection, capture_id: &str) -> Result<Vec<Event>> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {EVENT_COLUMNS} FROM capture_events WHERE capture_id = ?1 ORDER BY timestamp_us, id"
    ))?;
    let events = stmt
        .query_map(params![capture_id], row_to_event)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(events)
}

pub fn insert_capture_event(
    conn: &Connection,
    capture_id: &str,
    event: &NewEvent,
) -> Result<Event> {
    let event = conn.query_row(
        &format!(
            "INSERT INTO capture_events (capture_id, timestamp_us, duration_us, note, created_at_us, updated_at_us)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5) RETURNING {EVENT_COLUMNS}"
        ),
        params![capture_id, event.ts_us, event.duration_us, event.note, now_us()],
        row_to_event,
    )?;
    Ok(event)
}

/// Replace an event's time, duration and note; [`CaptureError::EventNotFound`] unless
/// the capture holds `id`.
pub fn update_capture_event(
    conn: &Connection,
    capture_id: &str,
    id: i64,
    event: &NewEvent,
) -> Result<Event> {
    conn.query_row(
        &format!(
            "UPDATE capture_events SET timestamp_us = ?3, duration_us = ?4, note = ?5, updated_at_us = ?6
             WHERE capture_id = ?1 AND id = ?2 RETURNING {EVENT_COLUMNS}"
        ),
        params![capture_id, id, event.ts_us, event.duration_us, event.note, now_us()],
        row_to_event,
    )
    .optional()?
    .ok_or(CaptureError::EventNotFound)
}

/// [`CaptureError::EventNotFound`] unless the capture holds `id`.
pub fn delete_capture_event(conn: &Connection, capture_id: &str, id: i64) -> Result<()> {
    let changed = conn.execute(
        "DELETE FROM capture_events WHERE capture_id = ?1 AND id = ?2",
        params![capture_id, id],
    )?;
    if changed == 0 {
        return Err(CaptureError::EventNotFound);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn event(ts_us: i64, duration_us: i64, note: &str) -> NewEvent {
    NewEvent {
        ts_us,
        duration_us,
        note: note.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_round_trip_in_timestamp_order() {
        let conn = crate::schema::migrated();
        let later = insert_capture_event(&conn, "c1", &event(30, 0, "later")).unwrap();
        let earlier = insert_capture_event(&conn, "c1", &event(10, 5, "earlier")).unwrap();
        insert_capture_event(&conn, "c2", &event(20, 0, "other capture")).unwrap();

        let listed = list_capture_events(&conn, "c1").unwrap();
        assert_eq!(
            listed.iter().map(|e| e.id).collect::<Vec<_>>(),
            [earlier.id, later.id]
        );
        assert_eq!(listed[0].duration_us, 5);
        assert_eq!(listed[0].created_at_us, listed[0].updated_at_us);

        let updated =
            update_capture_event(&conn, "c1", later.id, &event(30, 7, "renamed")).unwrap();
        assert_eq!(
            (updated.ts_us, updated.duration_us, updated.note.as_str()),
            (30, 7, "renamed")
        );
        assert!(updated.updated_at_us >= updated.created_at_us);

        delete_capture_event(&conn, "c1", earlier.id).unwrap();
        assert_eq!(list_capture_events(&conn, "c1").unwrap().len(), 1);
        assert!(matches!(
            delete_capture_event(&conn, "c1", earlier.id),
            Err(CaptureError::EventNotFound)
        ));
        assert!(matches!(
            update_capture_event(&conn, "c2", later.id, &event(30, 7, "wrong capture")),
            Err(CaptureError::EventNotFound)
        ));
        assert_eq!(list_capture_events(&conn, "c2").unwrap().len(), 1);
    }
}
