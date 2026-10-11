use rusqlite::{params, Connection};

use crate::error::Result;
use crate::model::TimestampedByte;

const BYTE_COLUMNS: &str = "byte_val, timestamp_us, bus";

fn row_to_byte(row: &rusqlite::Row) -> rusqlite::Result<TimestampedByte> {
    Ok(TimestampedByte {
        byte: row.get::<_, i64>(0)? as u8,
        timestamp_us: row.get::<_, i64>(1)? as u64,
        bus: row.get::<_, i64>(2)? as u8,
    })
}

fn read_bytes(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<TimestampedByte>> {
    let mut stmt = conn.prepare_cached(sql)?;
    let bytes = stmt
        .query_map(params, row_to_byte)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(bytes)
}

/// Append `bytes` to a capture in one transaction.
pub fn insert_bytes(
    conn: &mut Connection,
    capture_id: &str,
    bytes: &[TimestampedByte],
) -> Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO bytes (capture_id, byte_val, timestamp_us, bus) VALUES (?1, ?2, ?3, ?4)",
        )?;
        for b in bytes {
            stmt.execute(params![
                capture_id,
                b.byte as i64,
                b.timestamp_us as i64,
                b.bus as i64
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// A page of a capture's bytes in capture order, with how many it holds.
pub fn get_bytes_paginated(
    conn: &Connection,
    capture_id: &str,
    offset: usize,
    limit: usize,
) -> Result<(Vec<TimestampedByte>, usize)> {
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM bytes WHERE capture_id = ?1",
        params![capture_id],
        |row| row.get(0),
    )?;
    let bytes = read_bytes(
        conn,
        &format!("SELECT {BYTE_COLUMNS} FROM bytes WHERE capture_id = ?1 ORDER BY rowid LIMIT ?2 OFFSET ?3"),
        params![capture_id, limit as i64, offset as i64],
    )?;
    Ok((bytes, total as usize))
}

/// A capture's newest `limit` bytes, oldest first. Rows only, and no `OFFSET`: the live
/// view refetches it on every count signal, and walking the skipped rows is quadratic
/// over a session.
pub fn get_bytes_tail_rows(
    conn: &Connection,
    capture_id: &str,
    limit: usize,
) -> Result<Vec<TimestampedByte>> {
    let mut bytes = read_bytes(
        conn,
        &format!(
            "SELECT {BYTE_COLUMNS} FROM bytes WHERE capture_id = ?1 ORDER BY rowid DESC LIMIT ?2"
        ),
        params![capture_id, limit as i64],
    )?;
    bytes.reverse();
    Ok(bytes)
}

/// Every byte in a capture, in capture order: framing reads the whole stream.
pub fn get_all_bytes(conn: &Connection, capture_id: &str) -> Result<Vec<TimestampedByte>> {
    read_bytes(
        conn,
        &format!("SELECT {BYTE_COLUMNS} FROM bytes WHERE capture_id = ?1 ORDER BY rowid"),
        params![capture_id],
    )
}

/// How many of a capture's bytes come before `target_us`.
pub fn find_bytes_offset_for_timestamp(
    conn: &Connection,
    capture_id: &str,
    target_us: u64,
) -> Result<usize> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM bytes WHERE capture_id = ?1 AND timestamp_us < ?2",
        params![capture_id, target_us as i64],
        |row| row.get(0),
    )?;
    Ok(count as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Six bytes in `b1`, and a decoy capture whose rows must never appear in its tail.
    fn byte_capture() -> Connection {
        let mut conn = crate::schema::migrated();
        let byte = |byte, timestamp_us, bus| TimestampedByte {
            byte,
            timestamp_us,
            bus,
        };
        insert_bytes(
            &mut conn,
            "b1",
            &[
                byte(10, 100, 0),
                byte(11, 101, 0),
                byte(12, 102, 1),
                byte(13, 103, 0),
                byte(14, 104, 0),
                byte(15, 105, 0),
            ],
        )
        .unwrap();
        insert_bytes(&mut conn, "b2", &[byte(99, 106, 0)]).unwrap();
        conn
    }

    fn values(bytes: &[TimestampedByte]) -> Vec<u8> {
        bytes.iter().map(|b| b.byte).collect()
    }

    #[test]
    fn bytes_tail_returns_last_rows_chronologically() {
        let conn = byte_capture();

        let bytes = get_bytes_tail_rows(&conn, "b1", 3).unwrap();

        assert_eq!(values(&bytes), [13, 14, 15]);
        assert_eq!(
            bytes.iter().map(|b| b.timestamp_us).collect::<Vec<_>>(),
            [103, 104, 105]
        );
        assert_eq!(bytes[0].bus, 0);
    }

    #[test]
    fn bytes_tail_limit_past_start_returns_all() {
        let conn = byte_capture();

        let bytes = get_bytes_tail_rows(&conn, "b1", 100).unwrap();

        assert_eq!(values(&bytes), [10, 11, 12, 13, 14, 15]);
    }

    #[test]
    fn bytes_tail_matches_equivalent_page() {
        let conn = byte_capture();

        let tail = get_bytes_tail_rows(&conn, "b1", 2).unwrap();
        let (page, total) = get_bytes_paginated(&conn, "b1", 4, 2).unwrap();

        assert_eq!(total, 6);
        assert_eq!(tail, page);
    }

    #[test]
    fn all_bytes_and_the_offset_for_a_timestamp_stay_in_their_capture() {
        let conn = byte_capture();

        assert_eq!(
            get_all_bytes(&conn, "b1").unwrap()[2],
            TimestampedByte {
                byte: 12,
                timestamp_us: 102,
                bus: 1
            }
        );
        assert_eq!(values(&get_all_bytes(&conn, "b2").unwrap()), [99]);
        assert_eq!(
            find_bytes_offset_for_timestamp(&conn, "b1", 103).unwrap(),
            3
        );
        assert_eq!(
            find_bytes_offset_for_timestamp(&conn, "b1", 1000).unwrap(),
            6
        );
    }
}
