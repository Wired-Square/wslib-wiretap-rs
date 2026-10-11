use rusqlite::Connection;
use wiretap_analysis::source::InventoryRow;
use wiretap_gateway::{FrameRowFilter, Sql, SqlValue};

use crate::error::Result;
use crate::frames::STORED_LENGTH;
use crate::query::read_all;

/// The statement for a filter's identities, one row each, in the column order
/// [`inventory_row`] reads; `limit` adds a bound `LIMIT`.
pub fn inventory_statement(capture_id: &str, filter: &FrameRowFilter, limit: Option<u32>) -> Sql {
    let filter = filter.sql_where(capture_id);
    let mut statement = Sql {
        sql: format!(
            "SELECT protocol, frame_id, is_extended, COUNT(*), MIN(timestamp_us), MAX(timestamp_us), MAX({STORED_LENGTH}) \
             FROM frames WHERE {} \
             GROUP BY protocol, frame_id, is_extended ORDER BY frame_id, protocol, is_extended{}",
            filter.sql,
            if limit.is_some() { " LIMIT ?" } else { "" }
        ),
        values: filter.values,
    };
    statement
        .values
        .extend(limit.map(|n| SqlValue::Integer(n.into())));
    statement
}

pub fn inventory_row(row: &rusqlite::Row) -> rusqlite::Result<InventoryRow> {
    Ok(InventoryRow::new(
        &row.get::<_, String>(0)?,
        row.get::<_, i64>(1)? as u32,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get::<_, i64>(6)? as u16,
    ))
}

/// Every identity in a capture within `start_us..end_us`, with its rollup.
pub fn frame_inventory(
    conn: &Connection,
    capture_id: &str,
    start_us: Option<i64>,
    end_us: Option<i64>,
) -> Result<Vec<InventoryRow>> {
    let filter = FrameRowFilter {
        start_us,
        end_us,
        ..Default::default()
    };
    read_all(
        conn,
        &inventory_statement(capture_id, &filter, None),
        inventory_row,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::multi_protocol_capture;

    /// The inventory decides which groups a scan reads, so it splits the identity pair too.
    #[test]
    fn inventory_reports_one_row_per_protocol() {
        let conn = multi_protocol_capture();

        let rows = frame_inventory(&conn, "c1", None, None).unwrap();

        let for_256: Vec<(&str, i64)> = rows
            .iter()
            .filter(|r| r.frame_id == 256)
            .map(|r| (r.protocol.as_str(), r.count))
            .collect();
        assert_eq!(for_256, [("can", 1), ("modbus", 1), ("serial", 1)]);
        assert_eq!(rows.len(), 4);
    }

    #[test]
    fn the_window_is_start_inclusive_and_end_exclusive() {
        let conn = multi_protocol_capture();

        let rows = frame_inventory(&conn, "c1", Some(20), Some(40)).unwrap();

        assert_eq!(
            rows.iter()
                .map(|r| (r.protocol.as_str(), r.first_us, r.last_us))
                .collect::<Vec<_>>(),
            [("modbus", 20, 20), ("serial", 30, 30)]
        );
    }

    #[test]
    fn the_stored_length_is_the_inventorys_max_dlc() {
        let conn = crate::schema::migrated();
        conn.execute(
            "INSERT INTO frames (capture_id, protocol, timestamp_us, frame_id, bus, dlc, payload, is_fd, is_rtr)
             VALUES ('c1', 'can', 1, 256, 0, 15, ?1, 1, 0), ('c1', 'can', 2, 257, 0, 6, x'', 0, 1)",
            [vec![0u8; 64]],
        )
        .unwrap();

        let rows = frame_inventory(&conn, "c1", None, None).unwrap();

        assert_eq!(rows.iter().map(|r| r.max_dlc).collect::<Vec<_>>(), [64, 6]);
    }

    #[test]
    fn the_statement_is_the_one_the_desktop_shows() {
        let filter = FrameRowFilter {
            start_us: Some(1),
            end_us: Some(2),
            ..Default::default()
        };
        assert_eq!(
            inventory_statement("c'1", &filter, None).inlined(),
            "SELECT protocol, frame_id, is_extended, COUNT(*), MIN(timestamp_us), MAX(timestamp_us), \
             MAX(MAX(dlc, length(payload))) FROM frames WHERE capture_id = 'c''1' AND timestamp_us >= 1 \
             AND timestamp_us < 2 GROUP BY protocol, frame_id, is_extended ORDER BY frame_id, protocol, is_extended"
        );
    }

    #[test]
    fn a_limit_is_bound_last() {
        let conn = multi_protocol_capture();
        let statement = inventory_statement("c1", &FrameRowFilter::default(), Some(2));

        assert!(statement.sql.ends_with(" LIMIT ?"));
        assert_eq!(statement.values.last(), Some(&SqlValue::Integer(2)));
        assert_eq!(read_all(&conn, &statement, inventory_row).unwrap().len(), 2);
    }
}
