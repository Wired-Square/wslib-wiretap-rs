//! Spread sampling reads in two passes, not one window function: `ROW_NUMBER() OVER
//! (ORDER BY rowid)` sorts every matching row into a temp b-tree though the covering
//! index already yields them in rowid order, measured at 7× the cost of striding the
//! index's rowids here and reading back only the survivors.

use rusqlite::Connection;
use wiretap_gateway::{CaptureProtocol, FrameRowFilter, Sql, SqlValue};

use crate::error::{CaptureError, Result};
use crate::query::read_all;

/// At most `limit` items spread evenly across `items`. The step rounds up: rounding
/// down over 5,001 items for 5,000 takes the first 5,000 and drops the tail.
fn strided<T: Copy>(items: &[T], limit: u32) -> Vec<T> {
    let limit = limit.max(1) as usize;
    if items.len() <= limit {
        return items.to_vec();
    }
    items
        .iter()
        .step_by(items.len().div_ceil(limit))
        .copied()
        .collect()
}

fn frame_filter(
    capture_id: &str,
    protocol: Option<&str>,
    frame_id: u32,
    is_extended: Option<bool>,
) -> Result<Sql> {
    let protocols = protocol
        .map(|p| {
            CaptureProtocol::from_stored(p).ok_or_else(|| CaptureError::UnknownProtocol(p.into()))
        })
        .transpose()?
        .into_iter()
        .collect();
    let filter = FrameRowFilter {
        frame_id: Some(frame_id),
        is_extended,
        protocols,
        ..Default::default()
    };
    Ok(filter.sql_where(capture_id))
}

/// Up to `sample_limit` of one frame's payloads, spread evenly across the whole
/// capture, oldest first; `None` matches any protocol or extension. Passing
/// `is_extended` costs a row lookup per row, so leave it `None` when the id is
/// unambiguous.
pub fn sample_frame_payloads(
    conn: &Connection,
    capture_id: &str,
    protocol: Option<&str>,
    frame_id: u32,
    is_extended: Option<bool>,
    sample_limit: u32,
) -> Result<Vec<Vec<u8>>> {
    let filter = frame_filter(capture_id, protocol, frame_id, is_extended)?;
    let rowids = read_all(
        conn,
        &Sql {
            sql: format!(
                "SELECT rowid FROM frames WHERE {} ORDER BY rowid",
                filter.sql
            ),
            values: filter.values,
        },
        |row| row.get::<_, i64>(0),
    )?;
    let picked = strided(&rowids, sample_limit);
    if picked.is_empty() {
        return Ok(Vec::new());
    }
    read_all(
        conn,
        &Sql {
            sql: "SELECT payload FROM frames WHERE rowid IN (SELECT value FROM json_each(?)) ORDER BY rowid".into(),
            values: vec![SqlValue::Text(serde_json::Value::from(picked).to_string())],
        },
        |row| row.get(0),
    )
}

/// One frame's newest `limit` payloads, oldest first and contiguous: what byte roles
/// read, where a stride would multiply a counter's step.
pub fn tail_frame_payloads(
    conn: &Connection,
    capture_id: &str,
    protocol: Option<&str>,
    frame_id: u32,
    is_extended: Option<bool>,
    limit: u32,
) -> Result<Vec<Vec<u8>>> {
    let filter = frame_filter(capture_id, protocol, frame_id, is_extended)?;
    let mut statement = Sql {
        sql: format!(
            "SELECT payload FROM frames WHERE {} ORDER BY rowid DESC LIMIT ?",
            filter.sql
        ),
        values: filter.values,
    };
    statement
        .values
        .push(SqlValue::Integer(limit.max(1).into()));
    let mut payloads = read_all(conn, &statement, |row| row.get::<_, Vec<u8>>(0))?;
    payloads.reverse();
    Ok(payloads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::multi_protocol_capture;

    /// `n` CAN frames of one id, each payload its own position.
    fn can_capture_of(n: i64) -> Connection {
        let conn = crate::schema::migrated();
        for i in 0..n {
            conn.execute(
                "INSERT INTO frames (capture_id, protocol, timestamp_us, frame_id, bus, dlc, payload)
                 VALUES ('c1', 'can', ?1, 256, 0, 1, ?2)",
                rusqlite::params![i, vec![i as u8]],
            )
            .unwrap();
        }
        conn
    }

    fn positions(payloads: &[Vec<u8>]) -> Vec<u8> {
        payloads.iter().map(|p| p[0]).collect()
    }

    #[test]
    fn sampled_payloads_do_not_cross_protocols() {
        let conn = multi_protocol_capture();

        let can = sample_frame_payloads(&conn, "c1", Some("can"), 256, None, 100).unwrap();
        let modbus = sample_frame_payloads(&conn, "c1", Some("modbus"), 256, None, 100).unwrap();

        assert_eq!(can, [[0xAA]]);
        assert_eq!(modbus, [[0xBB]]);
    }

    #[test]
    fn sampled_payloads_without_a_protocol_span_all_of_them() {
        let conn = multi_protocol_capture();

        let all = sample_frame_payloads(&conn, "c1", None, 256, None, 100).unwrap();

        assert_eq!(all, [[0xAA], [0xBB], [0xCC]]);
    }

    #[test]
    fn an_unknown_protocol_is_refused() {
        let conn = multi_protocol_capture();

        let err = sample_frame_payloads(&conn, "c1", Some("lin"), 256, None, 100).unwrap_err();

        assert_eq!(err.to_string(), "Unknown protocol 'lin'");
    }

    /// A tail query answered 90..=99 and a head query 0..=9: each a different answer
    /// depending on the door the caller came in by.
    #[test]
    fn sampling_strides_the_whole_capture() {
        let conn = can_capture_of(100);

        let sampled = sample_frame_payloads(&conn, "c1", Some("can"), 256, None, 10).unwrap();

        assert_eq!(positions(&sampled), [0, 10, 20, 30, 40, 50, 60, 70, 80, 90]);
    }

    #[test]
    fn sampling_never_degenerates_into_the_first_n() {
        let conn = can_capture_of(101);

        let sampled = sample_frame_payloads(&conn, "c1", Some("can"), 256, None, 100).unwrap();

        assert_eq!(
            (sampled.first().unwrap()[0], sampled.last().unwrap()[0]),
            (0, 100)
        );
    }

    #[test]
    fn sampling_limit_past_the_end_returns_everything() {
        let conn = can_capture_of(40);

        let all = sample_frame_payloads(&conn, "c1", Some("can"), 256, None, 500).unwrap();

        assert_eq!(positions(&all), (0..40u8).collect::<Vec<_>>());
    }

    #[test]
    fn the_tail_is_the_newest_run_oldest_first() {
        let conn = can_capture_of(100);

        let tail = tail_frame_payloads(&conn, "c1", Some("can"), 256, None, 10).unwrap();

        assert_eq!(positions(&tail), (90..100u8).collect::<Vec<_>>());
    }

    #[test]
    fn the_tail_past_the_population_is_everything_in_order() {
        let conn = can_capture_of(40);

        let tail = tail_frame_payloads(&conn, "c1", Some("can"), 256, None, 500).unwrap();

        assert_eq!(positions(&tail), (0..40u8).collect::<Vec<_>>());
    }

    #[test]
    fn the_tail_does_not_cross_protocols() {
        let conn = multi_protocol_capture();

        let modbus = tail_frame_payloads(&conn, "c1", Some("modbus"), 256, None, 100).unwrap();

        assert_eq!(modbus, [[0xBB]]);
    }

    /// Filtering on `is_extended`, which `idx_frames_capture_fid` lacks, or a window
    /// function both take the rowid pass off the covering plan.
    #[test]
    fn payload_sampling_takes_its_rowids_from_the_covering_index() {
        let conn = multi_protocol_capture();
        let filter = frame_filter("c1", Some("can"), 256, None).unwrap();

        let plan: String = conn
            .query_row(
                &format!(
                    "EXPLAIN QUERY PLAN SELECT rowid FROM frames WHERE {} ORDER BY rowid",
                    filter.sql
                ),
                rusqlite::params!["c1", 256i64, "can"],
                |row| row.get(3),
            )
            .unwrap();

        assert!(
            plan.contains("COVERING INDEX idx_frames_capture_fid"),
            "rowid pass should stay covering, got: {plan}"
        );
        assert!(
            !plan.contains("TEMP B-TREE"),
            "rowid pass should not sort, got: {plan}"
        );
    }
}
