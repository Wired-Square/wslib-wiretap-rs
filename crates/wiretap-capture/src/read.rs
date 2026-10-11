use rusqlite::{params, Connection, OptionalExtension, ToSql};
use wiretap_analysis::source::FrameSelection;

use crate::error::Result;
use crate::frames::{
    row_to_frame, row_to_frame_with_rowid, StoredFrame, FRAME_COLUMNS, STORED_LENGTH,
};
use crate::model::CaptureFrameInfo;

/// Frames and their rowids, parallel and oldest first.
type Page = (Vec<StoredFrame>, Vec<i64>);

/// Restrict a frame query to a selection, bound as the one JSON parameter `?{param}`:
/// constant SQL text per shape, so `prepare_cached` hits, no parameter ceiling, and
/// the protocol bound rather than quoted. The text follows the shape because the
/// planner doesn't: a pair-only selection seeks `idx_frames_capture_fid` as a
/// covering index, where an `OR` on the protocol arm scans the capture.
pub(crate) fn selection_predicate(param: usize, selection: &FrameSelection) -> String {
    let by_pair = format!(
        "(frame_id, protocol) IN (SELECT j.value ->> 0, j.value ->> 1 FROM json_each(?{param}, '$.pairs') j)"
    );
    let by_protocol = format!("protocol IN (SELECT value FROM json_each(?{param}, '$.protocols'))");
    match (
        selection.protocols().is_empty(),
        selection.pairs().is_empty(),
    ) {
        (true, _) => format!("AND {by_pair}"),
        (false, true) => format!("AND {by_protocol}"),
        (false, false) => format!("AND ({by_protocol} OR {by_pair})"),
    }
}

pub(crate) fn selection_json(selection: &FrameSelection) -> String {
    serde_json::json!({ "protocols": selection.protocols(), "pairs": selection.pairs() })
        .to_string()
}

/// The predicate and its parameter, both empty for an empty selection.
fn optional_selection(param: usize, selection: &FrameSelection) -> (String, Option<String>) {
    if selection.is_empty() {
        (String::new(), None)
    } else {
        (
            selection_predicate(param, selection),
            Some(selection_json(selection)),
        )
    }
}

fn frames_with_rowids(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<(i64, StoredFrame)>> {
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt
        .query_map(params, row_to_frame_with_rowid)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

fn frames(conn: &Connection, sql: &str, capture_id: &str) -> Result<Vec<StoredFrame>> {
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt
        .query_map(params![capture_id], row_to_frame)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

fn page(rows: Vec<(i64, StoredFrame)>) -> Page {
    let (rowids, frames) = rows.into_iter().unzip();
    (frames, rowids)
}

fn tail(mut rows: Vec<(i64, StoredFrame)>) -> Page {
    rows.reverse();
    page(rows)
}

fn count(conn: &Connection, sql: &str, params: impl rusqlite::Params) -> Result<usize> {
    Ok(conn.query_row(sql, params, |row| row.get::<_, i64>(0))? as usize)
}

fn selection_count(
    conn: &Connection,
    capture_id: &str,
    selection: &FrameSelection,
    pairs: &str,
) -> Result<usize> {
    count(
        conn,
        &format!(
            "SELECT COUNT(*) FROM frames WHERE capture_id = ?1 {}",
            selection_predicate(2, selection)
        ),
        params![capture_id, pairs],
    )
}

/// A page of a capture's frames in capture order.
pub fn get_frames_paginated(
    conn: &Connection,
    capture_id: &str,
    offset: usize,
    limit: usize,
) -> Result<Page> {
    let sql = format!(
        "SELECT {FRAME_COLUMNS} FROM frames WHERE capture_id = ?1 ORDER BY rowid LIMIT ?2 OFFSET ?3"
    );
    frames_with_rowids(conn, &sql, params![capture_id, limit as i64, offset as i64]).map(page)
}

/// A page of a selection's frames in capture order, with how many the selection holds.
pub fn get_frames_paginated_filtered(
    conn: &Connection,
    capture_id: &str,
    offset: usize,
    limit: usize,
    selection: &FrameSelection,
) -> Result<(Vec<StoredFrame>, Vec<i64>, usize)> {
    if selection.is_empty() {
        let (frames, rowids) = get_frames_paginated(conn, capture_id, offset, limit)?;
        return Ok((frames, rowids, get_frame_count(conn, capture_id)?));
    }
    let pairs = selection_json(selection);
    let total = selection_count(conn, capture_id, selection, &pairs)?;
    let sql = format!(
        "SELECT {FRAME_COLUMNS} FROM frames WHERE capture_id = ?1 {} ORDER BY rowid LIMIT ?2 OFFSET ?3",
        selection_predicate(4, selection)
    );
    let (frames, rowids) = page(frames_with_rowids(
        conn,
        &sql,
        params![capture_id, limit as i64, offset as i64, pairs],
    )?);
    Ok((frames, rowids, total))
}

/// A capture's newest `limit` frames, oldest first. Rows only: the live view refetches
/// it on every count signal, so it must not scan the capture.
pub fn get_frames_tail_rows(conn: &Connection, capture_id: &str, limit: usize) -> Result<Page> {
    let sql = format!(
        "SELECT {FRAME_COLUMNS} FROM frames WHERE capture_id = ?1 ORDER BY rowid DESC LIMIT ?2"
    );
    frames_with_rowids(conn, &sql, params![capture_id, limit as i64]).map(tail)
}

/// A non-empty selection's newest `limit` frames, oldest first, with how many it holds.
pub fn get_frames_tail_filtered(
    conn: &Connection,
    capture_id: &str,
    limit: usize,
    selection: &FrameSelection,
) -> Result<(Vec<StoredFrame>, Vec<i64>, usize)> {
    debug_assert!(!selection.is_empty(), "use get_frames_tail_rows");
    let pairs = selection_json(selection);
    let total = selection_count(conn, capture_id, selection, &pairs)?;
    let sql = format!(
        "SELECT {FRAME_COLUMNS} FROM frames WHERE capture_id = ?1 {} ORDER BY rowid DESC LIMIT ?2",
        selection_predicate(3, selection)
    );
    let (frames, rowids) = tail(frames_with_rowids(
        conn,
        &sql,
        params![capture_id, limit as i64, pairs],
    )?);
    Ok((frames, rowids, total))
}

pub fn get_frame_count(conn: &Connection, capture_id: &str) -> Result<usize> {
    count(
        conn,
        "SELECT COUNT(*) FROM frames WHERE capture_id = ?1",
        params![capture_id],
    )
}

/// The protocols other than CAN a capture holds, alphabetically.
pub fn non_can_protocols(conn: &Connection, capture_id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT protocol FROM frames WHERE capture_id = ?1 AND protocol != 'can' ORDER BY protocol",
    )?;
    let protocols = stmt
        .query_map(params![capture_id], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(protocols)
}

/// One row per frame identity in a capture.
pub fn get_frame_info(conn: &Connection, capture_id: &str) -> Result<Vec<CaptureFrameInfo>> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT protocol, frame_id, MAX({STORED_LENGTH}) as max_dlc, MIN(bus) as bus, MAX(is_extended) as is_extended,
                (MIN({STORED_LENGTH}) != MAX({STORED_LENGTH})) as has_dlc_mismatch
         FROM frames WHERE capture_id = ?1 GROUP BY protocol, frame_id",
    ))?;
    let info = stmt
        .query_map(params![capture_id], |row| {
            Ok(CaptureFrameInfo {
                protocol: row.get("protocol")?,
                frame_id: row.get::<_, i64>("frame_id")? as u32,
                max_dlc: row.get::<_, i64>("max_dlc")? as u16,
                bus: row.get::<_, i64>("bus")? as u8,
                is_extended: row.get::<_, i64>("is_extended")? != 0,
                has_dlc_mismatch: row.get::<_, i64>("has_dlc_mismatch")? != 0,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(info)
}

/// How many of a selection's frames come before `target_us`.
pub fn find_offset_for_timestamp(
    conn: &Connection,
    capture_id: &str,
    target_us: u64,
    selection: &FrameSelection,
) -> Result<usize> {
    let (predicate, json) = optional_selection(3, selection);
    let sql = format!(
        "SELECT COUNT(*) FROM frames WHERE capture_id = ?1 AND timestamp_us < ?2 {predicate}"
    );
    let target = target_us as i64;
    let mut values: Vec<&dyn ToSql> = vec![&capture_id, &target];
    values.extend(json.as_ref().map(|j| j as &dyn ToSql));
    count(conn, &sql, values.as_slice())
}

/// Every frame in a capture, in capture order; for a capture known to be small.
pub fn get_all_frames(conn: &Connection, capture_id: &str) -> Result<Vec<StoredFrame>> {
    frames(
        conn,
        &format!("SELECT {FRAME_COLUMNS} FROM frames WHERE capture_id = ?1 ORDER BY rowid"),
        capture_id,
    )
}

/// The newest frame of each identity in a capture, by frame id: a Modbus sweep's
/// values without every pass that wrote them.
pub fn get_latest_frames(conn: &Connection, capture_id: &str) -> Result<Vec<StoredFrame>> {
    frames(
        conn,
        &format!(
            "SELECT {FRAME_COLUMNS} FROM frames
             WHERE rowid IN (
                 SELECT MAX(rowid) FROM frames WHERE capture_id = ?1 GROUP BY protocol, frame_id
             )
             ORDER BY frame_id"
        ),
        capture_id,
    )
}

/// Up to `limit` frames after `after_rowid`, oldest first.
pub fn read_frame_chunk(
    conn: &Connection,
    capture_id: &str,
    after_rowid: i64,
    limit: usize,
) -> Result<Vec<(i64, StoredFrame)>> {
    let sql = format!(
        "SELECT {FRAME_COLUMNS} FROM frames WHERE capture_id = ?1 AND rowid > ?2 ORDER BY rowid ASC LIMIT ?3"
    );
    frames_with_rowids(conn, &sql, params![capture_id, after_rowid, limit as i64])
}

/// Up to `limit` frames before `before_rowid`, newest first.
pub fn read_frame_chunk_reverse(
    conn: &Connection,
    capture_id: &str,
    before_rowid: i64,
    limit: usize,
) -> Result<Vec<(i64, StoredFrame)>> {
    let sql = format!(
        "SELECT {FRAME_COLUMNS} FROM frames WHERE capture_id = ?1 AND rowid < ?2 ORDER BY rowid DESC LIMIT ?3"
    );
    frames_with_rowids(conn, &sql, params![capture_id, before_rowid, limit as i64])
}

/// A capture's first and last rowid, `None` when it holds no frames.
pub fn get_rowid_range(conn: &Connection, capture_id: &str) -> Result<Option<(i64, i64)>> {
    let range = conn.query_row(
        "SELECT MIN(rowid), MAX(rowid) FROM frames WHERE capture_id = ?1",
        params![capture_id],
        |row| Ok(row.get::<_, Option<i64>>(0)?.zip(row.get(1)?)),
    )?;
    Ok(range)
}

/// The first frame at or after `timestamp_us`.
pub fn find_rowid_for_timestamp(
    conn: &Connection,
    capture_id: &str,
    timestamp_us: u64,
) -> Result<Option<i64>> {
    let rowid = conn
        .query_row(
            "SELECT rowid FROM frames WHERE capture_id = ?1 AND timestamp_us >= ?2 ORDER BY timestamp_us ASC, rowid ASC LIMIT 1",
            params![capture_id, timestamp_us as i64],
            |row| row.get(0),
        )
        .optional()?;
    Ok(rowid)
}

/// The frame at 0-based `index` in capture order.
pub fn get_frame_at_index(
    conn: &Connection,
    capture_id: &str,
    index: usize,
) -> Result<Option<(i64, StoredFrame)>> {
    let frame = conn
        .query_row(
            &format!(
                "SELECT {FRAME_COLUMNS} FROM frames WHERE capture_id = ?1 ORDER BY rowid LIMIT 1 OFFSET ?2"
            ),
            params![capture_id, index as i64],
            row_to_frame_with_rowid,
        )
        .optional()?;
    Ok(frame)
}

/// The selection's next frame after `current_rowid`, or previous one before it, with
/// its 0-based index in the whole capture.
pub fn get_next_filtered_frame(
    conn: &Connection,
    capture_id: &str,
    current_rowid: i64,
    selection: &FrameSelection,
    backward: bool,
) -> Result<Option<(i64, usize, StoredFrame)>> {
    let (op, order) = if backward {
        ("<", "DESC")
    } else {
        (">", "ASC")
    };
    let (predicate, json) = optional_selection(3, selection);
    let sql = format!(
        "SELECT {FRAME_COLUMNS} FROM frames WHERE capture_id = ?1 AND rowid {op} ?2 {predicate} \
         ORDER BY rowid {order} LIMIT 1"
    );
    let mut values: Vec<&dyn ToSql> = vec![&capture_id, &current_rowid];
    values.extend(json.as_ref().map(|j| j as &dyn ToSql));
    let Some((rowid, frame)) = conn
        .query_row(&sql, values.as_slice(), row_to_frame_with_rowid)
        .optional()?
    else {
        return Ok(None);
    };
    let index = count_frames_before_rowid(conn, capture_id, rowid)?;
    Ok(Some((rowid, index, frame)))
}

/// How many of a capture's frames come before `rowid`: its 0-based index.
pub fn count_frames_before_rowid(conn: &Connection, capture_id: &str, rowid: i64) -> Result<usize> {
    count(
        conn,
        "SELECT COUNT(*) FROM frames WHERE capture_id = ?1 AND rowid < ?2",
        params![capture_id, rowid],
    )
}

#[cfg(test)]
pub(crate) fn multi_protocol_capture() -> Connection {
    let conn = crate::schema::migrated();
    conn.execute_batch(
        "INSERT INTO frames (capture_id, protocol, timestamp_us, frame_id, bus, dlc, payload)
         VALUES ('c1', 'can',    10, 256, 0, 8, x'AA'),
                ('c1', 'modbus', 20, 256, 0, 2, x'BB'),
                ('c1', 'serial', 30, 256, 0, 1, x'CC'),
                ('c1', 'can',    40, 257, 0, 8, x'DD');",
    )
    .unwrap();
    conn
}

#[cfg(test)]
pub(crate) fn selection(groups: &[(&str, &[u32])]) -> FrameSelection {
    use wiretap_analysis::source::ProtocolFrames;
    FrameSelection::from_groups(
        groups
            .iter()
            .map(|(protocol, ids)| ProtocolFrames::ids(*protocol, ids.to_vec()))
            .collect(),
    )
}

#[cfg(test)]
pub(crate) fn whole(protocol: &str) -> FrameSelection {
    FrameSelection::from_groups(vec![wiretap_analysis::source::ProtocolFrames::whole(
        protocol,
    )])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames::{can_frame, insert_frames};
    use wiretap_analysis::source::ProtocolFrames;

    fn ids(frames: &[StoredFrame]) -> Vec<(&str, u32)> {
        frames
            .iter()
            .map(|f| (f.protocol.as_str(), f.frame_id))
            .collect()
    }

    fn plan(conn: &Connection, sql: &str, params: impl rusqlite::Params) -> String {
        conn.query_row(&format!("EXPLAIN QUERY PLAN {sql}"), params, |row| {
            row.get(3)
        })
        .unwrap()
    }

    #[test]
    fn a_whole_protocol_selects_all_its_rows_and_no_others() {
        let conn = multi_protocol_capture();

        let (frames, _, total) =
            get_frames_paginated_filtered(&conn, "c1", 0, 50, &whole("can")).unwrap();
        assert_eq!(total, 2);
        assert_eq!(ids(&frames), [("can", 256), ("can", 257)]);

        let (tail, _, total) = get_frames_tail_filtered(&conn, "c1", 50, &whole("modbus")).unwrap();
        assert_eq!(total, 1);
        assert_eq!(tail[0].protocol, "modbus");

        let combined = FrameSelection::from_groups(vec![
            ProtocolFrames::whole("serial"),
            ProtocolFrames::ids("can", vec![257]),
        ]);
        let (frames, _, total) =
            get_frames_paginated_filtered(&conn, "c1", 0, 50, &combined).unwrap();
        assert_eq!(total, 2);
        let mut got = ids(&frames);
        got.sort_unstable();
        assert_eq!(got, [("can", 257), ("serial", 256)]);
    }

    /// A bare `frame_id IN (…)` matched CAN 0x100 and Modbus register 256 against each other.
    #[test]
    fn filtered_page_does_not_cross_protocols() {
        let conn = multi_protocol_capture();

        let (frames, _, total) =
            get_frames_paginated_filtered(&conn, "c1", 0, 50, &selection(&[("can", &[256])]))
                .unwrap();

        assert_eq!(total, 1);
        assert_eq!(ids(&frames), [("can", 256)]);
        assert_eq!(frames[0].len, 8);
    }

    #[test]
    fn filtered_tail_does_not_cross_protocols() {
        let conn = multi_protocol_capture();

        let (frames, _, total) =
            get_frames_tail_filtered(&conn, "c1", 50, &selection(&[("modbus", &[256])])).unwrap();

        assert_eq!(total, 1);
        assert_eq!(ids(&frames), [("modbus", 256)]);
    }

    #[test]
    fn selecting_one_id_on_two_protocols_returns_both() {
        let conn = multi_protocol_capture();

        let (frames, _, total) = get_frames_paginated_filtered(
            &conn,
            "c1",
            0,
            50,
            &selection(&[("can", &[256]), ("modbus", &[256])]),
        )
        .unwrap();

        assert_eq!(total, 2);
        assert_eq!(ids(&frames), [("can", 256), ("modbus", 256)]);
    }

    #[test]
    fn filtered_page_keeps_capture_order() {
        let conn = multi_protocol_capture();
        let all_can = selection(&[("can", &[256, 257])]);

        let (frames, _, total) =
            get_frames_paginated_filtered(&conn, "c1", 0, 50, &all_can).unwrap();
        assert_eq!(total, 2);
        assert_eq!(ids(&frames), [("can", 256), ("can", 257)]);

        let (page_two, _, total) =
            get_frames_paginated_filtered(&conn, "c1", 1, 1, &all_can).unwrap();
        assert_eq!(total, 2);
        assert_eq!(ids(&page_two), [("can", 257)]);
    }

    #[test]
    fn protocol_is_bound_not_interpolated() {
        let conn = multi_protocol_capture();

        let (frames, _, total) = get_frames_paginated_filtered(
            &conn,
            "c1",
            0,
            50,
            &selection(&[("can'); DROP TABLE frames;--", &[256])]),
        )
        .unwrap();

        assert_eq!(total, 0);
        assert!(frames.is_empty());
        assert_eq!(get_frame_count(&conn, "c1").unwrap(), 4);
    }

    /// The filtered COUNT runs on the live tail path; an `OR` on the protocol arm
    /// turned its seek into a walk of the capture at 200× the cost.
    #[test]
    fn filtered_count_uses_the_covering_index() {
        let conn = multi_protocol_capture();
        let by_id = selection(&[("can", &[256])]);

        let plan = plan(
            &conn,
            &format!(
                "SELECT COUNT(*) FROM frames WHERE capture_id = 'c1' {}",
                selection_predicate(1, &by_id)
            ),
            params![selection_json(&by_id)],
        );

        assert!(
            plan.contains("COVERING INDEX idx_frames_capture_fid") && plan.contains("frame_id=?"),
            "filtered count should seek the id on the covering index, got: {plan}"
        );
    }

    /// Without `idx_frames_capture_rowid` the tail sorts the whole capture into a
    /// temp b-tree, on a query Discovery reissues twice a second.
    #[test]
    fn rowid_index_serves_the_live_tail_query() {
        let conn = crate::schema::migrated();

        let plan = plan(
            &conn,
            &format!(
                "SELECT {FRAME_COLUMNS} FROM frames WHERE capture_id = 'c1' ORDER BY rowid DESC LIMIT 50"
            ),
            [],
        );

        assert!(
            plan.contains("idx_frames_capture_rowid"),
            "tail query should use the rowid index, got: {plan}"
        );
    }

    #[test]
    fn a_stored_length_code_reads_as_the_payload_length_and_an_rtr_keeps_its_requested_length() {
        let conn = crate::schema::migrated();
        conn.execute(
            "INSERT INTO frames (capture_id, protocol, timestamp_us, frame_id, bus, dlc, payload, is_fd, is_rtr)
             VALUES ('c1', 'can', 1, 256, 0, 15, ?1, 1, 0), ('c1', 'can', 2, 257, 0, 6, x'', 0, 1)",
            params![vec![0u8; 64]],
        )
        .unwrap();

        let (frames, _, _) =
            get_frames_paginated_filtered(&conn, "c1", 0, 10, &whole("can")).unwrap();
        assert_eq!(frames.iter().map(|f| f.len).collect::<Vec<_>>(), [64, 6]);

        let info = get_frame_info(&conn, "c1").unwrap();
        assert_eq!(
            info.iter()
                .map(|i| (i.max_dlc, i.has_dlc_mismatch))
                .collect::<Vec<_>>(),
            [(64, false), (6, false)]
        );
    }

    #[test]
    fn frame_info_flags_a_length_that_varies() {
        let mut conn = crate::schema::migrated();
        insert_frames(
            &mut conn,
            "c1",
            &[
                can_frame(1, &[1, 2]),
                StoredFrame {
                    bus: 2,
                    extended: true,
                    ..can_frame(1, &[1, 2, 3])
                },
            ],
        )
        .unwrap();

        let info = get_frame_info(&conn, "c1").unwrap();

        assert_eq!(
            info,
            [CaptureFrameInfo {
                protocol: "can".into(),
                frame_id: 1,
                max_dlc: 3,
                bus: 0,
                is_extended: true,
                has_dlc_mismatch: true,
            }]
        );
    }

    #[test]
    fn all_frames_come_back_in_insertion_order_with_their_bytes() {
        let mut conn = crate::schema::migrated();
        insert_frames(
            &mut conn,
            "c1",
            &[can_frame(0x200, &[1, 2]), can_frame(0x100, &[3])],
        )
        .unwrap();

        let frames = get_all_frames(&conn, "c1").unwrap();

        let summary: Vec<_> = frames
            .iter()
            .map(|f| (f.frame_id, f.payload.clone()))
            .collect();
        assert_eq!(summary, [(0x200, vec![1, 2]), (0x100, vec![3])]);
        assert!(get_all_frames(&conn, "no-such-capture").unwrap().is_empty());
    }

    #[test]
    fn the_latest_frames_are_one_per_identity_and_the_newest() {
        let mut conn = multi_protocol_capture();
        insert_frames(&mut conn, "c1", &[can_frame(256, &[0xEE])]).unwrap();

        let latest = get_latest_frames(&conn, "c1").unwrap();

        let mut got: Vec<_> = latest
            .iter()
            .map(|f| (f.protocol.as_str(), f.frame_id, f.payload[0]))
            .collect();
        got.sort_unstable();
        assert_eq!(
            got,
            [
                ("can", 256, 0xEE),
                ("can", 257, 0xDD),
                ("modbus", 256, 0xBB),
                ("serial", 256, 0xCC)
            ]
        );
        assert_eq!(
            non_can_protocols(&conn, "c1").unwrap(),
            ["modbus", "serial"]
        );
    }

    #[test]
    fn the_unfiltered_tail_is_the_newest_rows_oldest_first() {
        let conn = multi_protocol_capture();

        let (frames, rowids) = get_frames_tail_rows(&conn, "c1", 2).unwrap();

        assert_eq!(ids(&frames), [("serial", 256), ("can", 257)]);
        assert_eq!(rowids, [3, 4]);
        let (page, page_rowids) = get_frames_paginated(&conn, "c1", 2, 2).unwrap();
        assert_eq!((page, page_rowids), (frames, rowids));
    }

    #[test]
    fn playback_walks_the_capture_by_rowid_and_time() {
        let conn = multi_protocol_capture();

        assert_eq!(get_rowid_range(&conn, "c1").unwrap(), Some((1, 4)));
        assert_eq!(get_rowid_range(&conn, "empty").unwrap(), None);

        let forward = read_frame_chunk(&conn, "c1", 1, 2).unwrap();
        assert_eq!(forward.iter().map(|(r, _)| *r).collect::<Vec<_>>(), [2, 3]);
        let backward = read_frame_chunk_reverse(&conn, "c1", 4, 2).unwrap();
        assert_eq!(backward.iter().map(|(r, _)| *r).collect::<Vec<_>>(), [3, 2]);

        assert_eq!(find_rowid_for_timestamp(&conn, "c1", 25).unwrap(), Some(3));
        assert_eq!(find_rowid_for_timestamp(&conn, "c1", 41).unwrap(), None);

        let (rowid, frame) = get_frame_at_index(&conn, "c1", 1).unwrap().unwrap();
        assert_eq!((rowid, frame.protocol.as_str()), (2, "modbus"));
        assert!(get_frame_at_index(&conn, "c1", 4).unwrap().is_none());
        assert_eq!(count_frames_before_rowid(&conn, "c1", 3).unwrap(), 2);
    }

    #[test]
    fn the_next_filtered_frame_skips_the_unselected_and_knows_its_index() {
        let conn = multi_protocol_capture();
        let can = whole("can");

        let next = get_next_filtered_frame(&conn, "c1", 1, &can, false)
            .unwrap()
            .unwrap();
        assert_eq!((next.0, next.1, next.2.frame_id), (4, 3, 257));
        let previous = get_next_filtered_frame(&conn, "c1", 4, &can, true)
            .unwrap()
            .unwrap();
        assert_eq!((previous.0, previous.1), (1, 0));
        assert!(get_next_filtered_frame(&conn, "c1", 4, &can, false)
            .unwrap()
            .is_none());

        let unfiltered = get_next_filtered_frame(&conn, "c1", 1, &FrameSelection::default(), false)
            .unwrap()
            .unwrap();
        assert_eq!((unfiltered.0, unfiltered.1), (2, 1));
    }

    #[test]
    fn the_offset_for_a_timestamp_counts_the_selected_frames_before_it() {
        let conn = multi_protocol_capture();

        assert_eq!(
            find_offset_for_timestamp(&conn, "c1", 35, &FrameSelection::default()).unwrap(),
            3
        );
        assert_eq!(
            find_offset_for_timestamp(&conn, "c1", 35, &whole("can")).unwrap(),
            1
        );
        assert_eq!(
            find_offset_for_timestamp(&conn, "c1", 0, &whole("can")).unwrap(),
            0
        );
    }
}
