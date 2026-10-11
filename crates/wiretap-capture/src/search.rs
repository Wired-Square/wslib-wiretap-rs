use rusqlite::{params, Connection};
use wiretap_analysis::source::FrameSelection;

use crate::error::Result;
use crate::read::{selection_json, selection_predicate};

/// The 0-based offsets, among a selection's frames, of those whose lowercase hex id
/// (`search_id`, an `0x` prefix dropped) or uppercase hex payload (`search_data`)
/// contains `query`. The caller strips whitespace; `LIKE` wildcards are not escaped.
pub fn search_frames(
    conn: &Connection,
    capture_id: &str,
    query: &str,
    search_id: bool,
    search_data: bool,
    selection: &FrameSelection,
) -> Result<Vec<usize>> {
    if query.is_empty() || (!search_id && !search_data) {
        return Ok(Vec::new());
    }
    let q = query
        .strip_prefix("0x")
        .or_else(|| query.strip_prefix("0X"))
        .unwrap_or(query);
    let literal = |s: String| s.replace('\'', "''");

    let mut clauses = Vec::new();
    if search_id {
        clauses.push(format!(
            "printf('%x', frame_id) LIKE '%{}%'",
            literal(q.to_lowercase())
        ));
    }
    if search_data {
        clauses.push(format!(
            "upper(hex(payload)) LIKE '%{}%'",
            literal(q.to_uppercase())
        ));
    }
    let id_filter = if selection.is_empty() {
        String::new()
    } else {
        format!(" {}", selection_predicate(2, selection))
    };
    let sql = format!(
        "WITH numbered AS (
            SELECT frame_id, payload,
                   CAST(ROW_NUMBER() OVER (ORDER BY rowid) AS INTEGER) - 1 AS offset
            FROM frames
            WHERE capture_id = ?1{id_filter}
        )
        SELECT offset FROM numbered WHERE {}",
        clauses.join(" OR ")
    );

    let mut stmt = conn.prepare(&sql)?;
    let offset_of = |row: &rusqlite::Row| row.get::<_, i64>(0).map(|n| n as usize);
    let offsets = if selection.is_empty() {
        stmt.query_map(params![capture_id], offset_of)?
            .collect::<rusqlite::Result<_>>()?
    } else {
        stmt.query_map(params![capture_id, selection_json(selection)], offset_of)?
            .collect::<rusqlite::Result<_>>()?
    };
    Ok(offsets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames::{can_frame, insert_frames, StoredFrame};
    use crate::read::selection;

    fn capture(frames: &[(u32, &[u8])]) -> Connection {
        let mut conn = crate::schema::migrated();
        let frames: Vec<StoredFrame> = frames
            .iter()
            .map(|&(frame_id, payload)| can_frame(frame_id, payload))
            .collect();
        insert_frames(&mut conn, "c1", &frames).unwrap();
        conn
    }

    fn search(conn: &Connection, query: &str, search_id: bool, search_data: bool) -> Vec<usize> {
        search_frames(
            conn,
            "c1",
            query,
            search_id,
            search_data,
            &FrameSelection::default(),
        )
        .unwrap()
    }

    #[test]
    fn a_search_matches_a_substring_of_the_unpadded_lowercase_hex_id() {
        let conn = capture(&[(0x100, &[]), (0x210, &[]), (0x7AB, &[])]);
        assert_eq!(search(&conn, "10", true, false), [0, 1]);
        assert_eq!(search(&conn, "0x7AB", true, false), [2]);
        assert_eq!(search(&conn, "", true, false), Vec::<usize>::new());
        assert_eq!(search(&conn, "10", false, false), Vec::<usize>::new());
    }

    #[test]
    fn a_data_search_matches_hex_across_byte_boundaries_in_either_case() {
        let conn = capture(&[(1, &[0xDE, 0xAD]), (2, &[0xBE, 0xEF]), (3, &[0x0E, 0xAD])]);
        assert_eq!(search(&conn, "ead", false, true), [0, 2]);
        assert_eq!(search(&conn, "EADB", false, true), Vec::<usize>::new());
        assert_eq!(search(&conn, "2", true, true), [1]);
    }

    #[test]
    fn like_wildcards_in_a_query_are_not_escaped() {
        let conn = capture(&[(0x100, &[0x01]), (0x200, &[0x02])]);
        assert_eq!(search(&conn, "_", true, false), [0, 1]);
        assert_eq!(search(&conn, "1%0", true, false), [0]);
        assert_eq!(search(&conn, "'", true, true), Vec::<usize>::new());
    }

    #[test]
    fn a_search_offset_counts_only_the_selected_frames() {
        let conn = capture(&[(0x100, &[]), (0x200, &[]), (0x100, &[])]);
        let only_0x100 = selection(&[("can", &[0x100])]);
        assert_eq!(
            search_frames(&conn, "c1", "100", true, false, &only_0x100).unwrap(),
            [0, 1]
        );
    }
}
