//! Which frames a query reads, and that choice as the SQLite `WHERE` clause over
//! the desktop's capture `frames` table.
//!
//! The clause is built by hand, so this crate stays on serde alone; the statement
//! around it, and running it, are the desktop's.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::Protocol;

/// A frame's rows in a time window: `start_us` inclusive, `end_us` exclusive.
/// `None` filters nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameRowFilter {
    pub frame_id: Option<u32>,
    pub is_extended: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    pub start_us: Option<i64>,
    pub end_us: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlValue {
    Integer(i64),
    Text(String),
}

/// A SQL literal: text quoted, its quotes doubled.
impl fmt::Display for SqlValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer(n) => write!(f, "{n}"),
            Self::Text(s) => write!(f, "'{}'", s.replace('\'', "''")),
        }
    }
}

/// A `WHERE` condition with a `?` per value, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlWhere {
    pub clause: String,
    pub values: Vec<SqlValue>,
}

impl SqlWhere {
    /// The clause with each value in place of its `?`, for showing what ran.
    pub fn inlined(&self) -> String {
        let mut parts = self.clause.split('?');
        let first = parts.next().unwrap_or_default().to_string();
        parts
            .zip(&self.values)
            .fold(first, |out, (part, value)| format!("{out}{value}{part}"))
    }
}

impl FrameRowFilter {
    /// The condition selecting these rows of capture `capture_id`.
    pub fn sql_where(&self, capture_id: &str) -> SqlWhere {
        use SqlValue::{Integer, Text};
        let terms = [
            Some(("capture_id =", Text(capture_id.to_string()))),
            self.frame_id.map(|id| ("frame_id =", Integer(id.into()))),
            self.protocol
                .map(|p| ("protocol =", Text(protocol_name(p).to_string()))),
            self.is_extended
                .map(|ext| ("is_extended =", Integer(ext.into()))),
            self.start_us.map(|us| ("timestamp_us >=", Integer(us))),
            self.end_us.map(|us| ("timestamp_us <", Integer(us))),
        ];
        let (columns, values): (Vec<_>, Vec<_>) = terms.into_iter().flatten().unzip();
        SqlWhere {
            clause: columns
                .iter()
                .map(|c| format!("{c} ?"))
                .collect::<Vec<_>>()
                .join(" AND "),
            values,
        }
    }
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Can => "can",
        Protocol::Modbus => "modbus",
        Protocol::Serial => "serial",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPTURE: &str = "d1-sql-golden";

    #[test]
    fn a_bounded_frame_reads_as_the_desktops_capture_queries() {
        let filter = FrameRowFilter {
            frame_id: Some(256),
            is_extended: Some(true),
            start_us: Some(1_000_000),
            end_us: Some(2_000_000),
            ..Default::default()
        };
        let sql = filter.sql_where(CAPTURE);
        assert_eq!(
            sql.clause,
            "capture_id = ? AND frame_id = ? AND is_extended = ? AND timestamp_us >= ? AND timestamp_us < ?"
        );
        assert_eq!(
            sql.values,
            [
                SqlValue::Text(CAPTURE.into()),
                SqlValue::Integer(256),
                SqlValue::Integer(1),
                SqlValue::Integer(1_000_000),
                SqlValue::Integer(2_000_000),
            ]
        );
        assert_eq!(
            sql.inlined(),
            "capture_id = 'd1-sql-golden' AND frame_id = 256 AND is_extended = 1 \
             AND timestamp_us >= 1000000 AND timestamp_us < 2000000"
        );
    }

    #[test]
    fn an_empty_filter_reads_the_whole_capture() {
        let sql = FrameRowFilter::default().sql_where(CAPTURE);
        assert_eq!(sql.inlined(), "capture_id = 'd1-sql-golden'");
    }

    #[test]
    fn the_protocol_sits_between_frame_id_and_is_extended_as_in_capture_db() {
        let filter = FrameRowFilter {
            frame_id: Some(3),
            is_extended: Some(false),
            protocol: Some(Protocol::Modbus),
            ..Default::default()
        };
        assert_eq!(
            filter.sql_where("c").inlined(),
            "capture_id = 'c' AND frame_id = 3 AND protocol = 'modbus' AND is_extended = 0"
        );
    }

    #[test]
    fn text_is_quoted_with_its_quotes_doubled() {
        assert_eq!(
            FrameRowFilter::default().sql_where("it's").inlined(),
            "capture_id = 'it''s'"
        );
    }

    #[test]
    fn bounds_serialise_as_microseconds() {
        let filter = FrameRowFilter {
            frame_id: Some(256),
            start_us: Some(5),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(&filter).unwrap(),
            serde_json::json!({ "frame_id": 256, "is_extended": null, "start_us": 5, "end_us": null })
        );
    }
}
