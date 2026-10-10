//! Which frames a query reads, and that choice as the SQLite `WHERE` clause over
//! the desktop's capture `frames` table.
//!
//! The clause is built by hand, so this crate stays on serde alone; the statement
//! around it, and running it, are the desktop's.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::Protocol;

/// A frame's rows in a time window: `start_us` inclusive, `end_us` exclusive.
/// `None`, or no protocols, filters nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameRowFilter {
    pub frame_id: Option<u32>,
    pub is_extended: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocols: Vec<CaptureProtocol>,
    pub start_us: Option<i64>,
    pub end_us: Option<i64>,
}

/// A capture row's `protocol`, as the desktop stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureProtocol {
    Can,
    #[serde(rename = "canfd")]
    CanFd,
    Modbus,
    ModbusRtu,
    Serial,
}

impl CaptureProtocol {
    const ALL: [Self; 5] = [
        Self::Can,
        Self::CanFd,
        Self::Modbus,
        Self::ModbusRtu,
        Self::Serial,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Can => "can",
            Self::CanFd => "canfd",
            Self::Modbus => "modbus",
            Self::ModbusRtu => "modbus_rtu",
            Self::Serial => "serial",
        }
    }

    /// The protocol a stored name is, `None` for a name the desktop doesn't store.
    pub fn from_stored(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == name)
    }

    /// What a capture stores an archive protocol's frames as: CAN with CAN FD, a
    /// Modbus TCP poll with a Modbus RTU message.
    pub fn of(protocol: Protocol) -> &'static [Self] {
        match protocol {
            Protocol::Can => &[Self::Can, Self::CanFd],
            Protocol::Modbus => &[Self::Modbus, Self::ModbusRtu],
            Protocol::Serial => &[Self::Serial],
        }
    }
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

/// SQL with a `?` per value, in order: a `WHERE` condition or a whole statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sql {
    pub sql: String,
    pub values: Vec<SqlValue>,
}

impl Sql {
    /// The SQL with each value in place of its `?`, for showing what ran.
    pub fn inlined(&self) -> String {
        let mut parts = self.sql.split('?');
        let first = parts.next().unwrap_or_default().to_string();
        parts
            .zip(&self.values)
            .fold(first, |out, (part, value)| format!("{out}{value}{part}"))
    }
}

impl FrameRowFilter {
    /// The condition selecting these rows of capture `capture_id`.
    pub fn sql_where(&self, capture_id: &str) -> Sql {
        use SqlValue::{Integer, Text};
        let equals = |column: &str, value| (format!("{column} = ?"), vec![value]);
        let protocols = match self.protocols.as_slice() {
            [] => None,
            [one] => Some(equals("protocol", Text(one.as_str().into()))),
            many => Some((
                format!("protocol IN ({})", vec!["?"; many.len()].join(", ")),
                many.iter().map(|p| Text(p.as_str().into())).collect(),
            )),
        };
        let terms = [
            Some(equals("capture_id", Text(capture_id.into()))),
            self.frame_id
                .map(|id| equals("frame_id", Integer(id.into()))),
            protocols,
            self.is_extended
                .map(|ext| equals("is_extended", Integer(ext.into()))),
            self.start_us
                .map(|us| ("timestamp_us >= ?".into(), vec![Integer(us)])),
            self.end_us
                .map(|us| ("timestamp_us < ?".into(), vec![Integer(us)])),
        ];
        let (conditions, values): (Vec<String>, Vec<_>) = terms.into_iter().flatten().unzip();
        Sql {
            sql: conditions.join(" AND "),
            values: values.concat(),
        }
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
            sql.sql,
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
            protocols: vec![CaptureProtocol::ModbusRtu],
            ..Default::default()
        };
        assert_eq!(
            filter.sql_where("c").inlined(),
            "capture_id = 'c' AND frame_id = 3 AND protocol = 'modbus_rtu' AND is_extended = 0"
        );
    }

    #[test]
    fn several_protocols_read_as_one_in() {
        let filter = FrameRowFilter {
            protocols: CaptureProtocol::of(Protocol::Can).to_vec(),
            start_us: Some(7),
            ..Default::default()
        };
        let sql = filter.sql_where("c");
        assert_eq!(
            sql.sql,
            "capture_id = ? AND protocol IN (?, ?) AND timestamp_us >= ?"
        );
        assert_eq!(
            sql.inlined(),
            "capture_id = 'c' AND protocol IN ('can', 'canfd') AND timestamp_us >= 7"
        );
    }

    #[test]
    fn a_capture_protocol_is_its_stored_name() {
        for p in CaptureProtocol::ALL {
            assert_eq!(serde_json::to_value(p).unwrap(), p.as_str());
            assert_eq!(CaptureProtocol::from_stored(p.as_str()), Some(p));
        }
        assert_eq!(CaptureProtocol::from_stored("can_fd"), None);
    }

    #[test]
    fn an_archive_protocol_matches_what_a_capture_stores_it_as() {
        let stored = |p| {
            CaptureProtocol::of(p)
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(stored(Protocol::Can), ["can", "canfd"]);
        assert_eq!(stored(Protocol::Modbus), ["modbus", "modbus_rtu"]);
        assert_eq!(stored(Protocol::Serial), ["serial"]);
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
