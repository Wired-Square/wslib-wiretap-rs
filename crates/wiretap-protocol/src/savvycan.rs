//! The SavvyCAN/GVRET CSV (`docs/savvycan.md`):
//! `Time Stamp,ID,Extended,Dir,Bus,LEN,D1..Dn`. Line by line and sans-io, like
//! [`candump`](crate::candump). A [`Row`] is the file's shape, not a CAN
//! frame: the desktop writes serial and Modbus rows past 64 bytes in it.

use std::fmt::{self, Write};

use crate::can::Direction;
use crate::dlc::{dlc_to_len, len_to_dlc};
use crate::text::{hex_value, numbered, push_hex_byte};

/// A CAN caller takes `fd` as `data.len() > 8`; the file has no column for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub ts_us: u64,
    pub arb_id: u32,
    pub extended: bool,
    pub direction: Direction,
    pub bus: u8,
    pub data: Vec<u8>,
}

/// Where each field is, by column index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Columns {
    pub timestamp: usize,
    pub id: usize,
    pub extended: usize,
    /// Without one, every row is [`Direction::Rx`].
    pub direction: Option<usize>,
    pub bus: usize,
    pub len: usize,
    /// `D1`; the rest follow it.
    pub data: usize,
}

impl Default for Columns {
    fn default() -> Self {
        Self {
            timestamp: 0,
            id: 1,
            extended: 2,
            direction: Some(3),
            bus: 4,
            len: 5,
            data: 6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Fewer cells than the columns, or `LEN`, call for.
    MissingCell,
    Timestamp,
    Id,
    Extended,
    Direction,
    Bus,
    Length,
    Data,
}

impl ErrorKind {
    /// A stable name for the caller to key its own text on.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingCell => "missing_cell",
            Self::Timestamp => "timestamp",
            Self::Id => "id",
            Self::Extended => "extended",
            Self::Direction => "direction",
            Self::Bus => "bus",
            Self::Length => "length",
            Self::Data => "data",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingCell => "the row has fewer cells than its columns and length need",
            Self::Timestamp => "the time stamp is not whole microseconds",
            Self::Id => "the id is not 1 to 8 hex digits",
            Self::Extended => "extended is not true or false",
            Self::Direction => "the direction is not Rx or Tx",
            Self::Bus => "the bus is not 0 to 255",
            Self::Length => "the length is not a whole number",
            Self::Data => "a data byte is not 1 or 2 hex digits",
        })
    }
}

impl std::error::Error for ErrorKind {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// From 1, counting blank lines and the header.
    pub line: usize,
    pub kind: ErrorKind,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.kind)
    }
}

impl std::error::Error for Error {}

/// The data columns a file needs for its longest payload: the length itself up
/// to 8 and past 64, and the CAN FD length that fits between them.
pub fn data_columns(longest: usize) -> usize {
    if longest <= 64 {
        dlc_to_len(len_to_dlc(longest), true)
    } else {
        longest
    }
}

/// Append the header, with no line ending.
pub fn encode_header_into(out: &mut String, data_columns: usize) {
    out.push_str("Time Stamp,ID,Extended,Dir,Bus,LEN");
    for i in 1..=data_columns {
        let _ = write!(out, ",D{i}");
    }
}

/// Append one row, with no line ending, its data padded with empty cells to
/// `data_columns`. A longer payload is written whole.
pub fn encode_row_into(out: &mut String, row: &Row, data_columns: usize) {
    let direction = match row.direction {
        Direction::Rx => "Rx",
        Direction::Tx => "Tx",
    };
    let _ = write!(
        out,
        "{},{:08X},{},{direction},{},{}",
        row.ts_us,
        row.arb_id,
        row.extended,
        row.bus,
        row.data.len()
    );
    for i in 0..data_columns.max(row.data.len()) {
        out.push(',');
        if let Some(&byte) = row.data.get(i) {
            push_hex_byte(out, byte);
        }
    }
}

/// The columns a header names, by the aliases `docs/savvycan.md` lists, or
/// `None` when it names none and so is not a header. A column it doesn't name
/// keeps its SavvyCAN place, except `Dir`, which is then absent.
pub fn parse_header(line: &str) -> Option<Columns> {
    let mut columns = Columns {
        direction: None,
        ..Columns::default()
    };
    let mut named = false;
    for (i, cell) in line.split(',').enumerate() {
        let field = match cell.trim().to_ascii_lowercase().as_str() {
            "time stamp" | "timestamp" | "time" => &mut columns.timestamp,
            "id" => &mut columns.id,
            "extended" | "ext" => &mut columns.extended,
            "dir" | "direction" => columns.direction.insert(0),
            "bus" => &mut columns.bus,
            "len" | "dlc" | "length" => &mut columns.len,
            "d1" | "data1" | "byte1" => &mut columns.data,
            _ => continue,
        };
        *field = i;
        named = true;
    }
    named.then_some(columns)
}

/// One row. The id is hex with or without `0x`, whatever its width.
pub fn parse_row(line: &str, columns: &Columns) -> Result<Row, ErrorKind> {
    let cells: Vec<&str> = line.split(',').map(str::trim).collect();
    let cell = |i: usize| cells.get(i).copied().ok_or(ErrorKind::MissingCell);
    let hex = |text: &str, digits| hex_value(strip_0x(text), digits);

    let direction = match columns.direction.map(cell).transpose()? {
        None => Direction::Rx,
        Some(d) if d.eq_ignore_ascii_case("rx") => Direction::Rx,
        Some(d) if d.eq_ignore_ascii_case("tx") => Direction::Tx,
        Some(_) => return Err(ErrorKind::Direction),
    };
    let extended = match cell(columns.extended)? {
        e if e.eq_ignore_ascii_case("true") => true,
        e if e.eq_ignore_ascii_case("false") => false,
        _ => return Err(ErrorKind::Extended),
    };
    let len: usize = cell(columns.len)?.parse().map_err(|_| ErrorKind::Length)?;
    let data = (0..len)
        .map(|i| {
            hex(cell(columns.data + i)?, 2)
                .map(|b| b as u8)
                .ok_or(ErrorKind::Data)
        })
        .collect::<Result<_, _>>()?;
    Ok(Row {
        ts_us: cell(columns.timestamp)?
            .parse()
            .map_err(|_| ErrorKind::Timestamp)?,
        arb_id: hex(cell(columns.id)?, 8).ok_or(ErrorKind::Id)?,
        extended,
        direction,
        bus: cell(columns.bus)?.parse().map_err(|_| ErrorKind::Bus)?,
        data,
    })
}

/// Every non-blank line parsed, numbered from 1. A first line that is a
/// header sets the columns; without one they are SavvyCAN's. A bad row is its
/// own `Err` and the rest carry on; what a file with no good row means is the
/// caller's.
pub fn rows<I>(lines: I) -> impl Iterator<Item = Result<Row, Error>>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let mut columns = None;
    numbered(lines).filter_map(move |(line, text)| {
        let text = text.as_ref();
        if columns.is_none() {
            if let Some(header) = parse_header(text) {
                columns = Some(header);
                return None;
            }
        }
        let columns = columns.get_or_insert_with(Columns::default);
        Some(parse_row(text, columns).map_err(|kind| Error { line, kind }))
    })
}

fn strip_0x(text: &str) -> &str {
    text.strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(len: usize) -> Row {
        Row {
            ts_us: 1_727_000_000_000_042,
            arb_id: 0x18DA_F110,
            extended: true,
            direction: Direction::Tx,
            bus: 2,
            data: (0..len).map(|i| i as u8).collect(),
        }
    }

    fn file(rows: &[Row]) -> String {
        let columns = data_columns(rows.iter().map(|r| r.data.len()).max().unwrap_or(0));
        let mut out = String::new();
        encode_header_into(&mut out, columns);
        for row in rows {
            out.push('\n');
            encode_row_into(&mut out, row, columns);
        }
        out
    }

    #[test]
    fn the_columns_round_up_to_a_can_fd_length_between_8_and_64() {
        let cases = [
            (0, 0),
            (5, 5),
            (8, 8),
            (9, 12),
            (13, 16),
            (49, 64),
            (64, 64),
            (65, 65),
            (256, 256),
        ];
        for (longest, columns) in cases {
            assert_eq!(data_columns(longest), columns, "{longest}");
        }
    }

    #[test]
    fn rows_of_every_size_round_trip() {
        for len in [0, 8, 9, 64, 100, 256] {
            let written = file(&[row(len), row(0)]);
            let parsed: Vec<_> = rows(written.lines()).map(Result::unwrap).collect();
            assert_eq!(parsed, [row(len), row(0)], "{len}");
        }
    }

    #[test]
    fn a_file_the_desktop_exported_parses() {
        let exported =
            "Time Stamp,ID,Extended,Dir,Bus,LEN,D1,D2,D3,D4,D5,D6,D7,D8,D9,D10,D11,D12\n\
            1727000000000042,00000123,false,Rx,0,2,DE,AD,,,,,,,,,,\n\
            1727000000000043,18DAF110,true,Tx,1,12,00,01,02,03,04,05,06,07,08,09,0A,0B\n";
        let parsed: Vec<_> = rows(exported.lines()).map(Result::unwrap).collect();
        assert_eq!(
            parsed,
            [
                Row {
                    ts_us: 1_727_000_000_000_042,
                    arb_id: 0x123,
                    extended: false,
                    direction: Direction::Rx,
                    bus: 0,
                    data: vec![0xDE, 0xAD],
                },
                Row {
                    ts_us: 1_727_000_000_000_043,
                    arb_id: 0x18DA_F110,
                    extended: true,
                    direction: Direction::Tx,
                    bus: 1,
                    data: (0..12).collect(),
                },
            ]
        );
        assert_eq!(file(&parsed), exported.trim_end());
    }

    #[test]
    fn the_id_is_hex_whatever_its_width() {
        let columns = Columns::default();
        for id in ["123", "0x123", "00000123"] {
            let line = format!("0,{id},false,Rx,0,0");
            assert_eq!(parse_row(&line, &columns).unwrap().arb_id, 0x123, "{id}");
        }
    }

    #[test]
    fn a_header_places_the_columns_by_name_and_without_dir_every_row_is_rx() {
        let columns = parse_header("bus, DLC ,id,Timestamp,ext,data1").unwrap();
        assert_eq!(
            columns,
            Columns {
                timestamp: 3,
                id: 2,
                extended: 4,
                direction: None,
                bus: 0,
                len: 1,
                data: 5,
            }
        );
        let parsed: Vec<_> = rows(["bus,dlc,id,time,ext,d1,d2", "1,2,7FF,10,TRUE,0xA,b"])
            .map(Result::unwrap)
            .collect();
        assert_eq!(
            parsed,
            [Row {
                ts_us: 10,
                arb_id: 0x7FF,
                extended: true,
                direction: Direction::Rx,
                bus: 1,
                data: vec![0x0A, 0x0B],
            }]
        );
        assert_eq!(parse_header("10,123,false,Rx,0,0"), None);
    }

    #[test]
    fn without_a_header_the_columns_are_savvycans() {
        let parsed: Vec<_> = rows(["5,1,false,tx,0,1,FF"]).map(Result::unwrap).collect();
        assert_eq!(parsed[0].direction, Direction::Tx);
        assert_eq!(parsed[0].data, [0xFF]);
    }

    #[test]
    fn malformed_rows_are_refused_by_kind() {
        let columns = Columns::default();
        let cases = [
            ("0,1,false,Rx,0", ErrorKind::MissingCell),
            ("0,1,false,Rx,0,2,AA", ErrorKind::MissingCell),
            ("1.5,1,false,Rx,0,0", ErrorKind::Timestamp),
            ("0,,false,Rx,0,0", ErrorKind::Id),
            ("0,123456789,false,Rx,0,0", ErrorKind::Id),
            ("0,G,false,Rx,0,0", ErrorKind::Id),
            ("0,1,yes,Rx,0,0", ErrorKind::Extended),
            ("0,1,false,In,0,0", ErrorKind::Direction),
            ("0,1,false,Rx,256,0", ErrorKind::Bus),
            ("0,1,false,Rx,0,x", ErrorKind::Length),
            ("0,1,false,Rx,0,1,", ErrorKind::Data),
            ("0,1,false,Rx,0,1,100", ErrorKind::Data),
            (
                &format!("0,1,false,Rx,0,{}", usize::MAX),
                ErrorKind::MissingCell,
            ),
        ];
        for (line, kind) in cases {
            assert_eq!(parse_row(line, &columns), Err(kind), "{line}");
        }
        let codes: std::collections::HashSet<_> = [
            ErrorKind::MissingCell,
            ErrorKind::Timestamp,
            ErrorKind::Id,
            ErrorKind::Extended,
            ErrorKind::Direction,
            ErrorKind::Bus,
            ErrorKind::Length,
            ErrorKind::Data,
        ]
        .iter()
        .map(ErrorKind::code)
        .collect();
        assert_eq!(codes.len(), 8);
    }

    #[test]
    fn a_file_skips_blank_lines_and_reports_each_bad_row_by_its_number() {
        let text = "Time Stamp,ID,Extended,Dir,Bus,LEN,D1\n\n0,1,false,Rx,0,1,AA\n0,1,maybe,Rx,0,0\n\n1,2,true,Tx,0,0\n";
        let parsed: Vec<_> = rows(text.lines()).collect();
        assert_eq!(parsed.len(), 3);
        assert!(parsed[0].is_ok() && parsed[2].is_ok());
        let error = Error {
            line: 4,
            kind: ErrorKind::Extended,
        };
        assert_eq!(parsed[1], Err(error));
        assert_eq!(error.to_string(), "line 4: extended is not true or false");
    }
}
