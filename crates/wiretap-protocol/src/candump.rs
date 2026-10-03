//! can-utils' `candump -L` log line (`docs/candump.md`), with `-x`'s direction,
//! and the `cansend` frame inside it. Line by line and sans-io: the caller
//! reads the file, and a line keeps what was written, absolute time included.

use std::fmt::{self, Write};

use crate::can::{CanFrame, Direction};
use crate::text::{hex_value, nibble, numbered, push_hex_byte};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub ts_us: u64,
    pub interface: String,
    /// On bus 0: mapping `interface` to a bus is the caller's.
    pub frame: CanFrame,
    pub direction: Option<Direction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Not `(time) interface frame`, with an optional `T` or `R` after it.
    Fields,
    Timestamp,
    Direction,
    NoSeparator,
    IdWidth,
    IdHex,
    RemoteLength,
    FdFlags,
    Data,
    TooLong {
        len: usize,
        max: usize,
    },
}

impl ErrorKind {
    /// A stable name for the caller to key its own text on.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Fields => "fields",
            Self::Timestamp => "timestamp",
            Self::Direction => "direction",
            Self::NoSeparator => "no_separator",
            Self::IdWidth => "id_width",
            Self::IdHex => "id_hex",
            Self::RemoteLength => "remote_length",
            Self::FdFlags => "fd_flags",
            Self::Data => "data",
            Self::TooLong { .. } => "too_long",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fields => f.write_str("a line is '(time) interface frame', then T or R"),
            Self::Timestamp => f.write_str("the time is '(seconds.fraction)', of 1 to 6 digits"),
            Self::Direction => f.write_str("the direction is T or R"),
            Self::NoSeparator => f.write_str("the frame has no '#'"),
            Self::IdWidth => f.write_str("the id is 3 hex digits, or 8 for an extended id"),
            Self::IdHex => f.write_str("the id is not hex"),
            Self::RemoteLength => f.write_str("a remote frame's length is one digit, 0 to 8"),
            Self::FdFlags => f.write_str("'##' is followed by one hex flags digit"),
            Self::Data => f.write_str("the data is not whole hex bytes"),
            Self::TooLong { len, max } => write!(f, "{len} bytes is more than {max}"),
        }
    }
}

impl std::error::Error for ErrorKind {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// From 1, counting blank lines.
    pub line: usize,
    pub kind: ErrorKind,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.kind)
    }
}

impl std::error::Error for Error {}

/// Append one line, with no line ending. RTR is written for a classic frame
/// only, and FD's flags are BRS 1 and ESI 2.
pub fn encode_line_into(
    out: &mut String,
    ts_us: u64,
    interface: &str,
    frame: &CanFrame,
    direction: Option<Direction>,
) {
    let _ = write!(
        out,
        "({:010}.{:06}) {interface} ",
        ts_us / 1_000_000,
        ts_us % 1_000_000
    );
    if frame.extended {
        let _ = write!(out, "{:08X}#", frame.arb_id);
    } else {
        let _ = write!(out, "{:03X}#", frame.arb_id);
    }
    if frame.rtr && !frame.fd {
        out.push('R');
        if (1..=8).contains(&frame.dlc()) {
            let _ = write!(out, "{}", frame.dlc());
        }
    } else {
        if frame.fd {
            let _ = write!(out, "#{:X}", u8::from(frame.brs) | u8::from(frame.esi) << 1);
        }
        for &byte in &frame.data {
            push_hex_byte(out, byte);
        }
    }
    match direction {
        Some(Direction::Tx) => out.push_str(" T"),
        Some(Direction::Rx) => out.push_str(" R"),
        None => {}
    }
}

pub fn parse_line(line: &str) -> Result<Line, ErrorKind> {
    let mut fields = line.split_ascii_whitespace();
    let stamp = fields.next().ok_or(ErrorKind::Fields)?;
    let ts_us = parse_stamp(stamp).ok_or(ErrorKind::Timestamp)?;
    let (Some(interface), Some(frame)) = (fields.next(), fields.next()) else {
        return Err(ErrorKind::Fields);
    };
    let direction = match fields.next() {
        None => None,
        Some("T") => Some(Direction::Tx),
        Some("R") => Some(Direction::Rx),
        Some(_) => return Err(ErrorKind::Direction),
    };
    if fields.next().is_some() {
        return Err(ErrorKind::Fields);
    }
    Ok(Line {
        ts_us,
        interface: interface.to_owned(),
        frame: parse_frame(frame, 0)?,
        direction,
    })
}

/// A `cansend` frame on `bus`: `123#DEADBEEF`, `12345678#…` extended (by
/// width, not value), `123##<flags><data>` FD, `123#R[<dlc>]` remote. Data may
/// be dotted. An FD payload is kept at the length written, not padded.
pub fn parse_frame(text: &str, bus: u8) -> Result<CanFrame, ErrorKind> {
    let (id, body) = text.split_once('#').ok_or(ErrorKind::NoSeparator)?;
    let extended = match id.len() {
        3 => false,
        8 => true,
        _ => return Err(ErrorKind::IdWidth),
    };
    let arb_id = hex_value(id, 8).ok_or(ErrorKind::IdHex)?;

    if let Some(dlc) = body.strip_prefix(['R', 'r']) {
        let dlc = match dlc.as_bytes() {
            [] => 0,
            [digit @ b'0'..=b'8'] => digit - b'0',
            _ => return Err(ErrorKind::RemoteLength),
        };
        return Ok(CanFrame::remote(bus, arb_id, extended, dlc));
    }

    let (fd, flags, data) = match body.strip_prefix('#') {
        Some(rest) => {
            let flags = rest
                .bytes()
                .next()
                .and_then(nibble)
                .ok_or(ErrorKind::FdFlags)?;
            (true, flags, &rest[1..])
        }
        None => (false, 0, body),
    };
    let data = decode_hex(data).ok_or(ErrorKind::Data)?;
    let max = if fd { 64 } else { 8 };
    if data.len() > max {
        return Err(ErrorKind::TooLong {
            len: data.len(),
            max,
        });
    }
    let mut frame = CanFrame::data(bus, arb_id, extended, fd, flags & 1 != 0, data);
    frame.esi = flags & 2 != 0;
    Ok(frame)
}

/// Every non-blank line parsed, numbered from 1. A bad line is its own `Err`
/// and the rest carry on; what a file with no good line means is the caller's.
pub fn lines<I>(lines: I) -> impl Iterator<Item = Result<Line, Error>>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    numbered(lines)
        .map(|(line, text)| parse_line(text.as_ref()).map_err(|kind| Error { line, kind }))
}

fn parse_stamp(stamp: &str) -> Option<u64> {
    let (secs, fraction) = stamp
        .strip_prefix('(')?
        .strip_suffix(')')?
        .split_once('.')?;
    let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !all_digits(secs) || !all_digits(fraction) || fraction.len() > 6 {
        return None;
    }
    let micros = fraction.parse::<u64>().ok()? * 10u64.pow(6 - fraction.len() as u32);
    secs.parse::<u64>()
        .ok()?
        .checked_mul(1_000_000)?
        .checked_add(micros)
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let digits = text
        .bytes()
        .filter(|&b| b != b'.')
        .map(nibble)
        .collect::<Option<Vec<u8>>>()?;
    if digits.len() % 2 != 0 {
        return None;
    }
    Some(
        digits
            .chunks(2)
            .map(|pair| pair[0] << 4 | pair[1])
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: u64 = 1_727_000_000_000_042;

    fn line(frame: &CanFrame, direction: Option<Direction>) -> String {
        let mut out = String::new();
        encode_line_into(&mut out, AT, "can0", frame, direction);
        out
    }

    fn fd(brs: bool, esi: bool, data: Vec<u8>) -> CanFrame {
        let mut frame = CanFrame::data(0, 0x123, false, true, brs, data);
        frame.esi = esi;
        frame
    }

    fn frame(text: &str) -> CanFrame {
        parse_frame(text, 0).unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    #[test]
    fn each_frame_kind_prints_as_candump_logs_it_and_parses_back() {
        let cases = [
            (
                CanFrame::data(0, 0x123, false, false, false, vec![0xDE, 0xAD, 0xBE, 0xEF]),
                "123#DEADBEEF",
            ),
            (CanFrame::data(0, 0x7, false, false, false, vec![]), "007#"),
            (
                CanFrame::data(0, 0x1234567, true, false, false, vec![1, 2]),
                "01234567#0102",
            ),
            (CanFrame::remote(0, 0x123, false, 0), "123#R"),
            (CanFrame::remote(0, 0x123, false, 5), "123#R5"),
            (CanFrame::remote(0, 0x1ABCDEF0, true, 8), "1ABCDEF0#R8"),
            (
                fd(true, false, vec![0xA5; 12]),
                "123##1A5A5A5A5A5A5A5A5A5A5A5A5",
            ),
            (fd(false, false, vec![0xAA]), "123##0AA"),
            (fd(false, true, vec![]), "123##2"),
            (fd(true, true, vec![0x01]), "123##301"),
            (
                fd(true, false, vec![0x5A; 64]),
                &format!("123##1{}", "5A".repeat(64)),
            ),
        ];
        for (frame, text) in cases {
            let written = line(&frame, None);
            assert_eq!(written, format!("(1727000000.000042) can0 {text}"));
            let parsed = parse_line(&written).unwrap();
            assert_eq!(
                parsed,
                Line {
                    ts_us: AT,
                    interface: "can0".into(),
                    frame,
                    direction: None
                }
            );
        }
    }

    #[test]
    fn own_frames_carry_their_direction_both_ways() {
        let frame = CanFrame::data(0, 0x10, false, false, false, vec![0x42]);
        for (direction, suffix) in [(Direction::Tx, "T"), (Direction::Rx, "R")] {
            let written = line(&frame, Some(direction));
            assert_eq!(written, format!("(1727000000.000042) can0 010#42 {suffix}"));
            assert_eq!(parse_line(&written).unwrap().direction, Some(direction));
        }
    }

    #[test]
    fn the_seconds_are_zero_padded_to_ten_digits() {
        let mut out = String::new();
        let frame = CanFrame::data(0, 1, false, false, false, vec![]);
        encode_line_into(&mut out, 1_500_000, "x", &frame, None);
        assert_eq!(out, "(0000000001.500000) x 001#");
    }

    #[test]
    fn time_is_kept_as_written_from_zero_to_the_last_microsecond() {
        let frame = CanFrame::data(0, 1, false, false, false, vec![]);
        for ts_us in [0, 1, u64::MAX] {
            let mut out = String::new();
            encode_line_into(&mut out, ts_us, "can0", &frame, None);
            assert_eq!(parse_line(&out).unwrap().ts_us, ts_us);
        }
        for (stamp, ts_us) in [
            ("(1.5)", 1_500_000),
            ("(12.000001)", 12_000_001),
            ("(0.25)", 250_000),
        ] {
            assert_eq!(
                parse_line(&format!("{stamp} can0 001#")).unwrap().ts_us,
                ts_us
            );
        }
    }

    #[test]
    fn cansend_frames_parse() {
        assert_eq!(
            frame("7FF#"),
            CanFrame::data(0, 0x7FF, false, false, false, vec![])
        );
        assert_eq!(
            frame("1a2#de.ad.be.ef"),
            CanFrame::data(0, 0x1A2, false, false, false, vec![0xDE, 0xAD, 0xBE, 0xEF])
        );
        assert_eq!(
            frame("12345678#0102"),
            CanFrame::data(0, 0x1234_5678, true, false, false, vec![1, 2])
        );
        assert_eq!(
            frame("00000123#"),
            CanFrame::data(0, 0x123, true, false, false, vec![])
        );
        assert_eq!(frame("FFF#").arb_id, 0xFFF);
        assert_eq!(parse_frame("123#", 1).unwrap().bus, 1);
    }

    #[test]
    fn remote_frames_parse_with_an_optional_length() {
        assert_eq!(frame("123#R"), CanFrame::remote(0, 0x123, false, 0));
        assert_eq!(frame("123#r3"), CanFrame::remote(0, 0x123, false, 3));
        assert_eq!(
            frame("1ABCDEF0#R8"),
            CanFrame::remote(0, 0x1ABC_DEF0, true, 8)
        );
    }

    #[test]
    fn fd_frames_keep_their_flags_and_their_written_length() {
        assert_eq!(
            frame("123##1DEADBEEF"),
            CanFrame::data(0, 0x123, false, true, true, vec![0xDE, 0xAD, 0xBE, 0xEF])
        );
        assert_eq!(
            frame("123##0"),
            CanFrame::data(0, 0x123, false, true, false, vec![])
        );
        let esi = frame("123##2AA");
        assert!(esi.fd && esi.esi && !esi.brs);
        assert_eq!(frame(&format!("123##1{}", "11".repeat(9))).data.len(), 9);
        assert_eq!(frame(&format!("123##1{}", "00".repeat(64))).data.len(), 64);
    }

    #[test]
    fn malformed_frames_are_refused_by_kind() {
        let cases = [
            ("123", ErrorKind::NoSeparator),
            ("12#00", ErrorKind::IdWidth),
            ("1234#00", ErrorKind::IdWidth),
            ("XYZ#00", ErrorKind::IdHex),
            ("+12#00", ErrorKind::IdHex),
            ("123#0", ErrorKind::Data),
            ("123#GG", ErrorKind::Data),
            (
                "123#010203040506070809",
                ErrorKind::TooLong { len: 9, max: 8 },
            ),
            ("123#R9", ErrorKind::RemoteLength),
            ("123#R12", ErrorKind::RemoteLength),
            ("123##", ErrorKind::FdFlags),
            ("123##G00", ErrorKind::FdFlags),
            (
                &format!("123##1{}", "00".repeat(65)),
                ErrorKind::TooLong { len: 65, max: 64 },
            ),
        ];
        for (text, kind) in cases {
            assert_eq!(parse_frame(text, 0), Err(kind), "{text}");
        }
    }

    #[test]
    fn malformed_lines_are_refused_by_kind() {
        let cases = [
            ("(1.0) can0", ErrorKind::Fields),
            ("(1.0) can0 123#00 T x", ErrorKind::Fields),
            ("(1.0) can0 123#00 X", ErrorKind::Direction),
            ("1.0 can0 123#00", ErrorKind::Timestamp),
            ("(1) can0 123#00", ErrorKind::Timestamp),
            ("(1.) can0 123#00", ErrorKind::Timestamp),
            ("(1.0000001) can0 123#00", ErrorKind::Timestamp),
            ("(+1.0) can0 123#00", ErrorKind::Timestamp),
            ("(18446744073709.551616) can0 123#00", ErrorKind::Timestamp),
            ("(1.0) can0 12#00", ErrorKind::IdWidth),
        ];
        for (text, kind) in cases {
            assert_eq!(parse_line(text).map(|_| ()), Err(kind), "{text}");
        }
    }

    #[test]
    fn a_line_that_isnt_candump_is_refused_on_its_timestamp_first() {
        for text in ["this line is not candump", "not candump"] {
            assert_eq!(
                parse_line(text).map(|_| ()),
                Err(ErrorKind::Timestamp),
                "{text}"
            );
        }
    }

    #[test]
    fn every_kind_has_its_own_code_and_text() {
        let kinds = [
            ErrorKind::Fields,
            ErrorKind::Timestamp,
            ErrorKind::Direction,
            ErrorKind::NoSeparator,
            ErrorKind::IdWidth,
            ErrorKind::IdHex,
            ErrorKind::RemoteLength,
            ErrorKind::FdFlags,
            ErrorKind::Data,
            ErrorKind::TooLong { len: 9, max: 8 },
        ];
        let codes: std::collections::HashSet<_> = kinds.iter().map(ErrorKind::code).collect();
        assert_eq!(codes.len(), kinds.len());
        assert_eq!(
            Error {
                line: 3,
                kind: ErrorKind::TooLong { len: 9, max: 8 }
            }
            .to_string(),
            "line 3: 9 bytes is more than 8"
        );
    }

    #[test]
    fn a_log_skips_blank_lines_and_reports_each_bad_one_by_its_number() {
        let log = "(1.000000) can0 123#00\n\n  \n(2.000000) can0 12#00\n(3.000000) can1 456#R T\n";
        let parsed: Vec<_> = lines(log.lines()).collect();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].as_ref().unwrap().ts_us, 1_000_000);
        assert_eq!(
            parsed[1],
            Err(Error {
                line: 4,
                kind: ErrorKind::IdWidth
            })
        );
        let last = parsed[2].as_ref().unwrap();
        assert_eq!(
            (last.interface.as_str(), last.direction),
            ("can1", Some(Direction::Tx))
        );
    }
}
