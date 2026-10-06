//! The WireTAP desktop's HTTP capture-import body (`docs/import.md`), both
//! ends: what the desktop streams to a gateway's import endpoint, and what the
//! gateway parses. A body is a header, `magic "WTIM" | version u8`, then
//! records back to back with no framing or checksum around them:
//! `ts_us i64 | id_flags u32 | flags u8 | bus u8 | len u8 | payload`,
//! little-endian.
//!
//! CAN only. `id_flags` and `flags` are the ingest protocol's CAN record words,
//! so they are packed and unpacked by [`RecordFields`]. There is no
//! negotiation: a gateway takes [`VERSION`] and refuses any other.

use crate::can::CanFrame;
use crate::ingest::{RecordFields, RecordKind};

pub const MAGIC: &[u8; 4] = b"WTIM";
/// The headerless body before it is version 1, and is refused as bad magic.
pub const VERSION: u8 = 2;
/// `magic [4] | version u8`.
pub const BODY_HEADER: usize = 5;
/// `ts_us i64 | id_flags u32 | flags u8 | bus u8 | len u8`.
pub const RECORD_HEADER: usize = 15;

/// Start a body: written once, before its first record.
pub fn encode_header_into(out: &mut Vec<u8>) {
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
}

/// Check a body's header, returning the bytes it takes. `Ok(None)` = need
/// more bytes; `Err` = not a body this end reads.
pub fn parse_header(buf: &[u8]) -> Result<Option<usize>, String> {
    if buf.len() < BODY_HEADER {
        return Ok(None);
    }
    if &buf[..4] != MAGIC {
        return Err(
            "not an import body: no \"WTIM\" magic (a pre-versioned v1 body, or not an import at all)"
                .into(),
        );
    }
    match buf[4] {
        VERSION => Ok(Some(BODY_HEADER)),
        found => Err(format!(
            "import body version {found} is not supported; this end takes version {VERSION}"
        )),
    }
}

/// Append one record. A payload over 64 bytes, one CAN FD frame, is clamped to
/// it; a remote frame's is dropped, as its length is the code in `flags`.
pub fn encode_record_into(out: &mut Vec<u8>, ts_us: i64, frame: &CanFrame, transmitted: bool) {
    let (id_flags, flags) = RecordFields::from_can(frame, transmitted).to_wire();
    let payload = if frame.rtr { &[][..] } else { &frame.data };
    let payload = &payload[..payload.len().min(RecordKind::Can.max_payload())];
    out.reserve(RECORD_HEADER + payload.len());
    out.extend_from_slice(&ts_us.to_le_bytes());
    out.extend_from_slice(&id_flags.to_le_bytes());
    out.push(flags);
    out.push(frame.bus);
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub ts_us: i64,
    pub id_flags: u32,
    pub flags: u8,
    pub bus: u8,
    pub payload: Vec<u8>,
}

impl Record {
    /// Always [`RecordFields::Can`].
    pub fn fields(&self) -> RecordFields {
        RecordFields::from_wire(RecordKind::Can, self.id_flags, self.flags)
    }

    pub fn into_can(self) -> CanFrame {
        self.fields()
            .to_can(self.bus, self.payload)
            .expect("an import record is CAN")
    }
}

/// Try to consume one complete record from the front of `buf`, after the body
/// header. `Ok(None)` = need more bytes; `Err` = a length over 64, after which
/// the stream cannot be resynchronised.
/// Drains per call; a streaming caller wants [`parse_record`].
pub fn take_record(buf: &mut Vec<u8>) -> Result<Option<Record>, String> {
    let parsed = parse_record(buf)?;
    Ok(parsed.map(|(record, consumed)| {
        buf.drain(..consumed);
        record
    }))
}

/// [`take_record`] for a caller that holds its own offset, returning the bytes consumed.
pub fn parse_record(buf: &[u8]) -> Result<Option<(Record, usize)>, String> {
    if buf.len() < RECORD_HEADER {
        return Ok(None);
    }
    let len = buf[14] as usize;
    let max = RecordKind::Can.max_payload();
    if len > max {
        return Err(format!("record payload length {len} > {max}"));
    }
    let total = RECORD_HEADER + len;
    if buf.len() < total {
        return Ok(None);
    }
    let record = Record {
        ts_us: i64::from_le_bytes(buf[0..8].try_into().unwrap()),
        id_flags: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        flags: buf[12],
        bus: buf[13],
        payload: buf[RECORD_HEADER..total].to_vec(),
    };
    Ok(Some((record, total)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::record_id_flags;

    /// An extended FD frame with BRS that the desktop transmitted, on bus 2, at
    /// 2026-01-01T00:00:00Z.
    const GOLDEN: [u8; 18] = [
        0x00, 0x40, 0x20, 0x46, 0x48, 0x47, 0x06, 0x00, // ts_us
        0x10, 0xF1, 0xDA, 0xF8, // id_flags
        0x02, // flags: BRS
        0x02, // bus
        0x03, // len
        0xDE, 0xAD, 0x01, // payload
    ];
    const GOLDEN_TS_US: i64 = 1_767_225_600_000_000;

    fn golden_frame() -> CanFrame {
        CanFrame::data(2, 0x18DA_F110, true, true, true, vec![0xDE, 0xAD, 0x01])
    }

    fn golden_record() -> Record {
        Record {
            ts_us: GOLDEN_TS_US,
            id_flags: record_id_flags(0x18DA_F110, true, true, true),
            flags: 0x02,
            bus: 2,
            payload: vec![0xDE, 0xAD, 0x01],
        }
    }

    fn encode(ts_us: i64, frame: &CanFrame) -> Vec<u8> {
        let mut out = Vec::new();
        encode_record_into(&mut out, ts_us, frame, false);
        out
    }

    fn round_trip(frame: &CanFrame) -> CanFrame {
        let mut buf = encode(0, frame);
        let r = take_record(&mut buf).unwrap().unwrap();
        assert!(buf.is_empty());
        r.into_can()
    }

    #[test]
    fn a_body_header_encodes_to_the_golden_bytes_and_parses_back() {
        let mut out = Vec::new();
        encode_header_into(&mut out);
        assert_eq!(out, b"WTIM\x02");
        out.extend_from_slice(&GOLDEN);
        assert_eq!(parse_header(&out), Ok(Some(BODY_HEADER)));
        assert_eq!(
            parse_record(&out[BODY_HEADER..]),
            Ok(Some((golden_record(), GOLDEN.len())))
        );
    }

    #[test]
    fn a_header_waits_for_five_bytes() {
        for cut in 0..BODY_HEADER {
            assert_eq!(parse_header(&b"WTIM\x02"[..cut]), Ok(None), "cut at {cut}");
        }
    }

    #[test]
    fn a_pre_versioned_body_is_refused_as_bad_magic() {
        let err = parse_header(&GOLDEN).unwrap_err();
        assert!(err.contains("magic") && err.contains("v1"), "{err}");
    }

    #[test]
    fn an_unsupported_version_is_refused_by_number() {
        for version in [1, 3] {
            let err = parse_header(&[b'W', b'T', b'I', b'M', version]).unwrap_err();
            assert!(err.contains(&format!("version {version}")), "{err}");
            assert!(err.contains(&format!("version {VERSION}")), "{err}");
        }
    }

    #[test]
    fn a_record_encodes_to_the_golden_bytes() {
        let mut out = Vec::new();
        encode_record_into(&mut out, GOLDEN_TS_US, &golden_frame(), true);
        assert_eq!(out, GOLDEN);
    }

    #[test]
    fn the_golden_bytes_decode_to_the_record() {
        let mut buf = GOLDEN.to_vec();
        let r = take_record(&mut buf).unwrap().unwrap();
        assert_eq!(r, golden_record());
        assert_eq!(r.fields(), RecordFields::from_can(&golden_frame(), true));
        assert_eq!(r.into_can(), golden_frame());
        assert!(buf.is_empty());
    }

    #[test]
    fn a_remote_frame_round_trips_with_its_length_code_and_no_payload() {
        let rtr = CanFrame::remote(1, 0x7DF, false, 8);
        let buf = encode(0, &rtr);
        assert_eq!((buf[12], buf[14]), (0x01 | 8 << 3, 0));
        assert_eq!(round_trip(&rtr), rtr);
    }

    #[test]
    fn an_fd_frame_with_brs_and_esi_round_trips() {
        let mut fd = CanFrame::data(0, 0x123, false, true, true, vec![0xAA; 12]);
        fd.esi = true;
        assert_eq!(encode(0, &fd)[12], 0x06);
        assert_eq!(round_trip(&fd), fd);
    }

    #[test]
    fn a_negative_timestamp_and_an_empty_payload_round_trip() {
        let mut buf = encode(-1, &CanFrame::data(0, 0x123, false, false, false, vec![]));
        assert_eq!(
            buf,
            [0xFF; 8]
                .iter()
                .chain(&[0x23, 0x01, 0, 0, 0, 0, 0])
                .copied()
                .collect::<Vec<_>>()
        );
        let r = take_record(&mut buf).unwrap().unwrap();
        assert_eq!((r.ts_us, r.id_flags, r.payload.len()), (-1, 0x123, 0));
    }

    #[test]
    fn an_incomplete_record_waits_for_more_at_every_cut() {
        for cut in 0..GOLDEN.len() {
            let mut buf = GOLDEN[..cut].to_vec();
            assert_eq!(take_record(&mut buf), Ok(None), "cut at {cut}");
            assert_eq!(buf.len(), cut, "nothing consumed");
        }
    }

    fn frame(id: u32, bus: u8, data: Vec<u8>) -> CanFrame {
        CanFrame::data(bus, id, false, data.len() > 8, false, data)
    }

    #[test]
    fn records_stream_back_to_back() {
        let mut buf = encode(1, &frame(0x100, 0, vec![1]));
        buf.extend(encode(2, &frame(0x200, 1, vec![2, 2])));
        buf.extend_from_slice(&GOLDEN[..5]);
        assert_eq!(take_record(&mut buf).unwrap().unwrap().ts_us, 1);
        assert_eq!(take_record(&mut buf).unwrap().unwrap().payload, [2, 2]);
        assert_eq!(take_record(&mut buf), Ok(None));
        assert_eq!(buf, GOLDEN[..5]);
    }

    #[test]
    fn parse_record_returns_the_bytes_consumed() {
        let buf = [&GOLDEN[..], &GOLDEN[..5]].concat();
        assert_eq!(
            parse_record(&buf),
            Ok(Some((golden_record(), GOLDEN.len())))
        );
    }

    fn records(n: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        for i in 0..n {
            let f = frame(i as u32 & 0x7FF, i as u8, vec![i as u8; i % 65]);
            encode_record_into(&mut buf, i as i64, &f, false);
        }
        buf
    }

    fn parse_by_offset(buf: &[u8]) -> Vec<Record> {
        let mut read = 0;
        let mut out = Vec::new();
        while let Some((record, consumed)) = parse_record(&buf[read..]).unwrap() {
            read += consumed;
            out.push(record);
        }
        assert_eq!(read, buf.len());
        out
    }

    #[test]
    fn walking_an_offset_reads_what_repeated_takes_read() {
        let mut buf = records(200);
        let by_offset = parse_by_offset(&buf);
        let taken: Vec<_> = std::iter::from_fn(|| take_record(&mut buf).unwrap()).collect();
        assert_eq!(by_offset, taken);
        assert_eq!(taken.len(), 200);
    }

    #[test]
    fn a_hundred_thousand_records_parse_by_offset() {
        assert_eq!(parse_by_offset(&records(100_000)).len(), 100_000);
    }

    #[test]
    fn a_length_over_64_is_refused_before_its_payload_arrives() {
        let mut buf = GOLDEN[..RECORD_HEADER].to_vec();
        buf[14] = 65;
        assert!(take_record(&mut buf).is_err());
        buf[14] = 64;
        assert_eq!(take_record(&mut buf), Ok(None));
    }

    #[test]
    fn an_over_long_payload_is_clamped_to_64() {
        let mut buf = encode(0, &frame(0, 0, vec![7; 100]));
        assert_eq!(buf.len(), RECORD_HEADER + 64);
        assert_eq!(take_record(&mut buf).unwrap().unwrap().payload, [7; 64]);
    }
}
