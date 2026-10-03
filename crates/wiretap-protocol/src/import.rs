//! The WireTAP desktop's HTTP capture-import record (`docs/import.md`), both
//! ends: what the desktop streams to a gateway's import endpoint, and what the
//! gateway parses. A body is these records back to back, with no framing,
//! header or checksum around them:
//! `ts_us i64 | id_flags u32 | bus u8 | len u8 | payload`, little-endian.
//!
//! CAN only. `id_flags` is the ingest protocol's CAN word, so it is packed with
//! [`ingest::record_id_flags`] and unpacked with [`ingest::record_id_fields`].

use crate::ingest::{self, RecordKind};

/// `ts_us i64 | id_flags u32 | bus u8 | len u8`.
pub const RECORD_HEADER: usize = 14;

/// Append one record. A payload over 64 bytes, one CAN FD frame, is clamped to
/// it, as [`ingest::encode_record_into`] clamps.
pub fn encode_record_into(out: &mut Vec<u8>, ts_us: i64, id_flags: u32, bus: u8, payload: &[u8]) {
    let payload = &payload[..payload.len().min(RecordKind::Can.max_payload())];
    out.reserve(RECORD_HEADER + payload.len());
    out.extend_from_slice(&ts_us.to_le_bytes());
    out.extend_from_slice(&id_flags.to_le_bytes());
    out.push(bus);
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub ts_us: i64,
    pub id_flags: u32,
    pub bus: u8,
    pub payload: Vec<u8>,
}

impl Record {
    /// `(arb_id, extended, is_fd, transmitted)`, as [`ingest::record_id_fields`].
    pub fn fields(&self) -> (u32, bool, bool, bool) {
        ingest::record_id_fields(self.id_flags)
    }
}

/// Try to consume one complete record from the front of `buf`.
/// `Ok(None)` = need more bytes; `Err` = a length over 64, after which the
/// stream cannot be resynchronised.
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
    let len = buf[13] as usize;
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
        bus: buf[12],
        payload: buf[RECORD_HEADER..total].to_vec(),
    };
    Ok(Some((record, total)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::record_id_flags;

    /// An extended FD frame the desktop transmitted, on bus 2, at
    /// 2026-01-01T00:00:00Z.
    const GOLDEN: [u8; 17] = [
        0x00, 0x40, 0x20, 0x46, 0x48, 0x47, 0x06, 0x00, // ts_us
        0x10, 0xF1, 0xDA, 0xF8, // id_flags
        0x02, // bus
        0x03, // len
        0xDE, 0xAD, 0x01, // payload
    ];

    fn golden_record() -> Record {
        Record {
            ts_us: 1_767_225_600_000_000,
            id_flags: record_id_flags(0x18DA_F110, true, true, true),
            bus: 2,
            payload: vec![0xDE, 0xAD, 0x01],
        }
    }

    #[test]
    fn a_record_encodes_to_the_golden_bytes() {
        let r = golden_record();
        let mut out = Vec::new();
        encode_record_into(&mut out, r.ts_us, r.id_flags, r.bus, &r.payload);
        assert_eq!(out, GOLDEN);
    }

    #[test]
    fn the_golden_bytes_decode_to_the_record() {
        let mut buf = GOLDEN.to_vec();
        let r = take_record(&mut buf).unwrap().unwrap();
        assert_eq!(r, golden_record());
        assert_eq!(r.fields(), (0x18DA_F110, true, true, true));
        assert!(buf.is_empty());
    }

    #[test]
    fn a_negative_timestamp_and_an_empty_payload_round_trip() {
        let mut buf = Vec::new();
        encode_record_into(&mut buf, -1, 0x123, 0, &[]);
        assert_eq!(
            buf,
            [0xFF; 8]
                .iter()
                .chain(&[0x23, 0x01, 0, 0, 0, 0])
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

    #[test]
    fn records_stream_back_to_back() {
        let mut buf = Vec::new();
        encode_record_into(&mut buf, 1, 0x100, 0, &[1]);
        encode_record_into(&mut buf, 2, 0x200, 1, &[2, 2]);
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
            encode_record_into(
                &mut buf,
                i as i64,
                i as u32,
                i as u8,
                &vec![i as u8; i % 65],
            );
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
        buf[13] = 65;
        assert!(take_record(&mut buf).is_err());
        buf[13] = 64;
        assert_eq!(take_record(&mut buf), Ok(None));
    }

    #[test]
    fn an_over_long_payload_is_clamped_to_64() {
        let mut buf = Vec::new();
        encode_record_into(&mut buf, 0, 0, 0, &[7; 100]);
        assert_eq!(buf.len(), RECORD_HEADER + 64);
        assert_eq!(take_record(&mut buf).unwrap().unwrap().payload, [7; 64]);
    }
}
