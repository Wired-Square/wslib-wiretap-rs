//! Fixtures shared across the crate's test modules.
//!
//! These are capture bytes, not tidied ones. A fixture that removes the awkward
//! case removes the bug class with it — the one-byte acknowledgements in
//! [`real_serial_frames_with_acks`] are exactly what a per-space feasibility
//! gate keyed on the *shortest* frame got wrong, and the tidied five-frame
//! fixture stayed green throughout.

use crate::algorithms::{crc16_modbus_checksum, ChecksumAlgorithm};
use crate::spec::ChecksumSpec;

pub fn spec(
    algorithm: ChecksumAlgorithm,
    position: i32,
    byte_length: usize,
    big_endian: bool,
    calc_start_byte: i32,
    calc_end_byte: i32,
) -> ChecksumSpec {
    ChecksumSpec {
        algorithm,
        position,
        byte_length,
        big_endian,
        calc_start_byte,
        calc_end_byte,
    }
}

/// Five frames captured from a real SLIP serial source. The checksum is a
/// sum of every byte after the leading type byte — note frames 4 and 5 are
/// permutations of each other differing only at byte 0, and share a checksum.
/// Byte -2 is constant 0x00 padding.
pub fn real_serial_frames() -> Vec<Vec<u8>> {
    vec![
        vec![
            0xFD, 0xE0, 0x55, 0x23, 0xF0, 0x0D, 0x03, 0x05, 0xDC, 0, 0, 0, 0, 0, 0x00, 0x39,
        ],
        vec![
            0xFB, 0xEB, 0xF0, 0x0D, 0x55, 0x23, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x60,
        ],
        vec![
            0xFD, 0xEB, 0x55, 0x23, 0x00, 0x6C, 0x03, 0xCF, 0x00, 0xF4, 0, 0, 0, 0, 0, 0, 0, 0,
            0x00, 0x95,
        ],
        vec![
            0xFB, 0xE0, 0xF0, 0x0D, 0x60, 0x61, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x9E,
        ],
        vec![
            0xFD, 0xE0, 0x60, 0x61, 0xF0, 0x0D, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x9E,
        ],
    ]
}

/// The reported capture as it actually arrives, rather than tidied up: the
/// same link carries bare one-byte acknowledgements, which are too short to
/// hold a checksum at all. The payload frames still sum bytes 1.. into the
/// last byte — 0xF1+0xF0+0x0D+0x55+0x23 is 0x66, and the third frame's
/// bytes happen to sum to 0x00.
pub fn real_serial_frames_with_acks() -> Vec<Vec<u8>> {
    [
        vec![
            0xFBu8, 0xF1, 0xF0, 0x0D, 0x55, 0x23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x66,
        ],
        vec![0xFC],
        vec![
            0xFD, 0xF1, 0x55, 0x23, 0x30, 0x31, 0x36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00,
        ],
        vec![0xF8],
        vec![
            0xFB, 0xE0, 0xF0, 0x0D, 0x60, 0x61, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x9E,
        ],
    ]
    .into_iter()
    .cycle()
    .take(120)
    .collect()
}

/// Repeated so the sample-count tiers behave as they would on a live capture.
pub fn many_real_frames() -> Vec<Vec<u8>> {
    real_serial_frames().into_iter().cycle().take(100).collect()
}

pub fn modbus_frames() -> Vec<Vec<u8>> {
    [
        vec![0x01u8, 0x03, 0x00, 0x00, 0x00, 0x0A],
        vec![0x01, 0x03, 0x00, 0x10, 0x00, 0x02],
        vec![0x02, 0x04, 0x00, 0x64, 0x00, 0x08],
        vec![0x03, 0x06, 0x00, 0x01, 0x12, 0x34],
        vec![0x01, 0x10, 0x00, 0x20, 0x00, 0x01],
    ]
    .into_iter()
    .cycle()
    .take(60)
    .map(|mut body| {
        let crc = crc16_modbus_checksum(&body);
        body.push((crc & 0xFF) as u8);
        body.push((crc >> 8) as u8);
        body
    })
    .collect()
}
