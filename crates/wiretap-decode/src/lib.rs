//! Protocol-agnostic decode primitives shared across WireTAP's catalogue
//! decoders (CAN, Serial, Modbus). This is the numeric/bit core — bit
//! extraction, 16-bit word-swap, exact `Decimal` scaling, and value
//! formatting — with no dependency on the catalogue model, so both
//! `wiretap-catalog`'s `decode_by_id` path and its Modbus manifest poller share
//! one implementation.
//!
//! Scaling is done in `Decimal` on purpose: `raw × factor + offset` in `f64`
//! picks up binary-float noise (`3374 × 0.1` is `337.40000000000003`), which
//! then stringifies into displays and entity states. `Decimal::from_f64` rounds
//! the scale factor cleanly (`0.1`, `0.01`, …) and `raw` is integer-valued, so
//! the product is exact.
//!
//! [`frame_id`] reads a serial message's frame id out of its bytes and formats
//! one for display, [`hex`] reads a typed hex byte string, and [`field`] is a
//! bit field cut from a payload without a catalogue.

pub mod field;
pub mod frame_id;
pub mod hex;

pub use field::{PayloadField, ScaledField};

use rust_decimal::prelude::FromPrimitive;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// Byte / word ordering. `Big` is the standard convention (high-order first);
/// `Little` is byte/word-swapped (e.g. Sungrow's word-swapped "CDAB").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endianness {
    Big,
    Little,
}

// ---------- bit extraction ----------

/// Extract a bitfield as an `f64`, honouring endianness and sign. Faithful
/// port of `extractBits` (i128 accumulator covers up to 64-bit signals without
/// precision loss; the TS BigInt path is the same algorithm).
pub fn extract_bits(
    bytes: &[u8],
    start_bit: u32,
    bit_length: u32,
    endian: Endianness,
    signed: bool,
) -> f64 {
    if bit_length == 0 {
        return 0.0;
    }
    let mut bits: Vec<u8> = Vec::with_capacity(bytes.len() * 8);
    match endian {
        Endianness::Big => {
            for &b in bytes {
                for k in (0..8).rev() {
                    bits.push((b >> k) & 1);
                }
            }
        }
        Endianness::Little => {
            for &b in bytes {
                for k in 0..8 {
                    bits.push((b >> k) & 1);
                }
            }
        }
    }
    let start = (start_bit as usize).min(bits.len());
    let end = (start + bit_length as usize).min(bits.len());
    let slice = &bits[start..end];

    let mut value: i128 = 0;
    match endian {
        Endianness::Big => {
            for &bit in slice {
                value = (value << 1) | bit as i128;
            }
        }
        Endianness::Little => {
            for &bit in slice.iter().rev() {
                value = (value << 1) | bit as i128;
            }
        }
    }
    if signed {
        let sign_bit: i128 = 1 << (bit_length - 1);
        if value & sign_bit != 0 {
            value -= 1 << bit_length;
        }
    }
    value as f64
}

/// Swap 16-bit words within a signal's byte span (low-word-first →
/// high-word-first) before big-endian extraction — the Sungrow "CDAB" case.
/// Mirrors the word-swap in `decodeSignal` / modbus `apply_word_swap`.
pub fn apply_word_swap(bytes: &mut [u8], start_bit: u32, bit_length: u32) {
    let start_byte = (start_bit / 8) as usize;
    let num_bytes = bit_length.div_ceil(8) as usize;
    let num_words = num_bytes.div_ceil(2);
    let mut words: Vec<(u8, u8)> = Vec::with_capacity(num_words);
    for i in 0..num_words {
        let idx = start_byte + i * 2;
        let a = bytes.get(idx).copied().unwrap_or(0);
        let b = bytes.get(idx + 1).copied().unwrap_or(0);
        words.push((a, b));
    }
    words.reverse();
    for (i, (a, b)) in words.into_iter().enumerate() {
        let idx = start_byte + i * 2;
        if idx < bytes.len() {
            bytes[idx] = a;
        }
        if idx + 1 < bytes.len() {
            bytes[idx + 1] = b;
        }
    }
}

/// How a data block's bits are ordered.
///
/// A register bank is big-endian bytes, and a signal may override either order.
/// A coil bank has one order — eight to a byte, least significant bit first, the
/// order Modbus packs it in — and it is not a signal's to override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitOrder {
    Registers {
        endianness: Endianness,
        word_order: Option<Endianness>,
    },
    Coils,
}

impl BitOrder {
    /// The byte order bits are read in.
    pub fn endianness(self) -> Endianness {
        match self {
            BitOrder::Registers { endianness, .. } => endianness,
            BitOrder::Coils => Endianness::Little,
        }
    }

    /// Apply a signal's own orders. Only a register bank has any to override.
    pub fn with_overrides(
        self,
        endianness: Option<Endianness>,
        word_order: Option<Endianness>,
    ) -> Self {
        match self {
            BitOrder::Registers {
                endianness: e,
                word_order: w,
            } => BitOrder::Registers {
                endianness: endianness.unwrap_or(e),
                word_order: word_order.or(w),
            },
            BitOrder::Coils => BitOrder::Coils,
        }
    }
}

/// Cut a signal's raw bits out of a data block, in its bank's ordering.
///
/// The word-swap is why this exists rather than a bare [`extract_bits`]: it
/// applies only to a register bank, only for little word order, and only past
/// one register's width.
pub fn extract_field(
    bytes: &[u8],
    start_bit: u32,
    bit_length: u32,
    order: BitOrder,
    signed: bool,
) -> f64 {
    let swap = matches!(
        order,
        BitOrder::Registers {
            word_order: Some(Endianness::Little),
            ..
        }
    ) && bit_length > 16;
    if swap {
        // The swap needs a mutable copy; otherwise read the caller's buffer.
        let mut swapped = bytes.to_vec();
        apply_word_swap(&mut swapped, start_bit, bit_length);
        return extract_bits(&swapped, start_bit, bit_length, order.endianness(), signed);
    }
    extract_bits(bytes, start_bit, bit_length, order.endianness(), signed)
}

// ---------- exact scaling ----------

/// Scale an integer-valued `raw` by `factor`/`offset` (defaulting to ×1 +0) in
/// exact `Decimal`, so `raw × factor + offset` doesn't pick up binary-float
/// artifacts. `from_f64` rounds the scale factor cleanly; `raw` is integer.
///
/// `None` when an input is non-finite or outside `Decimal`'s range, or the
/// result overflows it.
pub fn scale(raw: f64, factor: Option<f64>, offset: Option<f64>) -> Option<Decimal> {
    let factor = factor.map_or(Some(Decimal::ONE), to_decimal)?;
    let offset = offset.map_or(Some(Decimal::ZERO), to_decimal)?;
    to_decimal(raw)?.checked_mul(factor)?.checked_add(offset)
}

/// `from_f64` rounds a magnitude below ~1e-28 to zero rather than refusing it.
fn to_decimal(x: f64) -> Option<Decimal> {
    Decimal::from_f64(x).filter(|d| !d.is_zero() || x == 0.0)
}

// ---------- value formatting ----------

/// Format a scaled `Decimal` as a clean display string (`555 × 0.1` → `"55.5"`,
/// `3374 × 0.1` → `"337.4"`), trimming trailing zeros via `normalize`. Exact —
/// no float round-trip.
pub fn format_decimal(value: Decimal) -> String {
    value.normalize().to_string()
}

/// Format a raw value as byte-separated hex (`"1A 2B 3C"`), MSB-first for big
/// endian. Port of `formatHex`.
pub fn format_hex(value: f64, bit_length: u32, endian: Endianness) -> String {
    let num_bytes = bit_length.div_ceil(8).max(1) as usize;
    let mask: u128 = if bit_length >= 128 {
        u128::MAX
    } else {
        (1u128 << bit_length) - 1
    };
    let mut v = (value as i128 as u128) & mask;
    let mut bytes = Vec::with_capacity(num_bytes);
    for _ in 0..num_bytes {
        bytes.push((v & 0xff) as u8);
        v >>= 8;
    }
    if endian == Endianness::Big {
        bytes.reverse();
    }
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Extract the bytes a text signal spans and decode to a string, dropping NULs.
/// Port of `extractTextBytes` + `bytesToText`.
pub fn decode_text(bytes: &[u8], start_bit: u32, bit_length: u32) -> String {
    let start_byte = (start_bit / 8) as usize;
    let num_bytes = bit_length.div_ceil(8) as usize;
    let mut out = String::new();
    for i in 0..num_bytes {
        let b = bytes.get(start_byte + i).copied().unwrap_or(0);
        if b != 0 {
            out.push(b as char);
        }
    }
    out
}

/// Format a unix timestamp as `YYYY-MM-DD HH:MM:SS` (UTC). The TS version uses
/// the browser's local timezone; we use UTC for determinism (the frontend may
/// re-localise). Seconds vs milliseconds is auto-detected as in the TS.
pub fn format_unix_time(value: f64) -> String {
    if !value.is_finite() {
        return format!("Invalid ({value})");
    }
    // > year ~3000 in seconds ⇒ treat as milliseconds.
    let secs = if value > 32_503_680_000.0 {
        (value / 1000.0) as i64
    } else {
        value as i64
    };
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// Convert a unix timestamp (seconds, UTC) to a civil date-time. Uses Howard
/// Hinnant's days→civil algorithm (proleptic Gregorian).
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, h as u32, mi as u32, s as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn big_endian_extract() {
        // 0x1234 over 16 bits, big endian.
        assert_eq!(
            extract_bits(&[0x12, 0x34], 0, 16, Endianness::Big, false),
            0x1234 as f64
        );
    }

    #[test]
    fn little_endian_extract() {
        assert_eq!(
            extract_bits(&[0x34, 0x12], 0, 16, Endianness::Little, false),
            0x1234 as f64
        );
    }

    #[test]
    fn signed_extract() {
        // 0xFF over 8 bits signed = -1.
        assert_eq!(extract_bits(&[0xFF], 0, 8, Endianness::Big, true), -1.0);
    }

    #[test]
    fn word_swap_cdab() {
        // "CDAB" word order: 0xAABB 0xCCDD stored as 0xCCDD 0xAABB.
        let mut b = [0xCC, 0xDD, 0xAA, 0xBB];
        apply_word_swap(&mut b, 0, 32);
        assert_eq!(b, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn scale_is_exact_not_float_noisy() {
        // The whole point: 555 × 0.1 and 3374 × 0.1 must be exact.
        assert_eq!(
            scale(555.0, Some(0.1), None).map(format_decimal).as_deref(),
            Some("55.5")
        );
        assert_eq!(
            scale(3374.0, Some(0.1), None)
                .map(format_decimal)
                .as_deref(),
            Some("337.4")
        );
        assert_eq!(scale(555.0, Some(0.1), None), Some(dec!(55.5)));
    }

    #[test]
    fn scale_defaults_and_offset() {
        assert_eq!(scale(100.0, None, None), Some(dec!(100)));
        assert_eq!(
            scale(100.0, None, None).map(format_decimal).as_deref(),
            Some("100")
        );
        assert_eq!(scale(10.0, Some(2.0), Some(5.0)), Some(dec!(25)));
        assert_eq!(scale(0.0, Some(0.0), Some(0.0)), Some(dec!(0)));
        assert_eq!(scale(10.0, Some(1e-28), None), Some(dec!(1e-27)));
    }

    #[test]
    fn scale_is_none_when_the_result_overflows_decimal() {
        assert_eq!(scale(u64::MAX as f64, Some(1e15), None), None);
        assert_eq!(scale(4294967295.0, Some(2e19), None), None);
        assert_eq!(scale(-(i64::MAX as f64), Some(-1e10), None), None);
        assert_eq!(scale(7.9e28, Some(1.0), Some(7.9e28)), None);
    }

    #[test]
    fn scale_is_none_for_a_non_finite_or_out_of_range_input() {
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 1e29] {
            assert_eq!(scale(10.0, Some(bad), None), None, "factor {bad}");
            assert_eq!(scale(10.0, None, Some(bad)), None, "offset {bad}");
            assert_eq!(scale(bad, None, None), None, "raw {bad}");
        }
    }

    #[test]
    fn scale_is_none_for_a_factor_too_small_for_decimal_not_zero() {
        assert_eq!(scale(10.0, Some(1e-30), None), None);
        assert_eq!(scale(10.0, None, Some(-1e-30)), None);
    }

    #[test]
    fn hex_format_big_endian() {
        assert_eq!(format_hex(0x1A2B as f64, 16, Endianness::Big), "1A 2B");
    }

    #[test]
    fn text_drops_nuls() {
        assert_eq!(decode_text(b"AB\0D", 0, 32), "ABD");
    }

    #[test]
    fn unix_time_utc() {
        assert_eq!(format_unix_time(0.0), "1970-01-01 00:00:00");
    }
}
