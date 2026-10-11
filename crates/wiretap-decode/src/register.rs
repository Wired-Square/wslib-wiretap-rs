//! The readings a Modbus discovery table shows side by side: one register as
//! hex, u16, s16 and text, and two as u32, s32 and f32.

use serde::{Deserialize, Serialize};

use crate::{printable, Endianness};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterView {
    /// Upper case, unseparated: `0938`.
    pub hex: String,
    pub u16: u16,
    pub s16: i16,
    /// Non-printable as `.`.
    pub ascii: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RegisterPairView {
    pub u32: u32,
    pub s32: i32,
    pub f32: f32,
}

/// A register's first two bytes, big-endian; a short register reads the bits
/// it has.
fn register_word(bytes: &[u8]) -> u16 {
    bytes
        .iter()
        .take(2)
        .fold(0, |value, &b| (value << 8) | u16::from(b))
}

pub fn interpret_register(bytes: &[u8]) -> RegisterView {
    let word = &bytes[..bytes.len().min(2)];
    let u16 = register_word(bytes);
    RegisterView {
        hex: word.iter().map(|b| format!("{b:02X}")).collect(),
        u16,
        s16: u16 as i16,
        ascii: word.iter().map(|&b| printable(b)).collect(),
    }
}

/// Two adjacent registers as one 32-bit value. `Big` word order takes the high
/// word from `first`, `Little` from `second`.
pub fn interpret_pair(first: &[u8], second: &[u8], word_order: Endianness) -> RegisterPairView {
    let (a, b) = (register_word(first), register_word(second));
    let (high, low) = match word_order {
        Endianness::Big => (a, b),
        Endianness::Little => (b, a),
    };
    let u32 = u32::from(high) << 16 | u32::from(low);
    RegisterPairView {
        u32,
        s32: u32 as i32,
        f32: f32::from_bits(u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_register_reads_four_ways() {
        assert_eq!(
            interpret_register(&[0x09, 0x38]),
            RegisterView {
                hex: "0938".into(),
                u16: 2360,
                s16: 2360,
                ascii: ".8".into()
            }
        );
        let negative = interpret_register(&[0xFF, 0xFE, 0x41]);
        assert_eq!(
            (negative.hex.as_str(), negative.u16, negative.s16),
            ("FFFE", 0xFFFE, -2)
        );
        assert_eq!(interpret_register(b"Hi").ascii, "Hi");
    }

    #[test]
    fn a_short_register_reads_the_bits_it_has() {
        let one = interpret_register(&[0x8A]);
        assert_eq!(
            (one.hex.as_str(), one.u16, one.s16, one.ascii.as_str()),
            ("8A", 0x8A, 0x8A, ".")
        );
        let none = interpret_register(&[]);
        assert_eq!(
            (none.hex.as_str(), none.u16, none.ascii.as_str()),
            ("", 0, "")
        );
        assert_eq!(
            interpret_pair(&[0x01], &[], Endianness::Big).u32,
            0x0001_0000
        );
    }

    #[test]
    fn word_order_picks_the_high_register() {
        let big = interpret_pair(&[0x00, 0x01], &[0x86, 0xA0], Endianness::Big);
        assert_eq!((big.u32, big.s32), (100_000, 100_000));
        let little = interpret_pair(&[0x86, 0xA0], &[0x00, 0x01], Endianness::Little);
        assert_eq!(little, big);
        let negative = interpret_pair(&[0xFF, 0xFF], &[0xFF, 0xFE], Endianness::Big);
        assert_eq!((negative.u32, negative.s32), (0xFFFF_FFFE, -2));
    }

    #[test]
    fn a_pair_reads_as_an_ieee_float() {
        let f32_of =
            |first: [u8; 2], second: [u8; 2]| interpret_pair(&first, &second, Endianness::Big).f32;
        assert_eq!(f32_of([0x43, 0x6C], [0x00, 0x00]), 236.0);
        assert_eq!(f32_of([0xBF, 0x80], [0x00, 0x00]), -1.0);
        assert_eq!(f32_of([0x7F, 0x80], [0x00, 0x00]), f32::INFINITY);
        assert_eq!(f32_of([0xFF, 0x80], [0x00, 0x00]), f32::NEG_INFINITY);
        assert!(f32_of([0x7F, 0xC0], [0x00, 0x00]).is_nan());
        assert_eq!(f32_of([0x7F, 0xC0], [0x00, 0x01]).to_bits(), 0x7FC0_0001);
        assert_eq!(f32_of([0x00, 0x00], [0x00, 0x01]), f32::from_bits(1));
    }
}
