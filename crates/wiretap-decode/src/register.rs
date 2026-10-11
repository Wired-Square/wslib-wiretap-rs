//! The readings a Modbus discovery table shows side by side: one register as
//! hex, u16, s16 and text, and two as u32, s32 and f32.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{printable, Endianness};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct RegisterView {
    /// Upper case, unseparated: `0938`.
    pub hex: String,
    pub u16: u16,
    pub s16: i16,
    /// Non-printable as `.`.
    pub ascii: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct RegisterPairView {
    pub u32: u32,
    pub s32: i32,
    /// Non-finite as JS `String()` spells it.
    #[serde(with = "js_number")]
    #[cfg_attr(
        feature = "ts",
        ts(type = r#"number | "NaN" | "Infinity" | "-Infinity""#)
    )]
    pub f32: f32,
}

mod js_number {
    use super::*;

    pub fn serialize<S: Serializer>(value: &f32, serializer: S) -> Result<S::Ok, S::Error> {
        match *value {
            v if v.is_nan() => serializer.serialize_str("NaN"),
            f32::INFINITY => serializer.serialize_str("Infinity"),
            f32::NEG_INFINITY => serializer.serialize_str("-Infinity"),
            v => serializer.serialize_f32(v),
        }
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Spelt {
        Number(f32),
        Text(String),
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<f32, D::Error> {
        match Spelt::deserialize(deserializer)? {
            Spelt::Number(v) => Ok(v),
            Spelt::Text(text) => match text.as_str() {
                "NaN" => Ok(f32::NAN),
                "Infinity" => Ok(f32::INFINITY),
                "-Infinity" => Ok(f32::NEG_INFINITY),
                _ => Err(serde::de::Error::custom(format!("no f32 spelt {text}"))),
            },
        }
    }
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

    #[test]
    fn a_non_finite_float_round_trips_as_its_js_spelling() {
        let pair = |f32| RegisterPairView {
            u32: 0,
            s32: 0,
            f32,
        };
        for (value, spelt) in [
            (f32::NAN, serde_json::json!("NaN")),
            (f32::INFINITY, serde_json::json!("Infinity")),
            (f32::NEG_INFINITY, serde_json::json!("-Infinity")),
            (236.5, serde_json::json!(236.5)),
        ] {
            let json = serde_json::to_value(pair(value)).unwrap();
            assert_eq!(json["f32"], spelt);
            let back: RegisterPairView = serde_json::from_value(json).unwrap();
            assert!(back.f32 == value || back.f32.is_nan() && value.is_nan());
        }
    }
}
