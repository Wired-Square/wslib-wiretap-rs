//! An ad-hoc field: a bit field cut from a payload without a catalogue, and the
//! same field scaled. Both read through [`extract_bits`] and [`scale`], as a
//! catalogue signal does.

use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};

use crate::{extract_bits, scale, Endianness};

/// A bit field in a payload, numbered as [`extract_bits`] numbers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadField {
    pub start_bit: u32,
    pub bit_length: u32,
    pub endianness: Endianness,
    pub signed: bool,
}

impl PayloadField {
    /// An unsigned field of `len` whole bytes from byte `offset`.
    pub fn bytes(offset: u32, len: u32, endianness: Endianness) -> Self {
        Self {
            start_bit: offset * 8,
            bit_length: len * 8,
            endianness,
            signed: false,
        }
    }

    /// Whether the field is 1 to 64 bits long and ends within `payload_len` bytes.
    pub fn fits_in(&self, payload_len: usize) -> bool {
        let end = u64::from(self.start_bit) + u64::from(self.bit_length);
        (1..=64).contains(&self.bit_length) && end <= payload_len as u64 * 8
    }

    /// The raw value, or `None` when the field doesn't fit `payload`.
    pub fn read(&self, payload: &[u8]) -> Option<f64> {
        self.fits_in(payload.len()).then(|| {
            extract_bits(
                payload,
                self.start_bit,
                self.bit_length,
                self.endianness,
                self.signed,
            )
        })
    }
}

/// A [`PayloadField`] scaled `raw × factor + offset`; its JSON is the desktop's
/// `HypothesisParams`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScaledField {
    #[serde(flatten)]
    pub field: PayloadField,
    pub factor: f64,
    pub offset: f64,
}

impl ScaledField {
    /// The scaled value, or `None` when the field can't be read or [`scale`]
    /// can't scale it.
    pub fn decode(&self, payload: &[u8]) -> Option<f64> {
        let raw = self.field.read(payload)?;
        scale(raw, Some(self.factor), Some(self.offset))?.to_f64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Endianness::{Big, Little};

    /// The desktop's `byte_<offset>_<bits>b_<le|be>` decode, in its own arithmetic.
    fn desktop_byte_read(bytes: &[u8], offset: usize, bits: usize, le: bool) -> Option<f64> {
        if offset + bits / 8 > bytes.len() {
            return None;
        }
        let b = |i: usize| u32::from(bytes[offset + i]);
        Some(f64::from(match (bits, le) {
            (8, _) => b(0),
            (16, true) => b(0) | b(1) << 8,
            (16, false) => b(0) << 8 | b(1),
            (32, true) => b(0) | b(1) << 8 | b(2) << 16 | b(3) << 24,
            (32, false) => b(0) << 24 | b(1) << 16 | b(2) << 8 | b(3),
            _ => unreachable!(),
        }))
    }

    #[test]
    fn bytes_reads_as_the_desktops_byte_fields() {
        let payloads: [&[u8]; 3] = [
            &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0x00],
            &[0x80, 0x01, 0xFE],
        ];
        for payload in payloads {
            for bits in [8, 16, 32] {
                for offset in 0..=payload.len() {
                    for (endianness, le) in [(Little, true), (Big, false)] {
                        let field = PayloadField::bytes(offset as u32, bits as u32 / 8, endianness);
                        assert_eq!(
                            field.read(payload),
                            desktop_byte_read(payload, offset, bits, le),
                            "{payload:02X?} at {offset}, {bits} bits, {endianness:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn bytes_is_unsigned() {
        let field = PayloadField::bytes(0, 4, Little);
        assert_eq!(field.read(&[0xFF; 4]), Some(f64::from(u32::MAX)));
    }

    #[test]
    fn a_read_one_byte_short_is_none() {
        assert_eq!(PayloadField::bytes(1, 2, Big).read(&[1, 2]), None);
        assert_eq!(PayloadField::bytes(1, 2, Big).read(&[1, 2, 3]), Some(515.0));
    }

    #[test]
    fn a_field_of_no_bits_or_over_64_is_none() {
        let field = |bit_length| PayloadField {
            start_bit: 0,
            bit_length,
            endianness: Little,
            signed: false,
        };
        assert_eq!(field(0).read(&[0; 9]), None);
        assert_eq!(field(65).read(&[0; 9]), None);
        assert_eq!(field(64).read(&[0xFF; 9]), Some(u64::MAX as f64));
    }

    #[test]
    fn a_saved_hypothesis_round_trips() {
        let saved = serde_json::json!({
            "startBit": 12,
            "bitLength": 12,
            "endianness": "big",
            "signed": true,
            "factor": 0.1,
            "offset": -40.0,
        });
        let field: ScaledField = serde_json::from_value(saved.clone()).unwrap();
        assert_eq!(
            field.field,
            PayloadField {
                start_bit: 12,
                bit_length: 12,
                endianness: Big,
                signed: true,
            }
        );
        assert_eq!((field.factor, field.offset), (0.1, -40.0));
        assert_eq!(serde_json::to_value(field).unwrap(), saved);
    }

    #[test]
    fn decode_scales_exactly() {
        let field = ScaledField {
            field: PayloadField::bytes(0, 2, Big),
            factor: 0.1,
            offset: 0.0,
        };
        assert_eq!(field.decode(&3374u16.to_be_bytes()), Some(337.4));
        assert_eq!(field.decode(&[0x0D]), None);
    }

    #[test]
    fn decode_is_none_when_the_scaled_value_overflows() {
        let field = ScaledField {
            field: PayloadField::bytes(0, 8, Big),
            factor: 1e15,
            offset: 0.0,
        };
        assert_eq!(field.decode(&[0xFF; 8]), None);
    }
}
