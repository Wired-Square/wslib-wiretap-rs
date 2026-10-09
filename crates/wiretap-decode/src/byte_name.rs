//! The names a field cut without a catalogue is saved under:
//! `byte_<offset>_<bits>b_<le|be>`, and the older `byte[i]` for one byte.

use crate::{Endianness, PayloadField};

/// `byte_<offset>_<bits>b_<le|be>`, the one spelling written.
pub fn byte_name(offset: u32, bits: u32, endianness: Endianness) -> String {
    let order = match endianness {
        Endianness::Little => "le",
        Endianness::Big => "be",
    };
    format!("byte_{offset}_{bits}b_{order}")
}

/// The unsigned field a [`byte_name`] or a `byte[i]` names. Bits are a multiple
/// of 8 from 8 to 64; `byte[i]` is `byte_<i>_8b_le`.
pub fn parse_byte_name(name: &str) -> Option<PayloadField> {
    if let Some(index) = name.strip_prefix("byte[").and_then(|s| s.strip_suffix(']')) {
        return Some(PayloadField::bytes(
            index.parse().ok()?,
            1,
            Endianness::Little,
        ));
    }
    let mut parts = name.strip_prefix("byte_")?.split('_');
    let offset = parts.next()?.parse().ok()?;
    let bits: u32 = parts.next()?.strip_suffix('b')?.parse().ok()?;
    let endianness = match parts.next()? {
        "le" => Endianness::Little,
        "be" => Endianness::Big,
        _ => return None,
    };
    (parts.next().is_none() && bits.is_multiple_of(8) && (8..=64).contains(&bits))
        .then(|| PayloadField::bytes(offset, bits / 8, endianness))
}

#[cfg(test)]
mod tests {
    use super::*;
    use Endianness::{Big, Little};

    #[test]
    fn a_name_reads_back_as_its_field() {
        for (offset, bits, order) in [(0, 8, Little), (5, 16, Big), (3, 32, Little), (1, 64, Big)] {
            let name = byte_name(offset, bits, order);
            assert_eq!(
                parse_byte_name(&name),
                Some(PayloadField::bytes(offset, bits / 8, order)),
                "{name}"
            );
        }
        assert_eq!(byte_name(5, 16, Big), "byte_5_16b_be");
    }

    #[test]
    fn the_older_index_spelling_is_one_little_endian_byte() {
        assert_eq!(parse_byte_name("byte[3]"), parse_byte_name("byte_3_8b_le"));
    }

    #[test]
    fn widths_off_the_byte_grid_or_past_64_bits_are_refused() {
        for name in [
            "byte_0_12b_le",
            "byte_0_0b_le",
            "byte_0_72b_le",
            "byte_0_16b_xe",
            "byte_0_16_le",
            "byte_0_16b_le_x",
            "byte_x_16b_le",
            "byte[]",
            "byte[-1]",
            "hyp_100_b0_16le",
        ] {
            assert_eq!(parse_byte_name(name), None, "{name}");
        }
    }
}
