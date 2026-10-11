//! The Frame Calculator: a payload cut into groups of whole bytes or of a
//! repeating list of bit widths, each read at any width as unsigned, two's
//! complement, ones' complement and sign-magnitude, with its hex, binary and
//! text. A custom group's bits are [`crate::extract_bits`]' walk.

use serde::{Deserialize, Serialize};

use crate::{bit_walk, printable, Endianness};

/// How a group's bytes are ordered. Mid-big and mid-little swap the bytes of
/// each 16-bit word, then read as big and little.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "kebab-case")]
pub enum GroupOrder {
    Big,
    Little,
    MidBig,
    MidLittle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum GroupMode {
    #[serde(rename = "1B")]
    OneByte,
    #[serde(rename = "2B")]
    TwoBytes,
    #[serde(rename = "4B")]
    FourBytes,
    #[serde(rename = "8B")]
    EightBytes,
    /// Widths in bits, repeated until the payload runs out.
    #[serde(rename = "custom")]
    Custom(Vec<u32>),
}

/// One group, in the desktop's `GroupedValue` shape. The readings are decimal
/// strings; bit positions count `byte * 8 + bit`, bit 0 least significant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "GroupedValue"))]
#[serde(rename_all = "camelCase")]
pub struct Group {
    /// From 1.
    pub index: usize,
    pub bits: usize,
    pub hex: String,
    pub unsigned: String,
    pub signed_twos: String,
    pub signed_ones: String,
    pub signed_mag: String,
    /// The bytes the group's bits touch, non-printable as `.`.
    pub text: String,
    pub binary: String,
    /// The bytes the group's bits touch.
    pub display_hex: String,
    pub bit_offset: usize,
    pub start_byte_index: usize,
    pub used_bit_start: usize,
    pub used_bit_end: usize,
}

/// Group widths from a comma-separated list, each times `unit_bits`, with the
/// desktop's `parseInt` reading: `12abc` is 12, `1.5` is 1, and zero, negative
/// and unreadable entries are dropped. Nothing left reads as `[8]`, whatever
/// the unit.
pub fn parse_sizes(text: &str, unit_bits: u32) -> Vec<u32> {
    let sizes: Vec<u32> = text
        .split(',')
        .filter_map(|part| leading_int(&part.trim().replace('_', "")))
        .filter(|&n| n > 0)
        .map(|n| n.saturating_mul(unit_bits))
        .collect();
    if sizes.is_empty() {
        vec![8]
    } else {
        sizes
    }
}

fn leading_int(text: &str) -> Option<u32> {
    let text = text.trim_start();
    let text = text.strip_prefix('+').unwrap_or(text);
    let digits = text
        .find(|c: char| !c.is_ascii_digit())
        .map_or(text, |end| &text[..end]);
    (!digits.is_empty()).then(|| digits.parse().unwrap_or(u32::MAX))
}

pub fn decode_groups(bytes: &[u8], mode: &GroupMode, order: GroupOrder) -> Vec<Group> {
    let word = match mode {
        GroupMode::OneByte => return one_byte_groups(bytes, order),
        GroupMode::TwoBytes => 2,
        GroupMode::FourBytes => 4,
        GroupMode::EightBytes => 8,
        GroupMode::Custom(sizes) => return custom_groups(bytes, sizes, order),
    };
    bytes
        .chunks(word)
        .enumerate()
        .map(|(i, chunk)| byte_group(i, bytes, i * word, chunk.len(), order))
        .collect()
}

/// The whole payload reordered, one byte to a group, each labelled with the
/// byte it came from.
fn one_byte_groups(bytes: &[u8], order: GroupOrder) -> Vec<Group> {
    let indices: Vec<usize> = (0..bytes.len()).collect();
    reorder(&indices, order)
        .into_iter()
        .enumerate()
        .map(|(i, start)| byte_group(i, bytes, start, 1, order))
        .collect()
}

fn byte_group(i: usize, bytes: &[u8], start: usize, len: usize, order: GroupOrder) -> Group {
    let span = &bytes[start..start + len];
    let value: Vec<bool> = reorder(span, order)
        .into_iter()
        .flat_map(|b| (0..8).rev().map(move |k| b >> k & 1 == 1))
        .collect();
    let end = start * 8 + value.len() - 1;
    group(i, &value, span, end, start, start * 8, end)
}

/// The walk cut into consecutive runs of the widths in turn; a run past the
/// end is narrowed to what is left. Mid-big and mid-little walk the payload
/// with each word's bytes swapped, and positions name the original bytes.
fn custom_groups(bytes: &[u8], sizes: &[u32], order: GroupOrder) -> Vec<Group> {
    let (endian, swapped) = match order {
        GroupOrder::Big => (Endianness::Big, false),
        GroupOrder::MidBig => (Endianness::Big, true),
        GroupOrder::Little => (Endianness::Little, false),
        GroupOrder::MidLittle => (Endianness::Little, true),
    };
    let mut source: Vec<usize> = (0..bytes.len()).collect();
    if swapped {
        source = reorder(&source, GroupOrder::MidBig);
    }
    let walked: Vec<u8> = source.iter().map(|&i| bytes[i]).collect();
    let walk: Vec<(usize, bool)> = bit_walk(&walked, endian)
        .map(|(p, bit)| (source[p / 8] * 8 + p % 8, bit))
        .collect();
    let mut rest = &walk[..];
    let mut groups = Vec::new();
    for (i, &size) in sizes.iter().cycle().enumerate() {
        if rest.is_empty() || size == 0 {
            break;
        }
        let (run, after) = rest.split_at((size as usize).min(rest.len()));
        rest = after;
        let mut value: Vec<bool> = run.iter().map(|&(_, bit)| bit).collect();
        if endian == Endianness::Little {
            value.reverse();
        }
        let low = run.iter().map(|&(p, _)| p).min().unwrap_or_default();
        let high = run.iter().map(|&(p, _)| p).max().unwrap_or_default();
        let offset = if endian == Endianness::Big { high } else { low };
        groups.push(group(
            i,
            &value,
            &bytes[low / 8..=high / 8],
            offset,
            low / 8,
            low,
            high,
        ));
    }
    groups
}

fn reorder<T: Copy>(items: &[T], order: GroupOrder) -> Vec<T> {
    let word_swapped = || items.chunks(2).flat_map(|w| w.iter().rev().copied());
    match order {
        GroupOrder::Big => items.to_vec(),
        GroupOrder::Little => items.iter().rev().copied().collect(),
        GroupOrder::MidBig => word_swapped().collect(),
        GroupOrder::MidLittle => {
            let mut swapped: Vec<T> = word_swapped().collect();
            swapped.reverse();
            swapped
        }
    }
}

/// `value` is most significant bit first, and at least one bit.
fn group(
    i: usize,
    value: &[bool],
    span: &[u8],
    bit_offset: usize,
    start_byte_index: usize,
    used_bit_start: usize,
    used_bit_end: usize,
) -> Group {
    let unsigned = decimal(value.iter().copied());
    let negative = |magnitude: String| match magnitude.as_str() {
        "0" => magnitude,
        _ => format!("-{magnitude}"),
    };
    let inverted = || value.iter().map(|b| !b);
    let (signed_twos, signed_ones, signed_mag) = if value[0] {
        (
            negative(decimal(plus_one(inverted().collect()))),
            negative(decimal(inverted())),
            negative(decimal(value[1..].iter().copied())),
        )
    } else {
        (unsigned.clone(), unsigned.clone(), unsigned.clone())
    };
    Group {
        index: i + 1,
        bits: value.len(),
        hex: format!("0x{}", hex_digits(value)),
        unsigned,
        signed_twos,
        signed_ones,
        signed_mag,
        text: span.iter().map(|&b| printable(b)).collect(),
        binary: binary(value),
        display_hex: format!(
            "0x{}",
            span.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ),
        bit_offset,
        start_byte_index,
        used_bit_start,
        used_bit_end,
    }
}

fn decimal(bits: impl IntoIterator<Item = bool>) -> String {
    let mut digits = vec![0u8]; // least significant first
    for bit in bits {
        let mut carry = bit as u8;
        for d in &mut digits {
            let doubled = *d * 2 + carry;
            *d = doubled % 10;
            carry = doubled / 10;
        }
        if carry > 0 {
            digits.push(carry);
        }
    }
    digits.iter().rev().map(|&d| char::from(b'0' + d)).collect()
}

fn plus_one(mut bits: Vec<bool>) -> Vec<bool> {
    for bit in bits.iter_mut().rev() {
        *bit = !*bit;
        if *bit {
            return bits;
        }
    }
    bits.insert(0, true);
    bits
}

fn hex_digits(value: &[bool]) -> String {
    let pad = (4 - value.len() % 4) % 4;
    let padded: Vec<bool> = std::iter::repeat_n(false, pad)
        .chain(value.iter().copied())
        .collect();
    padded
        .chunks(4)
        .map(|nibble| nibble.iter().fold(0, |v, &b| v << 1 | b as u32))
        .map(|n| char::from_digit(n, 16).unwrap_or('0'))
        .collect()
}

/// Spaced every eight bits from the most significant.
fn binary(value: &[bool]) -> String {
    let mut out = String::with_capacity(value.len() * 9 / 8);
    for (i, &bit) in value.iter().enumerate() {
        if i > 0 && i % 8 == 0 {
            out.push(' ');
        }
        out.push(if bit { '1' } else { '0' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom(sizes: &[u32]) -> GroupMode {
        GroupMode::Custom(sizes.to_vec())
    }

    #[test]
    fn sizes_read_as_parse_int_does_and_fall_back_to_eight_bits() {
        assert_eq!(parse_sizes("3, 8,12abc", 1), [3, 8, 12]);
        assert_eq!(parse_sizes("1.5,1_6, +2", 8), [8, 128, 16]);
        assert_eq!(parse_sizes("0,-4,abc,", 8), [8]);
        assert_eq!(parse_sizes("", 8), [8]);
        assert_eq!(parse_sizes("99999999999", 8), [u32::MAX]);
    }

    #[test]
    fn signed_readings_follow_the_sign_bit() {
        let g = &decode_groups(&[0x80], &GroupMode::OneByte, GroupOrder::Big)[0];
        assert_eq!(
            (
                &*g.unsigned,
                &*g.signed_twos,
                &*g.signed_ones,
                &*g.signed_mag
            ),
            ("128", "-128", "-127", "0")
        );
        let g = &decode_groups(&[0xFF], &GroupMode::OneByte, GroupOrder::Big)[0];
        assert_eq!(
            (&*g.signed_twos, &*g.signed_ones, &*g.signed_mag),
            ("-1", "0", "-127")
        );
    }

    #[test]
    fn a_wide_custom_group_reads_exactly() {
        let groups = decode_groups(&[0xFF; 16], &custom(&[128]), GroupOrder::Big);
        assert_eq!(groups[0].unsigned, u128::MAX.to_string());
        assert_eq!(groups[0].signed_twos, "-1");
        let groups = decode_groups(&[0x80; 16], &custom(&[128]), GroupOrder::Little);
        assert_eq!(
            groups[0].signed_twos,
            i128::from_le_bytes([0x80; 16]).to_string()
        );
        assert_eq!(groups[0].hex, format!("0x{}", "80".repeat(16)));
    }

    #[test]
    fn mid_orders_swap_the_bytes_of_each_word() {
        let bytes = [0x12, 0x34, 0x56, 0x78];
        let hex = |order| {
            decode_groups(&bytes, &GroupMode::FourBytes, order)[0]
                .hex
                .clone()
        };
        assert_eq!(hex(GroupOrder::Big), "0x12345678");
        assert_eq!(hex(GroupOrder::Little), "0x78563412");
        assert_eq!(hex(GroupOrder::MidBig), "0x34127856");
        assert_eq!(hex(GroupOrder::MidLittle), "0x56781234");
    }

    #[test]
    fn a_mid_custom_group_reads_word_swapped_bytes_as_its_four_byte_twin() {
        let bytes = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let hexes = |order| -> Vec<String> {
            decode_groups(&bytes, &custom(&[32, 32]), order)
                .into_iter()
                .map(|g| g.hex)
                .collect()
        };
        assert_eq!(hexes(GroupOrder::MidBig), ["0x34127856", "0xbc9af0de"]);
        assert_eq!(hexes(GroupOrder::MidLittle), ["0x56781234", "0xdef09abc"]);
    }

    #[test]
    fn a_mid_custom_group_names_the_original_bytes() {
        let groups = decode_groups(&[0xE8, 0x08, 0x7f], &custom(&[4, 12]), GroupOrder::MidBig);
        let labels: Vec<_> = groups
            .iter()
            .map(|g| {
                let used = (g.used_bit_start, g.used_bit_end, g.bit_offset);
                (
                    g.hex.as_str(),
                    g.display_hex.as_str(),
                    g.start_byte_index,
                    used,
                )
            })
            .collect();
        assert_eq!(
            labels,
            [
                ("0x0", "0x08", 1, (12, 15, 15)),
                ("0x8e8", "0xe808", 0, (0, 11, 11)),
                ("0x7", "0x7f", 2, (20, 23, 23)),
                ("0xf", "0x7f", 2, (16, 19, 19)),
            ]
        );
    }

    #[test]
    fn a_one_byte_group_names_the_byte_it_came_from() {
        let groups = decode_groups(&[0x80, 0x01, 0x7f], &GroupMode::OneByte, GroupOrder::MidBig);
        let labels: Vec<_> = groups
            .iter()
            .map(|g| (g.hex.as_str(), g.display_hex.as_str(), g.start_byte_index))
            .collect();
        assert_eq!(
            labels,
            [
                ("0x01", "0x01", 1),
                ("0x80", "0x80", 0),
                ("0x7f", "0x7f", 2)
            ]
        );
        assert_eq!((groups[0].used_bit_start, groups[0].used_bit_end), (8, 15));
    }

    #[test]
    fn a_big_custom_group_shows_every_byte_its_bits_touch() {
        let groups = decode_groups(&[0xE8, 0x08], &custom(&[3]), GroupOrder::Big);
        let g = &groups[2];
        assert_eq!((g.hex.as_str(), g.display_hex.as_str()), ("0x0", "0xe808"));
        assert_eq!(
            (g.used_bit_start, g.used_bit_end, g.bit_offset),
            (0, 15, 15)
        );
    }

    #[test]
    fn group_serialises_as_the_desktop_s_grouped_value() {
        let g = &decode_groups(&[0x41], &GroupMode::OneByte, GroupOrder::Little)[0];
        assert_eq!(
            serde_json::to_value(g).unwrap(),
            serde_json::json!({
                "index": 1, "bits": 8, "hex": "0x41", "unsigned": "65", "signedTwos": "65",
                "signedOnes": "65", "signedMag": "65", "text": "A", "binary": "01000001",
                "displayHex": "0x41", "bitOffset": 7, "startByteIndex": 0,
                "usedBitStart": 0, "usedBitEnd": 7,
            })
        );
        assert_eq!(
            serde_json::to_value((GroupOrder::MidLittle, GroupMode::OneByte, custom(&[3])))
                .unwrap(),
            serde_json::json!(["mid-little", "1B", { "custom": [3] }])
        );
    }
}
