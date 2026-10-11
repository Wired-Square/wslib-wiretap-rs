//! Reading a frame id (or source address) out of a framed serial message, and
//! writing one for display.

use serde::{Deserialize, Serialize};

use crate::Endianness;

/// Where a frame id (or source address) sits in a framed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameIdField {
    /// Negative counts from the end.
    pub start_byte: i32,
    pub width: FrameIdWidth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameIdWidth {
    One,
    Two(Endianness),
}

/// The id `field` names in `frame`, or `None` when it runs past the end.
///
/// A negative start further back than the frame is long reads from its first
/// byte.
pub fn extract_frame_id(frame: &[u8], field: &FrameIdField) -> Option<u32> {
    let start = usize::try_from(field.start_byte).unwrap_or_else(|_| {
        frame
            .len()
            .saturating_sub(field.start_byte.unsigned_abs() as usize)
    });
    match field.width {
        FrameIdWidth::One => frame.get(start).copied().map(u32::from),
        FrameIdWidth::Two(endianness) => {
            let pair: [u8; 2] = frame.get(start..start + 2)?.try_into().ok()?;
            let id = match endianness {
                Endianness::Big => u16::from_be_bytes(pair),
                Endianness::Little => u16::from_le_bytes(pair),
            };
            Some(u32::from(id))
        }
    }
}

/// `0x` and upper-case hex, padded to 3 digits for a standard id and 8 for an
/// extended one.
pub fn format_frame_id(id: u32, extended: bool) -> String {
    let width = if extended { 8 } else { 3 };
    format!("0x{id:0width$X}")
}

/// The ids a CAN filter accepts, `id & mask` with the bits `mask` leaves free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct MatchedRange {
    pub lo: u32,
    pub hi: u32,
}

fn width_mask(width: u32) -> u32 {
    1u32.checked_shl(width).map_or(u32::MAX, |bit| bit - 1)
}

/// How many `width`-bit ids `mask` accepts: two to the power of the bits it
/// leaves free, saturating at `u64::MAX`.
pub fn matched_id_count(mask: u32, width: u32) -> u64 {
    let free = width - (mask & width_mask(width)).count_ones();
    1u64.checked_shl(free).unwrap_or(u64::MAX)
}

pub fn matched_range(id: u32, mask: u32, width: u32) -> MatchedRange {
    let lo = id & mask & width_mask(width);
    MatchedRange {
        lo,
        hi: lo | (!mask & width_mask(width)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Endianness::{Big, Little};

    fn one(start_byte: i32) -> FrameIdField {
        FrameIdField {
            start_byte,
            width: FrameIdWidth::One,
        }
    }

    fn two(start_byte: i32, endianness: Endianness) -> FrameIdField {
        FrameIdField {
            start_byte,
            width: FrameIdWidth::Two(endianness),
        }
    }

    #[test]
    fn a_frame_id_reads_one_or_two_bytes_in_either_order() {
        let frame = [0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(extract_frame_id(&frame, &one(0)), Some(0x01));
        assert_eq!(extract_frame_id(&frame, &two(1, Little)), Some(0x0302));
        assert_eq!(extract_frame_id(&frame, &two(1, Big)), Some(0x0203));
    }

    #[test]
    fn a_negative_start_counts_from_the_end() {
        let frame = [0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(extract_frame_id(&frame, &one(-1)), Some(0x05));
        assert_eq!(extract_frame_id(&frame, &two(-2, Big)), Some(0x0405));
    }

    #[test]
    fn a_negative_start_past_the_front_reads_from_the_first_byte() {
        let frame = [0x01, 0x02, 0x03];
        assert_eq!(extract_frame_id(&frame, &one(-10)), Some(0x01));
        assert_eq!(extract_frame_id(&frame, &two(i32::MIN, Big)), Some(0x0102));
    }

    #[test]
    fn a_frame_id_running_past_the_end_is_none() {
        let frame = [0x01, 0x02, 0x03];
        assert_eq!(extract_frame_id(&frame, &one(3)), None);
        assert_eq!(extract_frame_id(&frame, &two(2, Little)), None);
        assert_eq!(extract_frame_id(&frame, &two(-1, Big)), None);
        assert_eq!(extract_frame_id(&[], &one(0)), None);
        assert_eq!(extract_frame_id(&[], &one(-1)), None);
    }

    #[test]
    fn a_frame_id_is_padded_to_its_kind_s_width_and_never_cut() {
        assert_eq!(format_frame_id(0x7B, false), "0x07B");
        assert_eq!(format_frame_id(0x7B, true), "0x0000007B");
        assert_eq!(format_frame_id(0x18FF50E5, true), "0x18FF50E5");
        assert_eq!(format_frame_id(0x1234, false), "0x1234");
    }

    #[test]
    fn a_mask_counts_the_ids_its_free_bits_allow() {
        assert_eq!(matched_id_count(0x7FF, 11), 1);
        assert_eq!(matched_id_count(0x7F0, 11), 16);
        assert_eq!(matched_id_count(0, 11), 2048);
        assert_eq!(matched_id_count(0xFFFF_F800, 11), 2048);
        assert_eq!(matched_id_count(0x1FFF_FF00, 29), 256);
        assert_eq!(matched_id_count(0, 29), 1 << 29);
        assert_eq!(matched_id_count(0, 0), 1);
    }

    #[test]
    fn a_width_of_32_or_more_takes_every_mask_bit() {
        assert_eq!(matched_id_count(0, 32), 1 << 32);
        assert_eq!(matched_id_count(u32::MAX, 32), 1);
        assert_eq!(matched_id_count(0xFFFF_0000, 40), 1 << 24);
        assert_eq!(matched_id_count(0, 64), u64::MAX);
        assert_eq!(
            matched_range(0x1234_5678, 0xFFFF_0000, 32),
            MatchedRange {
                lo: 0x1234_0000,
                hi: 0x1234_FFFF
            }
        );
        assert_eq!(
            matched_range(0x1234_5678, 0xFFFF_0000, 40),
            MatchedRange {
                lo: 0x1234_0000,
                hi: 0x1234_FFFF
            }
        );
    }

    #[test]
    fn a_range_runs_from_the_masked_id_with_its_free_bits_set() {
        assert_eq!(
            matched_range(0x123, 0x7F0, 11),
            MatchedRange {
                lo: 0x120,
                hi: 0x12F
            }
        );
        assert_eq!(
            matched_range(0x123, 0x7FF, 11),
            MatchedRange {
                lo: 0x123,
                hi: 0x123
            }
        );
        assert_eq!(
            matched_range(0xFFF, 0, 11),
            MatchedRange { lo: 0, hi: 0x7FF }
        );
        assert_eq!(
            matched_range(0x18FF_50E5, 0x1FFF_FF00, 29),
            MatchedRange {
                lo: 0x18FF_5000,
                hi: 0x18FF_50FF
            }
        );
        assert_eq!(
            matched_range(0x123, 0x7F0, 0),
            MatchedRange { lo: 0, hi: 0 }
        );
    }
}
