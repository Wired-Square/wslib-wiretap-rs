//! Reading a frame id (or source address) out of a framed serial message, and
//! writing one for display.

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
}
