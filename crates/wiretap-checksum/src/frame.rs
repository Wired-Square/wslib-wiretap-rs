//! Applying a checksum to a *frame*: end-relative byte addressing, reading a
//! stored checksum out of the bytes, and validating one against the other.
//!
//! Offsets are Python-style — a negative index counts from the end. Detection is
//! entirely end-relative, because that is the only way frames of different
//! lengths on one link line up.

use serde::{Deserialize, Serialize};
use wiretap_decode::frame_id::{extract_frame_id, FrameIdField, FrameIdWidth};
use wiretap_decode::Endianness;

use crate::algorithms::{calculate_checksum_simple, ChecksumAlgorithm};

/// Resolve a byte index, supporting Python-style negative indexing.
/// Negative indices count from the end: -1 = last byte, -2 = second-to-last, etc.
///
/// Saturates at 0, so an index more negative than the frame is long lands on the
/// first byte rather than wrapping.
pub fn resolve_byte_index(index: i32, frame_length: usize) -> usize {
    if index >= 0 {
        index as usize
    } else {
        frame_length.saturating_sub(index.unsigned_abs() as usize)
    }
}

pub(crate) fn field_fits(position: i32, byte_length: usize, frame_length: usize) -> bool {
    resolve_byte_index(position, frame_length)
        .checked_add(byte_length)
        .is_some_and(|end| end <= frame_length)
}

/// The bytes a checksum is calculated over in *this* frame, or `None` when the
/// frame is not evidence about the configuration at all.
///
/// Two conditions, and both matter. The frame must be long enough to hold the
/// checksum, and there must be something left to calculate over — a one-byte
/// acknowledgement sharing a link fits a trailing checksum *exactly*, leaving an
/// empty range, and counting it as a failure is the bug that has bitten this
/// engine more than once.
///
/// One definition, because the rule had been written out three times: here, in
/// the sweep, and in the solver's own sample gathering.
pub fn calculated_range(
    frame_length: usize,
    position: i32,
    byte_length: usize,
    calc_start_byte: i32,
    calc_end_byte: i32,
) -> Option<std::ops::Range<usize>> {
    if !field_fits(position, byte_length, frame_length) {
        return None;
    }
    let start = resolve_byte_index(calc_start_byte, frame_length).min(frame_length);
    let end = resolve_byte_index(calc_end_byte, frame_length).min(frame_length);
    (start < end).then_some(start..end)
}

/// Result of checksum validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksumValidationResult {
    /// The checksum value extracted from the frame
    pub extracted: u16,
    /// The calculated checksum value
    pub calculated: u16,
    /// Whether the frame is evidence (see [`calculated_range`]) and extracted == calculated
    pub valid: bool,
}

/// Calculate a checksum over a byte range of a frame.
///
/// `calc_end_byte` is exclusive. Both offsets support negative indexing. A
/// degenerate range (start at or past end) yields 0.
pub fn calculate_checksum(
    algorithm: ChecksumAlgorithm,
    data: &[u8],
    calc_start_byte: i32,
    calc_end_byte: i32,
) -> u16 {
    let length = data.len();
    let start = resolve_byte_index(calc_start_byte, length).min(length);
    let end = resolve_byte_index(calc_end_byte, length).min(length);

    if start >= end {
        return 0;
    }

    calculate_checksum_simple(algorithm, &data[start..end])
}

/// Read the stored checksum value out of a frame, or `None` when the field is
/// empty or would overrun the frame. Lengths beyond 2 must still fit, but only
/// the first two bytes are read — no supported algorithm is wider than 16 bits.
pub fn extract_checksum(
    data: &[u8],
    start_byte: i32,
    byte_length: usize,
    big_endian: bool,
) -> Option<u16> {
    let width = match byte_length {
        0 => return None,
        1 => FrameIdWidth::One,
        _ if big_endian => FrameIdWidth::Two(Endianness::Big),
        _ => FrameIdWidth::Two(Endianness::Little),
    };
    if !field_fits(start_byte, byte_length, data.len()) {
        return None;
    }
    extract_frame_id(data, &FrameIdField { start_byte, width }).map(|id| id as u16)
}

/// Check a frame's stored checksum against a freshly calculated one.
#[allow(clippy::too_many_arguments)]
pub fn validate_checksum(
    algorithm: ChecksumAlgorithm,
    data: &[u8],
    start_byte: i32,
    byte_length: usize,
    big_endian: bool,
    calc_start_byte: i32,
    calc_end_byte: i32,
) -> ChecksumValidationResult {
    let extracted = extract_checksum(data, start_byte, byte_length, big_endian).unwrap_or(0);
    let calculated = calculate_checksum(algorithm, data, calc_start_byte, calc_end_byte);

    ChecksumValidationResult {
        extracted,
        calculated,
        valid: extracted == calculated
            && calculated_range(
                data.len(),
                start_byte,
                byte_length,
                calc_start_byte,
                calc_end_byte,
            )
            .is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::{crc16_modbus_checksum, sum8_checksum};

    // ---- Byte index resolution -------------------------------------------

    #[test]
    fn test_resolve_byte_index_positive() {
        assert_eq!(resolve_byte_index(0, 10), 0);
        assert_eq!(resolve_byte_index(5, 10), 5);
        assert_eq!(resolve_byte_index(9, 10), 9);
    }

    #[test]
    fn test_resolve_byte_index_negative() {
        assert_eq!(resolve_byte_index(-1, 10), 9); // last byte
        assert_eq!(resolve_byte_index(-2, 10), 8); // second-to-last
        assert_eq!(resolve_byte_index(-10, 10), 0); // first byte
    }

    #[test]
    fn test_resolve_byte_index_clamps_overly_negative() {
        assert_eq!(resolve_byte_index(-11, 10), 0);
        assert_eq!(resolve_byte_index(-100, 10), 0);
    }

    #[test]
    fn an_index_of_i32_min_lands_on_the_first_byte() {
        assert_eq!(resolve_byte_index(i32::MIN, 10), 0);
    }

    // ---- Calculating over a range ----------------------------------------

    #[test]
    fn test_calculate_checksum_with_range() {
        // Frame: [header, data1, data2, data3, checksum_placeholder]
        let frame = [0x55u8, 0x01, 0x02, 0x03, 0x00];

        // Bytes 1..4 — the data, excluding the header at 0.
        assert_eq!(
            calculate_checksum(ChecksumAlgorithm::Sum8, &frame, 1, 4),
            0x06
        );
    }

    #[test]
    fn test_calculate_checksum_with_negative_indices() {
        let frame = [0x55u8, 0x01, 0x02, 0x03, 0x00];

        // Whole frame except the trailing checksum byte.
        assert_eq!(
            calculate_checksum(ChecksumAlgorithm::Sum8, &frame, 0, -1),
            0x5B
        );
    }

    #[test]
    fn test_calculate_checksum_over_a_degenerate_range_is_zero() {
        let frame = [0x55u8, 0x01];
        assert_eq!(
            calculate_checksum(ChecksumAlgorithm::Sum8, &frame, 2, -1),
            0
        );
    }

    // ---- Extraction -------------------------------------------------------

    #[test]
    fn test_extract_checksum_single_byte() {
        let data = [0x01, 0x02, 0x03, 0xAB];
        assert_eq!(extract_checksum(&data, 3, 1, true), Some(0xAB));
        assert_eq!(extract_checksum(&data, -1, 1, true), Some(0xAB));
    }

    #[test]
    fn test_extract_checksum_single_byte_negative_index() {
        let frame = [0x01, 0x02, 0x03, 0xAB, 0xCD];
        assert_eq!(extract_checksum(&frame, -2, 1, true), Some(0xAB));
    }

    #[test]
    fn test_extract_checksum_two_bytes() {
        let data = [0x01, 0x02, 0xAB, 0xCD];
        assert_eq!(extract_checksum(&data, 2, 2, true), Some(0xABCD));
        assert_eq!(extract_checksum(&data, -2, 2, true), Some(0xABCD));
        assert_eq!(extract_checksum(&data, 2, 2, false), Some(0xCDAB));
        assert_eq!(extract_checksum(&data, -2, 2, false), Some(0xCDAB));
    }

    #[test]
    fn an_extracted_checksum_overrunning_the_frame_is_none() {
        assert_eq!(extract_checksum(&[0x01], -1, 2, true), None);
        assert_eq!(extract_checksum(&[], -1, 1, true), None);
        assert_eq!(extract_checksum(&[0x01, 0x02, 0x03], 1, 3, true), None);
    }

    #[test]
    fn a_field_length_that_overflows_is_an_overrun() {
        let data = [0x01, 0x02, 0x03];
        assert_eq!(extract_checksum(&data, 1, usize::MAX, true), None);
        assert_eq!(calculated_range(data.len(), 1, usize::MAX, 0, -1), None);
        assert!(
            !validate_checksum(ChecksumAlgorithm::Sum8, &data, 1, usize::MAX, true, 0, -1).valid
        );
    }

    #[test]
    fn an_extracted_checksum_of_zero_length_is_none() {
        assert_eq!(extract_checksum(&[0x01, 0x02], 0, 0, true), None);
    }

    #[test]
    fn a_checksum_wider_than_two_bytes_reads_its_first_two() {
        let data = [0x01, 0xAB, 0xCD, 0xEF];
        assert_eq!(extract_checksum(&data, 1, 3, true), Some(0xABCD));
        assert_eq!(extract_checksum(&data, -3, 3, false), Some(0xCDAB));
    }

    #[test]
    fn a_checksum_starting_before_the_frame_reads_from_the_first_byte() {
        let data = [0xAB, 0xCD, 0xEF];
        assert_eq!(extract_checksum(&data, -10, 1, true), Some(0xAB));
        assert_eq!(extract_checksum(&data, i32::MIN, 2, true), Some(0xABCD));
    }

    // ---- Validation -------------------------------------------------------

    #[test]
    fn test_validate_checksum_xor_valid() {
        // data = [0x01, 0x02], XOR = 0x03
        let result = validate_checksum(
            ChecksumAlgorithm::Xor,
            &[0x01, 0x02, 0x03],
            2,
            1,
            true,
            0,
            2,
        );
        assert_eq!(result.extracted, 0x03);
        assert_eq!(result.calculated, 0x03);
        assert!(result.valid);
    }

    #[test]
    fn test_validate_checksum_sum8_valid() {
        let data = [0x01u8, 0x02, 0x03];
        let mut frame = Vec::from(data);
        frame.push(sum8_checksum(&data)); // 0x06

        let result = validate_checksum(ChecksumAlgorithm::Sum8, &frame, -1, 1, true, 0, -1);
        assert!(result.valid);
        assert_eq!(result.extracted, 0x06);
        assert_eq!(result.calculated, 0x06);
    }

    #[test]
    fn test_validate_checksum_invalid() {
        let frame = [0x01, 0x02, 0x03, 0xFF]; // wrong checksum
        let result = validate_checksum(ChecksumAlgorithm::Sum8, &frame, -1, 1, true, 0, -1);
        assert!(!result.valid);
        assert_eq!(result.extracted, 0xFF);
        assert_eq!(result.calculated, 0x06);
    }

    #[test]
    fn test_validate_checksum_is_invalid_when_the_frame_is_no_evidence() {
        let empty = validate_checksum(ChecksumAlgorithm::Sum8, &[], -1, 1, true, 0, -1);
        assert!(!empty.valid);

        let nothing_to_calculate_over =
            validate_checksum(ChecksumAlgorithm::Sum8, &[0x00], -1, 1, true, 0, -1);
        assert!(!nothing_to_calculate_over.valid);
        assert_eq!(nothing_to_calculate_over.extracted, 0);
        assert_eq!(nothing_to_calculate_over.calculated, 0);
    }

    #[test]
    fn test_validate_checksum_crc16_modbus_valid() {
        let data = [0x01u8, 0x03, 0x00, 0x00, 0x00, 0x0A];
        let crc = crc16_modbus_checksum(&data); // 0xCDC5
        let mut frame = Vec::from(data);
        // Modbus wire format is little-endian: low byte first.
        frame.push((crc & 0xFF) as u8);
        frame.push((crc >> 8) as u8);

        let result = validate_checksum(ChecksumAlgorithm::Crc16Modbus, &frame, -2, 2, false, 0, -2);
        assert!(result.valid);
        assert_eq!(result.extracted, 0xCDC5);
        assert_eq!(result.calculated, 0xCDC5);
    }
}
