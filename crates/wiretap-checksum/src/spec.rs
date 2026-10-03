//! One point in the checksum candidate space, and the sweep that measures many
//! of them against many frames at once.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::algorithms::{calculate_checksum_simple, ChecksumAlgorithm};
use crate::frame::{extract_checksum, field_fits, resolve_byte_index};

/// One point in the checksum candidate space: where the checksum sits, how it is
/// read, and which bytes it is calculated over.
///
/// Both the unit the sweep iterates and the wire type for the single-spec live
/// check the dialog runs behind a hand-edited configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumSpec {
    pub algorithm: ChecksumAlgorithm,
    /// Byte offset of the checksum; negative counts from the end.
    pub position: i32,
    pub byte_length: usize,
    pub big_endian: bool,
    pub calc_start_byte: i32,
    pub calc_end_byte: i32,
}

/// How one spec fared across the sampled frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumSpecResult {
    /// Index into the `specs` array the caller passed in.
    pub spec_index: usize,
    pub match_count: usize,
    /// Frames the spec actually fitted — frames too short for it are excluded
    /// rather than counted as misses.
    pub total_count: usize,
}

/// Run many checksum configurations against many frames.
///
/// Specs sharing an `(algorithm, calc_start_byte, calc_end_byte)` key are grouped
/// so the underlying CRC runs once per group per frame rather than once per spec —
/// the two endiannesses of a CRC-16, for instance, differ only in how the stored
/// value is read, never in what is calculated.
pub fn sweep_specs(frames: &[Vec<u8>], specs: &[ChecksumSpec]) -> Vec<ChecksumSpecResult> {
    let mut groups: HashMap<(ChecksumAlgorithm, i32, i32), Vec<usize>> = HashMap::new();
    for (idx, spec) in specs.iter().enumerate() {
        groups
            .entry((spec.algorithm, spec.calc_start_byte, spec.calc_end_byte))
            .or_default()
            .push(idx);
    }

    let mut results: Vec<ChecksumSpecResult> = Vec::new();

    for ((algorithm, calc_start, calc_end), members) in &groups {
        // Calculated value per frame, once for the whole group. `None` where the
        // range is degenerate for that frame.
        let calculated: Vec<Option<u16>> = frames
            .iter()
            .map(|frame| {
                let len = frame.len();
                let start = resolve_byte_index(*calc_start, len).min(len);
                let end = resolve_byte_index(*calc_end, len).min(len);
                (start < end).then(|| calculate_checksum_simple(*algorithm, &frame[start..end]))
            })
            .collect();

        for &idx in members {
            let spec = &specs[idx];
            let mut match_count = 0usize;
            let mut total_count = 0usize;

            for (frame, calc) in frames.iter().zip(&calculated) {
                let Some(calc) = calc else { continue };
                if !field_fits(spec.position, spec.byte_length, frame.len()) {
                    continue;
                }
                total_count += 1;
                let extracted =
                    extract_checksum(frame, spec.position, spec.byte_length, spec.big_endian)
                        .unwrap_or(0);
                if extracted == *calc {
                    match_count += 1;
                }
            }

            if total_count > 0 {
                results.push(ChecksumSpecResult {
                    spec_index: idx,
                    match_count,
                    total_count,
                });
            }
        }
    }

    results.sort_by_key(|r| r.spec_index);
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{real_serial_frames, spec};

    #[test]
    fn test_sweep_excludes_frames_too_short_for_the_spec() {
        // A 2-byte checksum at -2 does not fit a 1-byte frame, so that frame is
        // excluded from the denominator rather than counted as a miss.
        let frames = vec![vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06], vec![0x07]];
        let results = sweep_specs(
            &frames,
            &[spec(ChecksumAlgorithm::Crc16Ccitt, -2, 2, true, 0, -2)],
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].total_count, 1);
    }

    #[test]
    fn test_sweep_excludes_frames_with_an_empty_calculation_range() {
        // resolve_byte_index saturates, so on a short frame calc_start can land
        // at or past calc_end. Those frames are skipped, not scored as misses.
        let frames = vec![vec![0x01, 0x02, 0x03, 0x04], vec![0x09]];
        let results = sweep_specs(
            &frames,
            &[spec(ChecksumAlgorithm::Sum8, -1, 1, true, 0, -1)],
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].total_count, 1);
    }

    #[test]
    fn test_sweep_skips_frames_for_a_field_length_that_overflows() {
        let results = sweep_specs(
            &real_serial_frames(),
            &[spec(ChecksumAlgorithm::Sum8, 1, usize::MAX, true, 0, -1)],
        );

        assert!(results.is_empty());
    }

    #[test]
    fn test_sweep_reports_a_hand_typed_mismatch_rather_than_hiding_it() {
        // The dialog's live match rate goes through here, so a configuration the
        // user typed must come back as 0/N, not 0/0.
        let results = sweep_specs(
            &real_serial_frames(),
            &[spec(ChecksumAlgorithm::Crc16Modbus, -2, 2, false, 0, -2)],
        );

        assert_eq!(results[0].match_count, 0);
        assert_eq!(results[0].total_count, 5);
    }

    /// The grouping is an optimisation, so it must not change the answer: two
    /// specs differing only in endianness share one calculation but still get
    /// their own extraction.
    #[test]
    fn test_sweep_keeps_grouped_specs_independent() {
        let frames = real_serial_frames();
        let results = sweep_specs(
            &frames,
            &[
                spec(ChecksumAlgorithm::Crc16Modbus, -2, 2, false, 0, -2),
                spec(ChecksumAlgorithm::Crc16Modbus, -2, 2, true, 0, -2),
            ],
        );

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].spec_index, 0);
        assert_eq!(results[1].spec_index, 1);
    }
}
