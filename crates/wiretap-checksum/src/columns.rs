//! Per-byte-column statistics over a set of payloads.
//!
//! Checksum columns are indexed from the *end* of the payload, because that is
//! where checksums live and it is the only indexing that lines up across frames
//! of different lengths on one link. Signals, mux selectors and ids are addressed
//! from the front, so the same accumulator runs from either [`Anchor`].

use serde::Serialize;

/// Below this many samples, one repeated value is not yet evidence of padding.
///
/// Deliberately private: both halves of the engine ask "is this column
/// constant" and they used to answer differently — identification rejected on
/// the first duplicate while scoring held out for eight samples, so a
/// thinly-sampled column could be called padding in the evidence panel and
/// swept as a candidate in the same result. [`ColumnStats::padding_value`] is
/// the only way to ask, and exporting the threshold would only invite a caller
/// to re-derive the check around it.
const CONSTANT_COLUMN_MIN_SAMPLES: usize = 8;

/// What one byte column does across the sample.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ColumnStats {
    /// Signed, as [`resolve_byte_index`](crate::frame::resolve_byte_index) reads it:
    /// 0 is the first byte, -1 the last.
    pub position: i32,
    pub distinct_values: usize,
    pub min: u8,
    pub max: u8,
    /// Set when the column holds one value across every sampled payload.
    pub constant_value: Option<u8>,
    /// Consecutive payload pairs in which this byte differed.
    pub changes: usize,
    /// Consecutive payload pairs the column took part in.
    pub transitions: usize,
    /// Shannon entropy of the observed values, in bits. 8.0 is the most a byte
    /// can carry; a counter over 16 values reaches 4.0.
    pub entropy_bits: f64,
    pub sample_count: usize,
}

impl ColumnStats {
    /// Distinct values against the most this column could have shown, which is
    /// bounded by the sample count as well as by the `span` a checksum of this
    /// width could reach — 256 for one byte, 65536 for two.
    pub fn distinct_ratio_over(&self, span: usize) -> f64 {
        let ceiling = self.sample_count.min(span);
        if ceiling == 0 {
            return 0.0;
        }
        self.distinct_values as f64 / ceiling as f64
    }

    /// Distinct values against the most a single byte column could have shown.
    pub fn distinct_ratio(&self) -> f64 {
        self.distinct_ratio_over(256)
    }

    /// The value this column is padded with, if enough samples agree to call it
    /// padding rather than a coincidence.
    pub fn padding_value(&self) -> Option<u8> {
        self.constant_value
            .filter(|_| self.sample_count >= CONSTANT_COLUMN_MIN_SAMPLES)
    }
}

/// Which end of the payload a column is counted from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    /// Byte 0 first, positions 0, 1, 2…
    Front,
    /// The last byte first, positions -1, -2, -3…
    End,
}

/// Profile every column of `payloads`, end-relative, out to the longest payload.
///
/// Payloads too short to reach a column simply do not contribute to it, the same
/// rule the checksum sweep uses — a one-byte acknowledgement sharing a link is
/// not evidence about byte -8.
pub fn analyse_columns(payloads: &[Vec<u8>]) -> Vec<ColumnStats> {
    analyse_columns_from(payloads, Anchor::End)
}

/// Profile every column of `payloads` from `anchor`, out to the longest payload,
/// under [`analyse_columns`]'s rule for payloads too short to reach a column.
pub fn analyse_columns_from(payloads: &[Vec<u8>], anchor: Anchor) -> Vec<ColumnStats> {
    let depth = payloads.iter().map(|p| p.len()).max().unwrap_or(0);

    (0..depth)
        .filter_map(|column| {
            let at = |payload: &[u8]| match anchor {
                Anchor::Front => payload.get(column).copied(),
                Anchor::End => payload.len().checked_sub(column + 1).map(|i| payload[i]),
            };
            let mut counts = [0usize; 256];
            let mut sample_count = 0usize;
            let mut previous: Option<u8> = None;
            let (mut changes, mut transitions) = (0usize, 0usize);

            for payload in payloads {
                let Some(byte) = at(payload) else {
                    // Too short for this column. It breaks the run of
                    // consecutive samples as well as contributing nothing —
                    // otherwise two payloads either side of a runt would read as
                    // adjacent.
                    previous = None;
                    continue;
                };

                counts[byte as usize] += 1;
                sample_count += 1;

                if let Some(prev) = previous {
                    transitions += 1;
                    if prev != byte {
                        changes += 1;
                    }
                }
                previous = Some(byte);
            }

            if sample_count == 0 {
                return None;
            }

            let observed: Vec<(u8, usize)> = counts
                .iter()
                .enumerate()
                .filter(|(_, n)| **n > 0)
                .map(|(value, n)| (value as u8, *n))
                .collect();

            let total = sample_count as f64;
            let entropy_bits = -observed
                .iter()
                .map(|(_, n)| {
                    let p = *n as f64 / total;
                    p * p.log2()
                })
                .sum::<f64>();

            Some(ColumnStats {
                position: match anchor {
                    Anchor::Front => column as i32,
                    Anchor::End => -(column as i32 + 1),
                },
                distinct_values: observed.len(),
                min: observed.first().map(|(v, _)| *v).unwrap_or(0),
                max: observed.last().map(|(v, _)| *v).unwrap_or(0),
                constant_value: (observed.len() == 1).then(|| observed[0].0),
                changes,
                transitions,
                entropy_bits,
                sample_count,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn a_constant_column_carries_no_entropy() {
        let payloads: Vec<Vec<u8>> = (0..20u8).map(|i| vec![i, 0x00]).collect();
        let columns = analyse_columns(&payloads);

        let last = columns.iter().find(|c| c.position == -1).unwrap();
        assert_eq!(last.constant_value, Some(0x00));
        assert_eq!(last.distinct_values, 1);
        assert_eq!(last.changes, 0);
        assert!(approx(last.entropy_bits, 0.0));
    }

    #[test]
    fn a_uniform_column_carries_its_full_bits() {
        // 256 values, each once: exactly 8 bits.
        let payloads: Vec<Vec<u8>> = (0..=255u8).map(|i| vec![i]).collect();
        let last = &analyse_columns(&payloads)[0];

        assert_eq!(last.distinct_values, 256);
        assert!(approx(last.entropy_bits, 8.0), "{}", last.entropy_bits);
        assert_eq!(last.changes, 255);
        assert_eq!(last.transitions, 255);
    }

    #[test]
    fn columns_are_end_relative_across_mixed_lengths() {
        let payloads = vec![vec![0x01, 0x02, 0xAA], vec![0x09, 0xAA], vec![0xAA]];
        let columns = analyse_columns(&payloads);

        let last = columns.iter().find(|c| c.position == -1).unwrap();
        assert_eq!(last.constant_value, Some(0xAA));
        assert_eq!(last.sample_count, 3);

        // Only the two longer payloads reach -2, and only the longest reaches -3.
        assert_eq!(
            columns
                .iter()
                .find(|c| c.position == -2)
                .unwrap()
                .sample_count,
            2
        );
        assert_eq!(
            columns
                .iter()
                .find(|c| c.position == -3)
                .unwrap()
                .sample_count,
            1
        );
    }

    /// A payload too short to reach a column must not make its neighbours look
    /// adjacent — that would invent a transition that never happened.
    #[test]
    fn a_short_payload_breaks_the_run_rather_than_joining_it() {
        let payloads = vec![vec![0x01, 0x11], vec![0x09], vec![0x01, 0x22]];
        let minus_two = analyse_columns(&payloads)
            .into_iter()
            .find(|c| c.position == -2)
            .unwrap();

        assert_eq!(minus_two.sample_count, 2);
        assert_eq!(minus_two.transitions, 0);
        assert_eq!(minus_two.changes, 0);
    }

    #[test]
    fn front_columns_count_from_byte_zero_and_keep_the_runt_rule() {
        let payloads = vec![vec![0x01, 0x11], vec![0x09], vec![0x01, 0x22]];
        let columns = analyse_columns_from(&payloads, Anchor::Front);

        assert_eq!(columns[0].position, 0);
        assert_eq!(columns[0].sample_count, 3);
        assert_eq!(columns[1].position, 1);
        assert_eq!(columns[1].sample_count, 2);
        assert_eq!(columns[1].transitions, 0);
    }

    #[test]
    fn analyse_columns_is_the_end_anchor() {
        let payloads = vec![vec![0x01, 0x02, 0xAA], vec![0x09, 0xAA], vec![0xAA]];
        assert_eq!(
            analyse_columns(&payloads),
            analyse_columns_from(&payloads, Anchor::End)
        );
    }

    #[test]
    fn distinct_ratio_is_bounded_by_the_sample_count() {
        let payloads: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i]).collect();
        let last = &analyse_columns(&payloads)[0];

        // Four distinct in four samples is saturated, not 4/256.
        assert!(approx(last.distinct_ratio(), 1.0));
    }

    /// A two-byte checksum reaches 65536 values, so the same column is far less
    /// saturated when judged as half of one.
    #[test]
    fn distinct_ratio_widens_with_the_span_asked_about() {
        let payloads: Vec<Vec<u8>> = (0..=255u8).map(|i| vec![i]).collect();
        let last = &analyse_columns(&payloads)[0];

        assert!(approx(last.distinct_ratio(), 1.0));
        assert!(approx(last.distinct_ratio_over(65536), 1.0));
    }

    /// One repeated value across three frames is a coincidence; across forty it
    /// is padding. Both halves of the engine now draw the line here.
    #[test]
    fn a_thinly_sampled_constant_column_is_not_yet_padding() {
        let thin: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i, 0x00]).collect();
        let last = analyse_columns(&thin).into_iter().next().unwrap();
        assert_eq!(last.constant_value, Some(0x00));
        assert_eq!(last.padding_value(), None);

        let plenty: Vec<Vec<u8>> = (0..40u8).map(|i| vec![i, 0x00]).collect();
        let last = analyse_columns(&plenty).into_iter().next().unwrap();
        assert_eq!(last.padding_value(), Some(0x00));
    }
}
