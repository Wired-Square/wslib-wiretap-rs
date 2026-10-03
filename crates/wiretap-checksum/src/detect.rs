//! The detection engine: sweep a candidate space, score each candidate with a
//! composite confidence, return them ranked with notes explaining the verdict.
//!
//! This lives beside the algorithms rather than in the caller so there is exactly
//! one implementation of each — an earlier split put the scoring on the far side
//! of an IPC boundary and needed a hand-maintained copy of all eleven algorithms
//! just to test it.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::algorithms::{ChecksumAlgorithm, ALL_ALGORITHMS};
use crate::columns::{analyse_columns, ColumnStats};
use crate::frame::resolve_byte_index;
use crate::notes::ChecksumNote;
use crate::sampling::strided_samples;
use crate::spec::{sweep_specs, ChecksumSpec};

/// How many end-relative byte columns the result reports on, at minimum.
/// Columns themselves are profiled to the longest payload — the calculation
/// ranges need to see a run of padding wherever it starts — but "the last few
/// bytes are 0x00" stops being one useful fact if it reaches the whole frame.
const MIN_TAIL_DEPTH: i32 = 4;

/// Cap on the returned candidate list.
const MAX_CANDIDATES: usize = 12;

/// Confidence below which a candidate is not worth reporting.
///
/// Exported because the solver's scorer applies the same floor, and the two rank
/// into one list — the same reason [`volume_bonus`] is public. It was the
/// `Default` here and a private const in the scan, which is one number spelled
/// twice.
pub const MIN_CONFIDENCE: u8 = 35;

/// The match rate at which a swept candidate stops being a coincidence.
///
/// A checksum that reproduces 94% of a capture is not a low-scoring checksum, it
/// is the wrong answer. The whole-capture scan filters here; the serial dialog
/// deliberately keeps a lower default so a hand-driven search can see near
/// misses.
pub const STRONG_MATCH_RATE: f64 = 95.0;

/// Frames sampled for detection. The dialog reads the same number from the
/// capture, so both halves measure against one set.
pub const MAX_SAMPLES: usize = 200;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ChecksumDetectionOptions {
    /// Checksum offsets to try, end-relative.
    pub positions: Vec<i32>,
    /// Restrict to checksums of these byte lengths. Empty means both.
    pub lengths: Vec<usize>,
    /// Byte offsets just past a declared header field, from the view's ID/Source
    /// chips. These widen the calculation-range candidates and earn a small
    /// confidence bonus; they never narrow the search.
    pub header_boundaries: Vec<i32>,
    /// Percentage below which a candidate is discarded.
    pub min_match_rate: f64,
    /// Confidence below which a candidate is discarded.
    pub min_confidence: u8,
}

impl Default for ChecksumDetectionOptions {
    fn default() -> Self {
        Self {
            positions: vec![-1, -2, -3],
            lengths: Vec::new(),
            header_boundaries: Vec::new(),
            min_match_rate: 50.0,
            min_confidence: MIN_CONFIDENCE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CalcRange {
    pub calc_start_byte: i32,
    pub calc_end_byte: i32,
}

/// A checksum configuration that reproduces some or all of the sampled frames.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumCandidate {
    pub algorithm: ChecksumAlgorithm,
    pub position: i32,
    pub length: usize,
    pub big_endian: bool,
    pub calc_start_byte: i32,
    pub calc_end_byte: i32,
    pub match_count: usize,
    pub total_count: usize,
    /// 0-100
    pub match_rate: f64,
    /// 0-100 composite score.
    pub confidence: u8,
    pub notes: Vec<ChecksumNote>,
    /// Other calculation ranges that scored identically. Kept rather than
    /// dropped, so a user who disagrees with the winner can see the alternatives.
    pub equivalent_ranges: Vec<CalcRange>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumDetectionResult {
    pub candidates: Vec<ChecksumCandidate>,
    pub best_candidate: Option<ChecksumCandidate>,
    pub tail_columns: Vec<ColumnStats>,
    /// Result-level explanation, including why nothing was found.
    pub notes: Vec<ChecksumNote>,
}

fn column_at(columns: &[ColumnStats], position: i32) -> Option<&ColumnStats> {
    columns.iter().find(|c| c.position == position)
}

/// Number of padding columns sitting immediately before `position`.
fn constant_run_before(position: i32, columns: &[ColumnStats]) -> i32 {
    let mut run = 0;
    let mut p = position.saturating_sub(1);
    while column_at(columns, p).is_some_and(|c| c.padding_value().is_some()) {
        run += 1;
        p -= 1;
    }
    run
}

/// The calculation ranges worth trying for a checksum at `position`.
///
/// This is the candidate space both halves of the engine search, and it exists
/// as one function because they used to disagree. The sweep tried these starts;
/// the solver hardcoded `0` — so a checksum over `1..n`, which is what a leading
/// type or id byte excluded from the calculation looks like and what the Tesla
/// HPWC sum actually does, could be *matched* but never *solved*. Ticking
/// "search custom polynomials" on such a frame reported nothing, with no knob to
/// turn.
///
/// **Starts** are 0, 1, 2 and any declared header boundary. `1` and `2` are not
/// arbitrary: a one- or two-byte header excluded from the calculation is the
/// common shape, and it is the one a declared boundary cannot express when the
/// field starts at byte 0.
///
/// **Ends** are the checksum's own position, and — when a run of padding sits
/// immediately before it — the position in front of that run. Both are offered
/// because a constant range contributes a constant, so including or excluding
/// it changes the offset and never the algorithm; the data cannot distinguish
/// them and the caller should not pretend otherwise.
pub fn calc_ranges(
    position: i32,
    columns: &[ColumnStats],
    header_boundaries: &[i32],
) -> Vec<CalcRange> {
    // `analyse_columns` emits one column per byte of the longest payload, so the
    // count is that length. Deriving it here rather than taking it as an
    // argument is the point: the two callers reached the same number by
    // different routes, which is the class of disagreement this function exists
    // to remove.
    let max_length = columns.len();

    let starts: BTreeSet<i32> = [0, 1, 2]
        .iter()
        .chain(header_boundaries.iter())
        .copied()
        .filter(|s| *s >= 0)
        .collect();

    let run = constant_run_before(position, columns);

    std::iter::once(position)
        .chain((run > 0).then(|| position - run))
        .flat_map(|calc_end_byte| {
            starts.iter().map(move |calc_start_byte| CalcRange {
                calc_start_byte: *calc_start_byte,
                calc_end_byte,
            })
        })
        // Degenerate for every frame: an end-relative range is at its widest in
        // the longest frame, so if even that one has nothing to calculate over,
        // none of them do.
        .filter(|range| {
            resolve_byte_index(range.calc_end_byte, max_length) > range.calc_start_byte as usize
        })
        .collect()
}

/// Enumerate the configurations worth testing.
///
/// Length is not a free axis — the algorithm fixes it — so the space is
/// (algorithm × position) × calcStart × calcEnd × endianness, which stays in the
/// low hundreds rather than the thousands.
pub fn build_checksum_specs(
    frames: &[Vec<u8>],
    options: &ChecksumDetectionOptions,
    columns: &[ColumnStats],
) -> Vec<ChecksumSpec> {
    // The longest frame, not the shortest. Feasibility here asks "can any frame
    // carry this configuration", because `sweep_specs` already excludes the
    // frames that individually cannot. Asking it of the shortest frame instead
    // lets one runt — a bare one-byte acknowledgement sharing the link — empty
    // the entire search space.
    let max_length = frames.iter().map(|f| f.len()).max().unwrap_or(0);

    // Ranges are per position, and every algorithm at a position shares them.
    let ranges: HashMap<i32, Vec<CalcRange>> = options
        .positions
        .iter()
        .map(|p| (*p, calc_ranges(*p, columns, &options.header_boundaries)))
        .collect();

    let mut specs = Vec::new();

    for algorithm in ALL_ALGORITHMS {
        let byte_length = algorithm.output_bytes();
        if !options.lengths.is_empty() && !options.lengths.contains(&byte_length) {
            continue;
        }
        // The checksum, plus at least one byte to calculate over, has to fit
        // inside a frame.
        if max_length < byte_length + 1 {
            continue;
        }
        // Endianness only means something for a multi-byte checksum.
        let endiannesses: &[bool] = if byte_length == 2 {
            &[false, true]
        } else {
            &[true]
        };

        for position in &options.positions {
            // The checksum must not overrun the end of the frame.
            if position
                .checked_add(byte_length as i32)
                .is_none_or(|end| end > 0)
            {
                continue;
            }

            for range in &ranges[position] {
                for big_endian in endiannesses {
                    specs.push(ChecksumSpec {
                        algorithm,
                        position: *position,
                        byte_length,
                        big_endian: *big_endian,
                        calc_start_byte: range.calc_start_byte,
                        calc_end_byte: range.calc_end_byte,
                    });
                }
            }
        }
    }

    specs
}

/// How much a candidate's score gains from the weight of evidence behind it.
///
/// Both scorers use it — the sweep here, and the solver's upstream, which ranks
/// into the same list. The tiers were written out twice, so retuning one
/// silently reweighted the other's position in a list they share.
///
/// Zero means too few samples to be worth crediting at all, which is also the
/// condition the `fewSamples` note reports.
pub fn volume_bonus(sample_count: usize) -> i32 {
    match sample_count {
        n if n >= 200 => 20,
        n if n >= 50 => 15,
        n if n >= 20 => 10,
        n if n >= 8 => 5,
        _ => 0,
    }
}

struct ScoringContext<'a> {
    columns: &'a [ColumnStats],
    header_boundaries: &'a [i32],
    frames: &'a [Vec<u8>],
}

/// The narrowest range this configuration ever actually calculates over, across
/// the frames it fits. Frames it does not fit are excluded here for the same
/// reason `sweep_specs` excludes them: they are not evidence about this spec.
fn narrowest_calc_span(spec: &ChecksumSpec, frames: &[Vec<u8>]) -> usize {
    frames
        .iter()
        .filter_map(|frame| {
            let len = frame.len();
            let start = resolve_byte_index(spec.calc_start_byte, len).min(len);
            let end = resolve_byte_index(spec.calc_end_byte, len).min(len);
            (start < end).then(|| end - start)
        })
        .min()
        .unwrap_or(0)
}

/// Score one swept configuration, or reject it.
///
/// Additive tiers plus corroboration bonuses and suspicion penalties. The
/// rejections matter as much as the score: an XOR or sum over an all-zero range
/// yields zero, which "matches" a constant 0x00 padding column perfectly and
/// would otherwise outrank the real answer.
fn score_candidate(
    spec: &ChecksumSpec,
    match_count: usize,
    total_count: usize,
    ctx: &ScoringContext,
) -> Option<ChecksumCandidate> {
    let match_rate = match_count as f64 / total_count as f64 * 100.0;
    let column = column_at(ctx.columns, spec.position);

    // A constant column is padding, not a checksum — however well it matches.
    if column.is_some_and(|c| c.padding_value().is_some()) {
        return None;
    }

    let mut notes: Vec<ChecksumNote> = Vec::new();
    let mut score: i32 = 0;

    if match_rate >= 100.0 {
        score += 55;
        notes.push(ChecksumNote::new(
            "matchesAll",
            &[("count", total_count.into())],
        ));
    } else {
        score += if match_rate >= 99.0 {
            48
        } else if match_rate >= 95.0 {
            40
        } else if match_rate >= 80.0 {
            25
        } else {
            10
        };
        notes.push(ChecksumNote::new(
            "matchesSome",
            &[
                ("matched", match_count.into()),
                ("total", total_count.into()),
            ],
        ));
    }

    let volume = volume_bonus(total_count);
    score += volume;
    if volume == 0 {
        notes.push(ChecksumNote::new(
            "fewSamples",
            &[("count", total_count.into())],
        ));
    }

    // A real checksum column varies. This is the same class of check as the
    // 0xC0-frequency test in the framing detector: cheap, structural, decisive.
    if let Some(column) = column {
        let distinct_ratio =
            column.distinct_ratio_over(if spec.byte_length == 2 { 65536 } else { 256 });
        if distinct_ratio >= 0.5 {
            score += 15;
            notes.push(ChecksumNote::new(
                "columnVaries",
                &[
                    ("distinct", column.distinct_values.into()),
                    ("samples", column.sample_count.into()),
                ],
            ));
        } else if distinct_ratio >= 0.2 {
            score += 8;
        } else if distinct_ratio < 0.05 {
            score -= 30;
            notes.push(ChecksumNote::new(
                "columnNearlyConstant",
                &[("distinct", column.distinct_values.into())],
            ));
        }
    }

    if spec.calc_end_byte == spec.position {
        score += 10;
    }

    if ctx.header_boundaries.contains(&spec.calc_start_byte) {
        score += 5;
        notes.push(ChecksumNote::new(
            "startsAfterHeader",
            &[("byte", spec.calc_start_byte.into())],
        ));
    }

    if spec.calc_end_byte < spec.position {
        if let Some(value) =
            column_at(ctx.columns, spec.calc_end_byte).and_then(|c| c.padding_value())
        {
            score += 5;
            notes.push(ChecksumNote::new(
                "constantExcluded",
                &[("value", format!("0x{value:02X}").into())],
            ));
        }
    }

    // A short calculated range is matched by chance far too easily.
    if narrowest_calc_span(spec, ctx.frames) < 2 {
        score -= 15;
        notes.push(ChecksumNote::new("shortRange", &[]));
    }

    // A 2-byte column whose high byte never moves is really a 1-byte checksum.
    if spec.byte_length == 2 {
        let high = if spec.big_endian {
            spec.position
        } else {
            spec.position + 1
        };
        if column_at(ctx.columns, high).is_some_and(|c| c.padding_value().is_some()) {
            score -= 10;
            notes.push(ChecksumNote::new("highByteConstant", &[]));
        }
    }

    Some(ChecksumCandidate {
        algorithm: spec.algorithm,
        position: spec.position,
        length: spec.byte_length,
        big_endian: spec.big_endian,
        calc_start_byte: spec.calc_start_byte,
        calc_end_byte: spec.calc_end_byte,
        match_count,
        total_count,
        match_rate,
        confidence: score.clamp(0, 100) as u8,
        notes,
        equivalent_ranges: Vec::new(),
    })
}

fn algorithm_rank(algorithm: ChecksumAlgorithm) -> usize {
    ALL_ALGORITHMS
        .iter()
        .position(|a| *a == algorithm)
        .unwrap_or(ALL_ALGORITHMS.len())
}

/// Confidence, then match rate, then parsimony: simpler explanations first.
fn compare_candidates(a: &ChecksumCandidate, b: &ChecksumCandidate) -> std::cmp::Ordering {
    b.confidence
        .cmp(&a.confidence)
        .then_with(|| b.match_rate.total_cmp(&a.match_rate))
        .then_with(|| a.length.cmp(&b.length))
        .then_with(|| a.calc_start_byte.cmp(&b.calc_start_byte))
        .then_with(|| algorithm_rank(a.algorithm).cmp(&algorithm_rank(b.algorithm)))
}

/// Rank, then fold configurations that differ only in calculation range into the
/// winner's `equivalent_ranges`.
///
/// Keying on the algorithm as well as the geometry keeps genuinely different
/// explanations visible while still collapsing the noise.
fn collapse_equivalent(mut candidates: Vec<ChecksumCandidate>) -> Vec<ChecksumCandidate> {
    candidates.sort_by(compare_candidates);

    let mut kept: Vec<ChecksumCandidate> = Vec::new();
    for candidate in candidates {
        let key = |c: &ChecksumCandidate| (c.algorithm, c.position, c.length, c.big_endian);
        match kept.iter_mut().find(|k| key(k) == key(&candidate)) {
            Some(winner) => {
                if winner.match_rate == candidate.match_rate {
                    winner.equivalent_ranges.push(CalcRange {
                        calc_start_byte: candidate.calc_start_byte,
                        calc_end_byte: candidate.calc_end_byte,
                    });
                }
            }
            None => kept.push(candidate),
        }
    }
    kept
}

/// Say why the search came up empty. A silent 0% reads as "your data is wrong";
/// naming what was looked at and what the tail actually looks like points at the
/// next thing to try.
fn explain_no_candidates(last: &ColumnStats, frame_count: usize) -> ChecksumNote {
    match last.constant_value {
        Some(value) => ChecksumNote::new(
            "noneLastByteConstant",
            &[
                ("value", format!("0x{value:02X}").into()),
                ("frames", frame_count.into()),
            ],
        ),
        None => ChecksumNote::new(
            "noneButLastByteVaries",
            &[
                ("distinct", last.distinct_values.into()),
                ("frames", frame_count.into()),
            ],
        ),
    }
}

/// Report constant tail columns as runs rather than one note each.
///
/// An all-zero frame profiles four constant columns and produced four lines
/// saying the same thing in different words. Only columns sharing a value join a
/// run — `0x00` beside `0xFF` is two facts, not one.
///
/// Scoped to `depth` because columns are now profiled to the whole payload: on
/// an all-constant frame id — which a real bus has plenty of — reporting every
/// column would turn one useful observation about the tail into eight lines
/// restating that the frame does not change.
fn constant_padding_notes(columns: &[ColumnStats]) -> Vec<ChecksumNote> {
    let padding: Vec<(i32, u8)> = columns
        .iter()
        .filter_map(|c| Some((c.position, c.padding_value()?)))
        .collect();

    let mut notes = Vec::new();
    let mut index = 0;

    while index < padding.len() {
        let (position, value) = padding[index];

        // Columns arrive -1, -2, -3…, so a run is contiguous in this order. A
        // column that failed the padding test is simply absent, which breaks
        // the run by failing this adjacency check.
        let start = index;
        while index + 1 < padding.len()
            && padding[index + 1].1 == value
            && padding[index + 1].0 == padding[index].0 - 1
        {
            index += 1;
        }

        let hex = format!("0x{value:02X}");
        notes.push(if index > start {
            ChecksumNote::new(
                "constantPaddingRun",
                &[
                    ("from", padding[index].0.into()),
                    ("to", position.into()),
                    ("value", hex.into()),
                ],
            )
        } else {
            ChecksumNote::new(
                "constantPadding",
                &[("position", position.into()), ("value", hex.into())],
            )
        });
        index += 1;
    }

    notes
}

/// Find the checksum configurations that best explain a set of frames.
pub fn detect_checksum(
    frames: &[Vec<u8>],
    options: &ChecksumDetectionOptions,
) -> ChecksumDetectionResult {
    // Strided, not a prefix: handed more than `MAX_SAMPLES` frames, taking the
    // first of them measures a rate over the start of a capture and reports it
    // as the whole. `strided_samples` owns that rule for every caller.
    let samples = strided_samples(frames, MAX_SAMPLES);
    let columns = analyse_columns(&samples);
    detect_checksum_with_columns(&samples, options, &columns)
}

/// [`detect_checksum`] for a caller that has already profiled the columns and
/// already chosen its sample.
///
/// The identification pass upstream analyses the same columns to decide what is
/// worth solving, so making it hand them over is one pass rather than two — and,
/// more importantly, means the two halves cannot reach different verdicts about
/// the same byte.
pub fn detect_checksum_with_columns(
    samples: &[Vec<u8>],
    options: &ChecksumDetectionOptions,
    columns: &[ColumnStats],
) -> ChecksumDetectionResult {
    if samples.is_empty() {
        return ChecksumDetectionResult {
            candidates: Vec::new(),
            best_candidate: None,
            tail_columns: Vec::new(),
            notes: vec![ChecksumNote::new("noFrames", &[])],
        };
    }

    let min_length = samples.iter().map(|f| f.len()).min().unwrap_or(0);
    let max_length = samples.iter().map(|f| f.len()).max().unwrap_or(0);

    // Columns are profiled to the whole payload, because the calculation ranges
    // have to see a run of padding wherever it starts. What the *result* carries
    // is the tail, which is what the field promises and what a reader wants: on
    // an all-constant frame id, every column would otherwise be listed to say
    // the frame does not change.
    let depth = options
        .positions
        .iter()
        .copied()
        .min()
        .unwrap_or(-1)
        .saturating_neg()
        .max(MIN_TAIL_DEPTH);
    let tail_columns: Vec<ColumnStats> = columns
        .iter()
        .filter(|c| c.position >= -depth)
        .cloned()
        .collect();

    let mut notes = vec![ChecksumNote::new(
        "analysed",
        &[
            ("frames", samples.len().into()),
            ("minLength", min_length.into()),
            ("maxLength", max_length.into()),
        ],
    )];
    notes.extend(constant_padding_notes(&tail_columns));

    let specs = build_checksum_specs(samples, options, columns);
    let results = sweep_specs(samples, &specs);

    notes.push(ChecksumNote::new(
        "configurationsTested",
        &[
            ("specs", specs.len().into()),
            ("algorithms", ALL_ALGORITHMS.len().into()),
        ],
    ));

    // Scoring gets every column, not the trimmed tail: the `constantExcluded`
    // bonus looks up the column at a range's end, which sits deeper than the
    // swept positions whenever padding was trimmed out of the range.
    let ctx = ScoringContext {
        columns,
        header_boundaries: &options.header_boundaries,
        frames: samples,
    };

    let scored: Vec<ChecksumCandidate> = results
        .iter()
        .filter(|r| r.match_count as f64 / r.total_count as f64 * 100.0 >= options.min_match_rate)
        .filter_map(|r| score_candidate(&specs[r.spec_index], r.match_count, r.total_count, &ctx))
        .collect();

    let mut candidates = collapse_equivalent(scored);
    candidates.retain(|c| c.confidence >= options.min_confidence);
    candidates.truncate(MAX_CANDIDATES);

    // Non-empty samples always yield a -1 column, so there is always something to
    // say about the byte a checksum would most likely occupy.
    if let (true, Some(last)) = (candidates.is_empty(), column_at(columns, -1)) {
        notes.push(explain_no_candidates(last, samples.len()));
    }

    ChecksumDetectionResult {
        best_candidate: candidates.first().cloned(),
        candidates,
        tail_columns,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        many_real_frames, modbus_frames, real_serial_frames, real_serial_frames_with_acks,
    };
    use serde_json::json;

    fn note_codes(notes: &[ChecksumNote]) -> Vec<&str> {
        notes.iter().map(|n| n.code.as_str()).collect()
    }

    // ---- The reported bug -------------------------------------------------

    #[test]
    fn test_detect_finds_sum8_over_the_real_capture() {
        // The dialog used to seed CRC-16 Modbus at -2 and report 0/20 here.
        let result = detect_checksum(&many_real_frames(), &Default::default());
        let best = result.best_candidate.expect("a candidate");

        assert_eq!(best.algorithm, ChecksumAlgorithm::Sum8);
        assert_eq!(best.position, -1);
        assert_eq!(best.length, 1);
        assert_eq!(best.calc_start_byte, 1);
        assert_eq!(best.calc_end_byte, -1);
        assert_eq!(best.match_rate, 100.0);
    }

    #[test]
    fn test_detect_finds_sum8_despite_one_byte_acknowledgements() {
        // The shortest frame on the link must not gate the search: a bare ACK
        // cannot hold a checksum, and the frames that can still deserve one.
        let frames = real_serial_frames_with_acks();
        let specs = build_checksum_specs(&frames, &Default::default(), &analyse_columns(&frames));
        assert!(!specs.is_empty(), "the ACKs emptied the search space");

        let best = detect_checksum(&frames, &Default::default())
            .best_candidate
            .expect("a candidate");
        assert_eq!(best.algorithm, ChecksumAlgorithm::Sum8);
        assert_eq!(best.position, -1);
        assert_eq!(best.calc_start_byte, 1);
        assert_eq!(best.calc_end_byte, -1);
        assert_eq!(best.match_rate, 100.0);
        // The acknowledgements are excluded from the denominator, not counted
        // as misses against a checksum they were never going to carry.
        assert_eq!(best.total_count, 72);
    }

    /// Adjacent constant columns sharing a value are one fact, not four. The
    /// fixture pads bytes -4 through -2 with zeros, so that is one note.
    #[test]
    fn test_detect_reports_constant_padding_as_a_single_run() {
        let result = detect_checksum(&many_real_frames(), &Default::default());

        let minus_two = result
            .tail_columns
            .iter()
            .find(|c| c.position == -2)
            .unwrap();
        assert_eq!(minus_two.constant_value, Some(0x00));

        let padding: Vec<&ChecksumNote> = result
            .notes
            .iter()
            .filter(|n| n.code.starts_with("constantPadding"))
            .collect();

        assert_eq!(padding.len(), 1, "{padding:?}");
        assert_eq!(padding[0].code, "constantPaddingRun");
        assert_eq!(padding[0].values["from"], json!(-4));
        assert_eq!(padding[0].values["to"], json!(-2));
    }

    /// A lone constant column still reads as one, not as a run of one.
    #[test]
    fn test_detect_reports_a_single_constant_column_without_a_range() {
        // Byte -2 is constant; -1 and -3 vary, so it cannot join a run.
        let frames: Vec<Vec<u8>> = (0..40u32)
            .map(|i| vec![0x10, (i * 7) as u8, (i * 13) as u8, 0xAA, (i * 3) as u8])
            .collect();
        let result = detect_checksum(&frames, &Default::default());

        let padding: Vec<&ChecksumNote> = result
            .notes
            .iter()
            .filter(|n| n.code.starts_with("constantPadding"))
            .collect();

        assert_eq!(padding.len(), 1, "{padding:?}");
        assert_eq!(padding[0].code, "constantPadding");
        assert_eq!(padding[0].values["position"], json!(-2));
    }

    /// Different constants are different facts, so they must not merge.
    #[test]
    fn test_detect_does_not_merge_constant_columns_of_different_values() {
        let frames: Vec<Vec<u8>> = (0..40u32)
            .map(|i| vec![0x10, (i * 7) as u8, 0xFF, 0x00, (i * 3) as u8])
            .collect();
        let result = detect_checksum(&frames, &Default::default());

        let padding: Vec<&ChecksumNote> = result
            .notes
            .iter()
            .filter(|n| n.code.starts_with("constantPadding"))
            .collect();

        assert_eq!(padding.len(), 2, "{padding:?}");
        assert!(padding.iter().all(|n| n.code == "constantPadding"));
    }

    #[test]
    fn test_detect_ranks_a_coincidental_match_below_the_real_answer() {
        // XOR over the same range reproduces one frame in five by chance, which
        // is why a raw match count is not on its own evidence.
        let result = detect_checksum(&many_real_frames(), &Default::default());
        let best = result.best_candidate.clone().unwrap();

        assert_eq!(best.algorithm, ChecksumAlgorithm::Sum8);
        for candidate in &result.candidates {
            if candidate.algorithm == ChecksumAlgorithm::Xor {
                assert!(candidate.confidence < best.confidence);
            }
        }
    }

    // ---- Priors and rejections -------------------------------------------

    #[test]
    fn test_detect_rejects_a_constant_checksum_column() {
        // Every frame ends 0x00 and the body is all zeros, so XOR and sum both
        // "match" perfectly — but the column is padding, not a checksum.
        let frames: Vec<Vec<u8>> = (0..40u8).map(|i| vec![0x01, i, 0x00, 0x00, 0x00]).collect();
        let result = detect_checksum(&frames, &Default::default());
        assert!(result.candidates.iter().all(|c| c.position != -1));
    }

    #[test]
    fn test_detect_explains_itself_when_nothing_matches() {
        let frames: Vec<Vec<u8>> = (0..40u32)
            .map(|i| vec![0x10, 0x20, i as u8, (i * 37 + 11) as u8])
            .collect();
        let result = detect_checksum(&frames, &Default::default());

        assert!(result.candidates.is_empty());
        assert!(note_codes(&result.notes).contains(&"noneButLastByteVaries"));
    }

    #[test]
    fn test_detect_says_so_when_there_are_no_frames() {
        let result = detect_checksum(&[], &Default::default());
        assert_eq!(note_codes(&result.notes), vec!["noFrames"]);
        assert!(result.best_candidate.is_none());
    }

    // ---- Candidate space --------------------------------------------------

    #[test]
    fn test_build_specs_includes_the_configuration_the_old_sweep_could_not_express() {
        let frames = real_serial_frames();
        let options = ChecksumDetectionOptions::default();
        let specs = build_checksum_specs(&frames, &options, &analyse_columns(&frames));

        assert!(specs.iter().any(|s| s.algorithm == ChecksumAlgorithm::Sum8
            && s.position == -1
            && s.calc_start_byte == 1
            && s.calc_end_byte == -1));
    }

    #[test]
    fn test_build_specs_tries_both_endiannesses_only_for_two_byte_algorithms() {
        let frames = real_serial_frames();
        let options = ChecksumDetectionOptions::default();
        let specs = build_checksum_specs(&frames, &options, &analyse_columns(&frames));

        let crc16: BTreeSet<bool> = specs
            .iter()
            .filter(|s| s.algorithm == ChecksumAlgorithm::Crc16Modbus)
            .map(|s| s.big_endian)
            .collect();
        assert_eq!(crc16, BTreeSet::from([false, true]));

        let sum8: BTreeSet<bool> = specs
            .iter()
            .filter(|s| s.algorithm == ChecksumAlgorithm::Sum8)
            .map(|s| s.big_endian)
            .collect();
        assert_eq!(sum8, BTreeSet::from([true]));
    }

    #[test]
    fn test_build_specs_widens_with_header_hints_without_narrowing() {
        let frames = real_serial_frames();
        let options = ChecksumDetectionOptions {
            header_boundaries: vec![4],
            ..Default::default()
        };
        let specs = build_checksum_specs(&frames, &options, &analyse_columns(&frames));

        assert!(specs.iter().any(|s| s.calc_start_byte == 4));
        // The real answer starts at byte 1, which is not a declared boundary —
        // hints must never replace the defaults.
        assert!(specs.iter().any(|s| s.calc_start_byte == 1));
    }

    #[test]
    fn test_build_specs_honours_a_length_restriction() {
        let frames = real_serial_frames();
        let options = ChecksumDetectionOptions {
            lengths: vec![1],
            ..Default::default()
        };
        let specs = build_checksum_specs(&frames, &options, &analyse_columns(&frames));

        assert!(!specs.is_empty());
        assert!(specs.iter().all(|s| s.byte_length == 1));
    }

    #[test]
    fn test_detect_skips_a_position_that_overflows_either_end() {
        let options = ChecksumDetectionOptions {
            positions: vec![i32::MIN, i32::MIN + 1, i32::MAX - 1, i32::MAX],
            ..Default::default()
        };
        let result = detect_checksum(&real_serial_frames(), &options);
        assert!(result.candidates.is_empty());
    }

    #[test]
    fn test_build_specs_stays_within_a_sane_search_size() {
        let frames = real_serial_frames();
        let options = ChecksumDetectionOptions::default();
        let specs = build_checksum_specs(&frames, &options, &analyse_columns(&frames));

        assert!(specs.len() > 50, "{} specs", specs.len());
        assert!(specs.len() < 400, "{} specs", specs.len());
    }

    // ---- Endianness, lengths, ranges --------------------------------------

    #[test]
    fn test_detect_distinguishes_a_little_endian_crc16() {
        // The TS sweep this replaced hardcoded big-endian, so a Modbus CRC was
        // undiscoverable on that path.
        let result = detect_checksum(&modbus_frames(), &Default::default());
        let best = result.best_candidate.expect("a candidate");

        assert_eq!(best.algorithm, ChecksumAlgorithm::Crc16Modbus);
        assert!(!best.big_endian);
        assert_eq!(best.position, -2);
        assert_eq!(best.length, 2);
        assert_eq!(best.match_rate, 100.0);
    }

    #[test]
    fn test_detect_keeps_an_equally_scoring_range_as_an_alternative() {
        // [1:-1] and [1:-2] both reproduce the frames, since byte -2 is zero.
        let result = detect_checksum(&many_real_frames(), &Default::default());
        let best = result.best_candidate.unwrap();

        assert_eq!(best.calc_end_byte, -1);
        assert!(!best.equivalent_ranges.is_empty());
    }

    #[test]
    fn test_detect_resolves_positions_across_mixed_frame_lengths() {
        // The fixture mixes 16- and 20-byte frames, so a candidate matching every
        // one of them proves the position resolved per frame, not per capture.
        let frames = many_real_frames();
        assert_eq!(frames.iter().map(|f| f.len()).min(), Some(16));
        assert_eq!(frames.iter().map(|f| f.len()).max(), Some(20));

        let result = detect_checksum(&frames, &Default::default());
        assert_eq!(result.best_candidate.unwrap().total_count, frames.len());
    }

    #[test]
    fn test_detect_caps_the_sample() {
        // 600 frames in, MAX_SAMPLES out — the dialog reads the same number from
        // the capture so both halves measure against one set.
        let many: Vec<Vec<u8>> = real_serial_frames().into_iter().cycle().take(600).collect();
        let result = detect_checksum(&many, &Default::default());
        assert_eq!(result.best_candidate.unwrap().total_count, MAX_SAMPLES);
    }
}
