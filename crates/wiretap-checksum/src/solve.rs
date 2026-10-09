//! Solving a checksum rather than searching for one.
//!
//! [`detect`](crate::detect) sweeps a fixed space of eleven named algorithms.
//! That answers "is it one of the usual ones", and most of the time it is. This
//! module answers the harder question — *what is it* — for the two families
//! where the answer can be computed instead of guessed.
//!
//! # Additive checksums are solved in one pass
//!
//! If a checksum is `sum(range) + k`, then `observed − sum(range)` is `k` for
//! every sample. Compute that residue once per sample and see whether it moves.
//! No search, no candidate list, and it finds the offset variants
//! (`sum + C`, two's complement) that a fixed algorithm list cannot express.
//!
//! # CRC `init` and `xorOut` are not search axes — they cancel
//!
//! A CRC register is affine in its initial value: after `L` bytes,
//!
//! ```text
//! R(init, m) = R(0, m) ⊕ T^{8L}(init)
//! CRC(m)     = R(init, m) ⊕ xorOut
//! ```
//!
//! so for messages of **equal length** the `init` and `xorOut` terms are one
//! constant. Define the residue
//!
//! ```text
//! K = observed ⊕ CRC(m, init = 0, xorOut = 0)
//! ```
//!
//! and a polynomial is correct exactly when `K` is the same for every sample.
//! The search collapses from `poly × init × xorOut × reflect` to
//! `poly × reflect`: 510 tests for CRC-8 and 262,140 for CRC-16, against the
//! 4,080 and 4,194,240 configurations an enumeration over `init`/`xorOut` costs.
//! Most polynomials disagree on the first pair of samples, so in practice it is
//! one CRC each.
//!
//! `(init = 0, xorOut = K)` always reproduces the data exactly, and is what this
//! module reports. It is not, however, the *only* pair that does: for
//! fixed-length payloads `init` and `xorOut` are not separately identifiable, so
//! [`CrcParameters::alternatives`] carries the conventional inits and the
//! `xorOut` each would imply. A caller must not present one of them as the
//! answer. Recovering a unique pair needs samples of two different lengths,
//! which CAN — one DLC per frame id — does not provide.

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::algorithms::{
    calculate_checksum_simple, crc16_parameterised, crc8_parameterised, ChecksumAlgorithm,
    ALL_ALGORITHMS,
};
use crate::detect::CalcRange;
use crate::frame::{calculated_range, extract_checksum};

/// Well-known polynomials, preferred when several reproduce the data equally
/// well. Recognising a standard is worth more to a reader than an arbitrary
/// value that happens to fit.
const KNOWN_CRC8_POLYNOMIALS: [u16; 7] = [0x07, 0x1D, 0x2F, 0x31, 0x9B, 0xD5, 0x85];

const KNOWN_CRC16_POLYNOMIALS: [u16; 8] = [
    0x8005, 0x1021, 0x3D65, 0x8BB7, 0xC867, 0x0589, 0x080D, 0x1DCF,
];

/// The id a recovered CRC is stored under. It is not one of the eleven — its
/// parameters travel with the declaration.
pub const CRC_CUSTOM: &str = "crc_custom";

/// The id for a sum negated into two's complement, likewise unnameable by the
/// fixed list.
pub const SUM8_NEGATED: &str = "sum8_negated";

/// Every algorithm id a stored checksum may use: the eleven named ones plus the
/// two parameterised shapes the solver recovers.
pub fn all_algorithm_ids() -> Vec<&'static str> {
    ALL_ALGORITHMS
        .iter()
        .map(|a| a.as_str())
        .chain([CRC_CUSTOM, SUM8_NEGATED])
        .collect()
}

/// One stored algorithm id and how many bytes its checksum occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmWidth {
    pub id: &'static str,
    /// `None` for the two parameterised ids, [`CRC_CUSTOM`] and [`SUM8_NEGATED`],
    /// whose declaration carries its own `byte_length`.
    pub output_bytes: Option<usize>,
}

/// [`all_algorithm_ids`], in the same order, each with its fixed width.
pub fn algorithm_widths() -> Vec<AlgorithmWidth> {
    all_algorithm_ids()
        .into_iter()
        .map(|id| AlgorithmWidth {
            id,
            output_bytes: id
                .parse::<ChecksumAlgorithm>()
                .ok()
                .map(|a| a.output_bytes()),
        })
        .collect()
}

/// Conventional initial values reported as alternatives.
const CONVENTIONAL_INITS: [u16; 2] = [0x0000, 0xFFFF];

/// Samples needed before a solution means anything. Two payloads agree on a
/// residue far too easily.
const MIN_SAMPLES: usize = 3;

/// How many samples the screening pass uses before a full verification.
const SCREEN_SAMPLES: usize = 3;

/// Where the checksum sits and what it is calculated over. The geometry is the
/// caller's to decide — [`crate::detect`] or the identification pass upstream —
/// and this module only answers "what algorithm fits *here*".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SolveTarget {
    /// Byte offset of the checksum; negative counts from the end.
    pub position: i32,
    pub byte_length: usize,
    pub big_endian: bool,
    pub calc_start_byte: i32,
    pub calc_end_byte: i32,
}

/// The additive families, in the order they are tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdditiveOp {
    /// `observed = XOR(range) ⊕ offset`
    Xor,
    /// `observed = SUM(range) + offset`
    Sum,
    /// `observed = offset − SUM(range)` — the two's-complement shape.
    NegatedSum,
}

/// One conventional `init` and the `xorOut` it implies for this residue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrcAlternative {
    pub init: u16,
    pub xor_out: u16,
}

/// A recovered CRC. `init`/`xor_out` are the canonical pair — always exact, and
/// always one of several that fit; see [`alternatives`](Self::alternatives).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrcParameters {
    /// 8 or 16.
    pub width: u8,
    pub polynomial: u16,
    pub reflect_in: bool,
    pub reflect_out: bool,
    /// Canonically 0. Retained so a caller can write a complete CRC definition.
    pub init: u16,
    /// The residue `observed ⊕ CRC(m, 0, 0)`, constant across the samples.
    pub xor_out: u16,
    /// True when `polynomial` is a recognised standard.
    pub well_known: bool,
    /// Other `(init, xorOut)` pairs that reproduce the samples identically.
    /// Non-empty means `init` is not determined by this data.
    pub alternatives: Vec<CrcAlternative>,
}

/// How a checksum is computed.
///
/// One type for all three answers the engine can give: a named algorithm from
/// the scored sweep, or one of the two families [`solve_additive`] and
/// [`solve_crc`] recover, which carry parameters no fixed list can express.
/// They were declared separately either side of the crate boundary and sorted
/// against each other in one list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum ChecksumSpecification {
    Named { algorithm: ChecksumAlgorithm },
    Additive { op: AdditiveOp, offset: u8 },
    Crc(CrcParameters),
}

/// A specification's identity ignoring what a calculation range absorbs.
///
/// A constant range contributes a constant, which a sum takes into its offset
/// and a CRC into its `init`/`xorOut` residue. So two solutions of the same
/// family over different ranges differ in exactly those fields and agree on
/// everything else — and comparing them is the whole basis of the fold.
///
/// Deriving this from an exhaustive match, rather than hand-listing fields at
/// the point of comparison, is what stops a new checksum family from compiling
/// cleanly and silently never folding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ChecksumFamily {
    Named(ChecksumAlgorithm),
    Additive(AdditiveOp),
    /// Width, polynomial and the two reflections. `init` and `xor_out` are the
    /// residue, and the residue moves with the range.
    Crc {
        width: u8,
        polynomial: u16,
        reflect_in: bool,
        reflect_out: bool,
    },
}

impl ChecksumSpecification {
    pub(crate) fn family(&self) -> ChecksumFamily {
        match self {
            Self::Named { algorithm } => ChecksumFamily::Named(*algorithm),
            Self::Additive { op, .. } => ChecksumFamily::Additive(*op),
            Self::Crc(crc) => ChecksumFamily::Crc {
                width: crc.width,
                polynomial: crc.polynomial,
                reflect_in: crc.reflect_in,
                reflect_out: crc.reflect_out,
            },
        }
    }
}

impl ChecksumSpecification {
    /// The catalogue id this serialises as.
    ///
    /// Exhaustive, and beside the type it names, so a new family cannot be
    /// added without deciding what it is called. The ids used to be spelled by
    /// hand wherever one was written or read.
    pub fn algorithm_id(&self) -> &'static str {
        match self {
            Self::Named { algorithm } => algorithm.as_str(),
            Self::Additive { op, .. } => match op {
                AdditiveOp::Xor => ChecksumAlgorithm::Xor.as_str(),
                AdditiveOp::Sum => ChecksumAlgorithm::Sum8.as_str(),
                AdditiveOp::NegatedSum => SUM8_NEGATED,
            },
            Self::Crc(_) => CRC_CUSTOM,
        }
    }

    /// Apply this configuration to the bytes it is calculated over.
    ///
    /// The counterpart to solving: [`solve_additive`] and [`solve_crc`] work out
    /// *what* a checksum is, and this reproduces it. Without it a caller holding
    /// a stored configuration has no way to check it except by parsing the
    /// algorithm id and hoping the parameters beside it do not matter — which
    /// silently mis-reads every offset sum, because those are stored as `sum8`.
    pub fn calculate(&self, data: &[u8]) -> u16 {
        match self {
            Self::Named { algorithm } => calculate_checksum_simple(*algorithm, data),
            Self::Additive { op, offset } => {
                let value = match op {
                    AdditiveOp::Xor => data.iter().fold(0u8, |a, b| a ^ b) ^ *offset,
                    AdditiveOp::Sum => data
                        .iter()
                        .fold(0u8, |a, b| a.wrapping_add(*b))
                        .wrapping_add(*offset),
                    AdditiveOp::NegatedSum => {
                        offset.wrapping_sub(data.iter().fold(0u8, |a, b| a.wrapping_add(*b)))
                    }
                };
                value as u16
            }
            Self::Crc(crc) => {
                if crc.width == 8 {
                    crc8_parameterised(
                        data,
                        crc.polynomial as u8,
                        crc.init as u8,
                        crc.xor_out as u8,
                        crc.reflect_in,
                    ) as u16
                } else {
                    crc16_parameterised(
                        data,
                        crc.polynomial,
                        crc.init,
                        crc.xor_out,
                        crc.reflect_in,
                        crc.reflect_out,
                    )
                }
            }
        }
    }

    /// Whether the scored sweep of named algorithms can already express this.
    ///
    /// A plain XOR or Sum with no offset *is* one of the eleven, so reporting it
    /// as a solved answer duplicates a candidate the sweep already scored with a
    /// measured rate. Only the variants the fixed list cannot express are news.
    ///
    /// It lives here, matched exhaustively, because it is a claim about what
    /// [`ChecksumAlgorithm`] covers — a caller asserting it from outside goes
    /// silently wrong the day a `Sum16` joins the list.
    pub fn is_expressible_by_sweep(&self) -> bool {
        match self {
            Self::Named { .. } => true,
            Self::Additive { op, offset } => {
                *offset == 0 && matches!(op, AdditiveOp::Xor | AdditiveOp::Sum)
            }
            Self::Crc(_) => false,
        }
    }
}

/// A configuration that reproduces every sample it was solved against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SolvedChecksum {
    pub target: SolveTarget,
    #[serde(flatten)]
    pub specification: ChecksumSpecification,
    /// Samples the solution was verified against. A solution is only reported
    /// when it reproduces all of them, so there is no match *rate* here.
    pub sample_count: usize,
    /// Samples excluded because their calculation range was a different length.
    /// Always 0 for the additive solutions.
    pub excluded_count: usize,
    /// Ranges that explain the samples equally well, folded in by
    /// `collapse_solved`. Non-empty means the bytes between them never
    /// changed, so the data cannot say which is right.
    pub equivalent_ranges: Vec<CalcRange>,
}

#[derive(Debug, Clone)]
pub struct CrcSolveOptions {
    /// Test only the recognised standards. Rarely worth setting — an exhaustive
    /// sweep is milliseconds — but it makes a scan over many frame ids cheaper.
    pub known_polynomials_only: bool,
    /// Cap on returned solutions. Several polynomials can fit a thin sample.
    pub max_solutions: usize,
}

impl Default for CrcSolveOptions {
    fn default() -> Self {
        Self {
            known_polynomials_only: false,
            max_solutions: 8,
        }
    }
}

/// One sample reduced to what a solver needs: the bytes covered by the
/// calculation range, and the checksum value stored alongside them.
struct Observation {
    data: Vec<u8>,
    observed: u16,
}

fn observations(frames: &[Vec<u8>], target: &SolveTarget) -> Vec<Observation> {
    frames
        .iter()
        .filter_map(|frame| {
            let range = calculated_range(
                frame.len(),
                target.position,
                target.byte_length,
                target.calc_start_byte,
                target.calc_end_byte,
            )?;
            Some(Observation {
                data: frame[range].to_vec(),
                observed: extract_checksum(
                    frame,
                    target.position,
                    target.byte_length,
                    target.big_endian,
                )?,
            })
        })
        .collect()
}

/// Find the additive or XOR checksum that fits, if one does.
///
/// One pass per family, no search: the offset is whatever the first sample
/// implies, and the remaining samples either agree or rule the family out.
pub fn solve_additive(frames: &[Vec<u8>], target: &SolveTarget) -> Option<SolvedChecksum> {
    if target.byte_length != 1 {
        return None;
    }

    let samples = observations(frames, target);
    if samples.len() < MIN_SAMPLES {
        return None;
    }

    let residue = |op: AdditiveOp, sample: &Observation| -> u8 {
        let observed = sample.observed as u8;
        match op {
            AdditiveOp::Xor => observed ^ sample.data.iter().fold(0u8, |a, b| a ^ b),
            AdditiveOp::Sum => {
                observed.wrapping_sub(sample.data.iter().fold(0u8, |a, b| a.wrapping_add(*b)))
            }
            AdditiveOp::NegatedSum => {
                observed.wrapping_add(sample.data.iter().fold(0u8, |a, b| a.wrapping_add(*b)))
            }
        }
    };

    [AdditiveOp::Xor, AdditiveOp::Sum, AdditiveOp::NegatedSum]
        .into_iter()
        .find_map(|op| {
            let offset = residue(op, &samples[0]);
            samples[1..]
                .iter()
                .all(|s| residue(op, s) == offset)
                .then_some(SolvedChecksum {
                    target: *target,
                    specification: ChecksumSpecification::Additive { op, offset },
                    sample_count: samples.len(),
                    excluded_count: 0,
                    equivalent_ranges: Vec::new(),
                })
        })
}

/// `CRC(data, init = 0, xorOut = 0)` — the linear part, which is all the
/// residue test needs.
fn crc_zeroed(data: &[u8], width: u8, polynomial: u16, reflect_in: bool, reflect_out: bool) -> u16 {
    if width == 8 {
        crc8_parameterised(data, polynomial as u8, 0, 0, reflect_in) as u16
    } else {
        crc16_parameterised(data, polynomial, 0, 0, reflect_in, reflect_out)
    }
}

/// The reflection combinations worth testing. CRC-8 couples input and output
/// reflection — that is the convention every named CRC-8 follows — so it has two
/// cases where CRC-16 has four.
fn reflection_combinations(width: u8) -> Vec<(bool, bool)> {
    if width == 8 {
        vec![(false, false), (true, true)]
    } else {
        vec![(false, false), (true, true), (true, false), (false, true)]
    }
}

/// The residue shared by every sample, or `None` if the polynomial is wrong.
fn shared_residue(
    samples: &[&Observation],
    width: u8,
    polynomial: u16,
    reflect_in: bool,
    reflect_out: bool,
) -> Option<u16> {
    let mut residue = None;
    for sample in samples {
        let k =
            sample.observed ^ crc_zeroed(&sample.data, width, polynomial, reflect_in, reflect_out);
        match residue {
            None => residue = Some(k),
            Some(existing) if existing == k => {}
            Some(_) => return None,
        }
    }
    residue
}

/// Recover the polynomial of a CRC by residue agreement.
///
/// Only samples whose calculation range is the same length take part — the
/// residue is length-dependent, so mixing lengths would compare incomparable
/// values. The largest such group is used and the rest are reported as
/// `excluded_count`.
pub fn solve_crc(
    frames: &[Vec<u8>],
    target: &SolveTarget,
    options: &CrcSolveOptions,
) -> Vec<SolvedChecksum> {
    let width = match target.byte_length {
        1 => 8u8,
        2 => 16u8,
        _ => return Vec::new(),
    };

    let all = observations(frames, target);
    let Some(length) = largest_length_group(&all) else {
        return Vec::new();
    };
    let samples: Vec<&Observation> = all.iter().filter(|s| s.data.len() == length).collect();
    if samples.len() < MIN_SAMPLES {
        return Vec::new();
    }

    let known: &[u16] = if width == 8 {
        &KNOWN_CRC8_POLYNOMIALS
    } else {
        &KNOWN_CRC16_POLYNOMIALS
    };
    let polynomials: Vec<u16> = if options.known_polynomials_only {
        known.to_vec()
    } else {
        let last = if width == 8 { 0xFF } else { 0xFFFF };
        (1..=last).collect()
    };

    // Screening first: a wrong polynomial disagrees on the second sample with
    // probability 1 − 2⁻ʷ, so nearly every candidate dies after one CRC.
    let screen = &samples[..samples.len().min(SCREEN_SAMPLES)];
    let samples = &samples[..];

    let mut solutions: Vec<CrcParameters> = polynomials
        .par_iter()
        .flat_map_iter(|polynomial| {
            let polynomial = *polynomial;
            reflection_combinations(width)
                .into_iter()
                .filter_map(move |(reflect_in, reflect_out)| {
                    shared_residue(screen, width, polynomial, reflect_in, reflect_out)?;
                    let residue =
                        shared_residue(samples, width, polynomial, reflect_in, reflect_out)?;
                    Some(CrcParameters {
                        width,
                        polynomial,
                        reflect_in,
                        reflect_out,
                        init: 0,
                        xor_out: residue,
                        well_known: known.contains(&polynomial),
                        alternatives: conventional_alternatives(
                            width,
                            polynomial,
                            reflect_in,
                            reflect_out,
                            length,
                            residue,
                        ),
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect();

    // A recognised standard beats an arbitrary value that fits equally well;
    // otherwise the lower polynomial, so the ordering is stable run to run.
    solutions.sort_by_key(|s| (!s.well_known, s.polynomial, s.reflect_in, s.reflect_out));
    solutions.truncate(options.max_solutions);

    solutions
        .into_iter()
        .map(|crc| SolvedChecksum {
            target: *target,
            specification: ChecksumSpecification::Crc(crc),
            sample_count: samples.len(),
            excluded_count: all.len() - samples.len(),
            equivalent_ranges: Vec::new(),
        })
        .collect()
}

/// Solve every target, and fold the duplicates the range space produces.
///
/// The entry point a caller should use. [`crate::calc_ranges`] deliberately
/// offers the solver every range the sweep searches, and wherever the bytes
/// between two of those ranges never change, *both* solve — with a different
/// offset or residue each. Those are one answer written several ways, and
/// reporting them as several would make the wider search read as noise.
///
/// Folding here rather than in the caller is the point: the crate produces the
/// duplicates, so the crate clears them up. Leaving it to a doc comment is how
/// a second consumer ends up without it.
pub fn solve_all(
    frames: &[Vec<u8>],
    targets: &[SolveTarget],
    options: &CrcSolveOptions,
) -> Vec<SolvedChecksum> {
    let solutions = targets
        .iter()
        .flat_map(|target| {
            solve_additive(frames, target)
                .into_iter()
                .chain(solve_crc(frames, target, options))
        })
        .collect();
    collapse_solved(solutions)
}

/// Fold solutions that differ only in a range the data cannot tell apart.
///
/// The widest range wins — lowest start, end furthest into the frame — and the
/// rest become its `equivalent_ranges`. When only one range solves, the excluded
/// bytes *did* move, and that single answer is the real one.
fn collapse_solved(mut solutions: Vec<SolvedChecksum>) -> Vec<SolvedChecksum> {
    // Widest first, so the survivor of each group is the parsimonious one.
    solutions.sort_by(|a, b| {
        a.target
            .calc_start_byte
            .cmp(&b.target.calc_start_byte)
            .then_with(|| b.target.calc_end_byte.cmp(&a.target.calc_end_byte))
    });

    let mut kept: Vec<SolvedChecksum> = Vec::new();
    for solution in solutions {
        let same = |k: &SolvedChecksum| {
            k.target.position == solution.target.position
                && k.target.byte_length == solution.target.byte_length
                && k.target.big_endian == solution.target.big_endian
                && k.specification.family() == solution.specification.family()
        };
        match kept.iter_mut().find(|k| same(k)) {
            Some(winner) => winner.equivalent_ranges.push(CalcRange {
                calc_start_byte: solution.target.calc_start_byte,
                calc_end_byte: solution.target.calc_end_byte,
            }),
            None => kept.push(solution),
        }
    }
    kept
}

fn largest_length_group(samples: &[Observation]) -> Option<usize> {
    let mut counts: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    for sample in samples {
        *counts.entry(sample.data.len()).or_default() += 1;
    }
    // Ties break to the longer range: more bytes under the checksum is the
    // stronger evidence.
    counts
        .into_iter()
        .max_by_key(|(length, count)| (*count, *length))
        .map(|(length, _)| length)
}

/// `xorOut` for each conventional `init`, given the residue.
///
/// `K = CRC(zeros_L, init, 0) ⊕ xorOut`, so `xorOut = K ⊕ CRC(zeros_L, init, 0)`
/// — the zero message isolates the `init` term.
fn conventional_alternatives(
    width: u8,
    polynomial: u16,
    reflect_in: bool,
    reflect_out: bool,
    length: usize,
    residue: u16,
) -> Vec<CrcAlternative> {
    let zeros = vec![0u8; length];
    let mask = if width == 8 { 0x00FF } else { 0xFFFF };

    CONVENTIONAL_INITS
        .iter()
        .map(|init| init & mask)
        .filter(|init| *init != 0)
        .map(|init| {
            let carried = if width == 8 {
                crc8_parameterised(&zeros, polynomial as u8, init as u8, 0, reflect_in) as u16
            } else {
                crc16_parameterised(&zeros, polynomial, init, 0, reflect_in, reflect_out)
            };
            CrcAlternative {
                init,
                xor_out: residue ^ carried,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::{crc16_modbus_checksum, crc8_checksum, sum8_checksum, xor_checksum};

    /// A checksum at the last byte, calculated over everything before it.
    const TRAILING_BYTE: SolveTarget = SolveTarget {
        position: -1,
        byte_length: 1,
        big_endian: true,
        calc_start_byte: 0,
        calc_end_byte: -1,
    };

    const TRAILING_WORD: SolveTarget = SolveTarget {
        position: -2,
        byte_length: 2,
        big_endian: false,
        calc_start_byte: 0,
        calc_end_byte: -2,
    };

    /// Payloads with a checksum appended by `f`. Deliberately varied so a wrong
    /// candidate has somewhere to disagree.
    fn frames_with<F: Fn(&[u8]) -> u8>(count: u32, f: F) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| {
                let mut body = vec![
                    0x10,
                    i as u8,
                    (i >> 8) as u8,
                    (i.wrapping_mul(37) ^ 0x5A) as u8,
                    (i.wrapping_mul(211)) as u8,
                    0xC3,
                    (i.wrapping_mul(7) ^ 0xF0) as u8,
                ];
                let checksum = f(&body);
                body.push(checksum);
                body
            })
            .collect()
    }

    /// The one CRC a solve is expected to find. Panics on an empty result so a
    /// failure reads as "found nothing" rather than an index panic.
    fn only_crc(solved: &[SolvedChecksum]) -> CrcParameters {
        match solved.first().map(|s| &s.specification) {
            Some(ChecksumSpecification::Crc(crc)) => crc.clone(),
            other => panic!("expected a CRC, got {other:?}"),
        }
    }

    // ---- Additive: solved, not searched -----------------------------------

    #[test]
    fn test_solve_additive_finds_a_plain_sum() {
        let solved = solve_additive(&frames_with(40, sum8_checksum), &TRAILING_BYTE).unwrap();
        assert_eq!(
            solved.specification,
            ChecksumSpecification::Additive {
                op: AdditiveOp::Sum,
                offset: 0
            }
        );
        assert_eq!(solved.sample_count, 40);
    }

    #[test]
    fn test_solve_additive_finds_a_plain_xor() {
        let solved = solve_additive(&frames_with(40, xor_checksum), &TRAILING_BYTE).unwrap();
        assert_eq!(
            solved.specification,
            ChecksumSpecification::Additive {
                op: AdditiveOp::Xor,
                offset: 0
            }
        );
    }

    /// The variant the fixed eleven-algorithm list cannot express, and the
    /// reason this is a solve rather than a sweep.
    #[test]
    fn test_solve_additive_finds_a_sum_with_a_constant_offset() {
        let frames = frames_with(40, |d| sum8_checksum(d).wrapping_add(0xA5));
        let solved = solve_additive(&frames, &TRAILING_BYTE).unwrap();
        assert_eq!(
            solved.specification,
            ChecksumSpecification::Additive {
                op: AdditiveOp::Sum,
                offset: 0xA5
            }
        );
    }

    #[test]
    fn test_solve_additive_finds_a_twos_complement_sum() {
        let frames = frames_with(40, |d| sum8_checksum(d).wrapping_neg());
        let solved = solve_additive(&frames, &TRAILING_BYTE).unwrap();
        assert_eq!(
            solved.specification,
            ChecksumSpecification::Additive {
                op: AdditiveOp::NegatedSum,
                offset: 0
            }
        );
    }

    #[test]
    fn test_solve_additive_rejects_a_crc() {
        assert!(solve_additive(&frames_with(40, crc8_checksum), &TRAILING_BYTE).is_none());
    }

    #[test]
    fn test_solve_additive_needs_more_than_a_couple_of_samples() {
        assert!(solve_additive(&frames_with(2, sum8_checksum), &TRAILING_BYTE).is_none());
    }

    // ---- CRC: the residue collapses init and xorOut -----------------------

    #[test]
    fn test_solve_crc_recovers_a_named_crc8() {
        let crc = only_crc(&solve_crc(
            &frames_with(40, crc8_checksum),
            &TRAILING_BYTE,
            &Default::default(),
        ));

        assert_eq!(crc.polynomial, 0x07);
        assert!(!crc.reflect_in);
        assert!(crc.well_known);
        // init 0, xorOut 0 for this one, so the residue is 0.
        assert_eq!(crc.xor_out, 0x0000);
    }

    /// The point of the whole exercise: a polynomial nobody catalogued, with a
    /// non-zero init and xorOut, recovered without enumerating either.
    #[test]
    fn test_solve_crc_recovers_an_arbitrary_polynomial() {
        let frames = frames_with(60, |d| crc8_parameterised(d, 0x4D, 0xB7, 0x2C, false));
        let crc = only_crc(&solve_crc(&frames, &TRAILING_BYTE, &Default::default()));
        assert_eq!(crc.polynomial, 0x4D);
        assert!(!crc.well_known);

        // The canonical form must reproduce the capture exactly.
        for frame in &frames {
            let body = &frame[..frame.len() - 1];
            let reproduced = crc8_parameterised(
                body,
                crc.polynomial as u8,
                crc.init as u8,
                crc.xor_out as u8,
                crc.reflect_in,
            );
            assert_eq!(reproduced, *frame.last().unwrap());
        }
    }

    #[test]
    fn test_solve_crc_recovers_a_reflected_polynomial() {
        let frames = frames_with(60, |d| crc8_parameterised(d, 0x31, 0x00, 0x00, true));
        let crc = only_crc(&solve_crc(&frames, &TRAILING_BYTE, &Default::default()));

        assert_eq!(crc.polynomial, 0x31);
        assert!(crc.reflect_in);
    }

    #[test]
    fn test_solve_crc_recovers_a_16_bit_polynomial() {
        let frames: Vec<Vec<u8>> = (0..60u32)
            .map(|i| {
                let mut body = vec![
                    0x02,
                    i as u8,
                    (i >> 8) as u8,
                    (i.wrapping_mul(97)) as u8,
                    0x11,
                ];
                let crc = crc16_modbus_checksum(&body);
                body.push((crc & 0xFF) as u8);
                body.push((crc >> 8) as u8);
                body
            })
            .collect();

        let crc = only_crc(&solve_crc(&frames, &TRAILING_WORD, &Default::default()));
        assert_eq!(crc.polynomial, 0x8005);
        assert!(crc.reflect_in);
        assert!(crc.well_known);
    }

    /// `init` and `xorOut` are not separately identifiable from fixed-length
    /// payloads, and the result has to say so rather than pick one.
    #[test]
    fn test_solve_crc_offers_the_conventional_inits_as_alternatives() {
        let frames = frames_with(40, |d| crc8_parameterised(d, 0x1D, 0xFF, 0xFF, false));
        let crc = only_crc(&solve_crc(&frames, &TRAILING_BYTE, &Default::default()));

        assert_eq!(crc.polynomial, 0x1D);
        assert_eq!(crc.init, 0);

        let alternative = crc.alternatives.iter().find(|a| a.init == 0xFF).unwrap();
        // Both pairs must reproduce the capture; neither is more true.
        for frame in &frames {
            let body = &frame[..frame.len() - 1];
            assert_eq!(
                crc8_parameterised(body, 0x1D, 0x00, crc.xor_out as u8, false),
                *frame.last().unwrap()
            );
            assert_eq!(
                crc8_parameterised(body, 0x1D, 0xFF, alternative.xor_out as u8, false),
                *frame.last().unwrap()
            );
        }
    }

    #[test]
    fn test_solve_crc_finds_nothing_in_noise() {
        let frames: Vec<Vec<u8>> = (0..60u32)
            .map(|i| {
                vec![
                    0x10,
                    i as u8,
                    (i.wrapping_mul(37)) as u8,
                    (i.wrapping_mul(91) ^ 0x3C) as u8,
                ]
            })
            .collect();

        assert!(solve_crc(&frames, &TRAILING_BYTE, &Default::default()).is_empty());
    }

    #[test]
    fn test_solve_crc_excludes_samples_of_a_different_range_length() {
        let mut frames = frames_with(40, crc8_checksum);
        // A short frame on the same link: a different calculation length, so a
        // different residue, so not evidence about this one.
        frames.push(vec![0x10, 0x20, 0x30]);

        let solved = solve_crc(&frames, &TRAILING_BYTE, &Default::default());
        assert_eq!(solved[0].sample_count, 40);
        assert_eq!(solved[0].excluded_count, 1);
        assert_eq!(only_crc(&solved).polynomial, 0x07);
    }

    #[test]
    fn test_solve_crc_honours_the_known_only_option() {
        let frames = frames_with(60, |d| crc8_parameterised(d, 0x4D, 0xB7, 0x2C, false));
        let options = CrcSolveOptions {
            known_polynomials_only: true,
            ..Default::default()
        };

        assert!(solve_crc(&frames, &TRAILING_BYTE, &options).is_empty());
        assert!(!solve_crc(&frames, &TRAILING_BYTE, &Default::default()).is_empty());
    }

    /// A constant prefix cancels in the residue just as `init` does, so the
    /// frame id being inside or outside the calculation changes the residue but
    /// never the polynomial.
    #[test]
    fn test_solve_crc_is_indifferent_to_a_constant_prefix() {
        let frames = frames_with(40, crc8_checksum);
        let prefixed: Vec<Vec<u8>> = frames
            .iter()
            .map(|f| [&[0x07u8, 0x01][..], f].concat())
            .collect();

        let bare = only_crc(&solve_crc(&frames, &TRAILING_BYTE, &Default::default())).polynomial;
        let with_prefix =
            only_crc(&solve_crc(&prefixed, &TRAILING_BYTE, &Default::default())).polynomial;

        assert_eq!(bare, with_prefix);
    }

    // ---- Folding what the range space duplicates ---------------------------

    /// Every start solves when the bytes they differ by never change, because a
    /// constant range is absorbed — into the offset here. One answer, and it
    /// must come back as one.
    #[test]
    fn test_solve_all_folds_ranges_the_data_cannot_tell_apart() {
        // Bytes 0 and 1 are constant, so starts 0, 1 and 2 all reproduce the
        // frames with a different offset each.
        let frames: Vec<Vec<u8>> = (0..40u32)
            .map(|i| {
                let mut body = vec![0x10, 0x20, i as u8, (i.wrapping_mul(37) ^ 0x5A) as u8];
                body.push(sum8_checksum(&body).wrapping_add(0xA5));
                body
            })
            .collect();

        let targets: Vec<SolveTarget> = [0, 1, 2]
            .iter()
            .map(|start| SolveTarget {
                calc_start_byte: *start,
                ..TRAILING_BYTE
            })
            .collect();

        let solved = solve_all(&frames, &targets, &Default::default());
        assert_eq!(
            solved.len(),
            1,
            "one answer, {} ways: {solved:?}",
            solved.len()
        );
        // The widest range wins; the others are kept rather than dropped,
        // because none of them is more true than another.
        assert_eq!(solved[0].target.calc_start_byte, 0);
        assert_eq!(
            solved[0].specification,
            ChecksumSpecification::Additive {
                op: AdditiveOp::Sum,
                offset: 0xA5
            }
        );
        let starts: Vec<i32> = solved[0]
            .equivalent_ranges
            .iter()
            .map(|r| r.calc_start_byte)
            .collect();
        assert_eq!(starts, vec![1, 2]);
    }

    /// The other direction, and the reason the wider range space exists: a
    /// leading byte that *moves* is not absorbed, so only the range excluding it
    /// solves and there is nothing to be ambiguous about.
    #[test]
    fn test_solve_all_keeps_the_one_range_that_fits_when_the_prefix_moves() {
        let frames: Vec<Vec<u8>> = (0..40u32)
            .map(|i| {
                let mut body = vec![(i % 7) as u8, i as u8, (i.wrapping_mul(37) ^ 0x5A) as u8];
                body.push(sum8_checksum(&body[1..]));
                body
            })
            .collect();

        let targets: Vec<SolveTarget> = [0, 1, 2]
            .iter()
            .map(|start| SolveTarget {
                calc_start_byte: *start,
                ..TRAILING_BYTE
            })
            .collect();

        let solved = solve_all(&frames, &targets, &Default::default());
        assert_eq!(solved.len(), 1, "{solved:?}");
        assert_eq!(solved[0].target.calc_start_byte, 1);
        assert!(solved[0].equivalent_ranges.is_empty());
    }

    /// Two genuinely different explanations must stay two. `family()` keys the
    /// fold, so a different polynomial is a different answer however similar the
    /// geometry.
    #[test]
    fn test_collapse_keeps_different_families_apart() {
        let frames = frames_with(40, crc8_checksum);
        let solved = solve_all(&frames, &[TRAILING_BYTE], &Default::default());
        let families: std::collections::HashSet<_> =
            solved.iter().map(|s| s.specification.family()).collect();

        assert_eq!(families.len(), solved.len(), "{solved:?}");
    }

    /// The whole point is that this is affordable. An exhaustive 16-bit sweep is
    /// 262,140 candidates; the enumeration it replaces was 4,194,240 IPC calls.
    #[test]
    fn test_solve_crc16_exhaustive_sweep_is_fast() {
        let frames: Vec<Vec<u8>> = (0..200u32)
            .map(|i| {
                let mut body = vec![
                    0x02,
                    i as u8,
                    (i >> 8) as u8,
                    (i.wrapping_mul(97)) as u8,
                    0x11,
                ];
                let crc = crc16_parameterised(&body, 0x9EB2, 0x1234, 0x5678, false, false);
                body.push((crc & 0xFF) as u8);
                body.push((crc >> 8) as u8);
                body
            })
            .collect();

        let start = std::time::Instant::now();
        let solved = solve_crc(&frames, &TRAILING_WORD, &Default::default());
        let elapsed = start.elapsed();

        assert_eq!(only_crc(&solved).polynomial, 0x9EB2);
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "exhaustive CRC-16 sweep took {elapsed:?}"
        );
    }
}
