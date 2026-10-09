//! Checksum algorithms and a scored detection engine for WireTAP frames.
//!
//! - [`algorithms`] — the eleven named algorithms plus parameterised CRC-8/16.
//!   Bytes in, value out; nothing here knows about frames.
//! - [`frame`] — end-relative byte addressing, reading a stored checksum out of
//!   a frame, and validating one against the other.
//! - [`columns`] — per-byte-column statistics. The structural evidence both the
//!   sweep and the identification pass upstream rest on, so it lives here with
//!   the addressing it is indexed by rather than in either caller.
//! - [`spec`] — [`ChecksumSpec`], one point in the candidate space, and the
//!   grouped sweep that measures many specs against many frames.
//! - [`detect`] — the engine: build the candidate space from column priors,
//!   sweep it, score and rank what survives, and explain the verdict.
//! - [`solve`] — computing the answer instead of enumerating candidates:
//!   additive residues, and a CRC search with `init`/`xorOut` collapsed out.
//! - [`sampling`] — picking payloads worth solving over, because a periodic
//!   link hands you a hundred copies of one frame.
//! - [`notes`] — the translatable note type every explanation crosses as, and
//!   [`ALL_NOTES`], the manifest a consumer pins its locale file against.
//!
//! Offsets are end-relative throughout (a negative index counts from the end),
//! because that is the only way frames of different lengths on one link line up.
//! A one-byte acknowledgement sharing a link with 20-byte payload frames is the
//! case that breaks length assumptions, and it is a real capture, not a corner.

pub mod algorithms;
pub mod columns;
pub mod detect;
pub mod frame;
pub mod notes;
pub mod sampling;
pub mod solve;
pub mod spec;

#[cfg(test)]
mod testing;

pub use algorithms::{
    calculate_checksum_simple, crc16_parameterised, crc8_parameterised, ChecksumAlgorithm,
    ALL_ALGORITHMS,
};
pub use columns::{analyse_columns, analyse_columns_from, Anchor, ColumnStats};
pub use detect::{
    build_checksum_specs, calc_ranges, detect_checksum, detect_checksum_with_columns, volume_bonus,
    CalcRange, ChecksumCandidate, ChecksumDetectionOptions, ChecksumDetectionResult, MAX_SAMPLES,
    MIN_CONFIDENCE, STRONG_MATCH_RATE,
};
pub use frame::{
    calculate_checksum, calculated_range, extract_checksum, resolve_byte_index, validate_checksum,
    ChecksumValidationResult,
};
pub use notes::{ChecksumNote, NoteSpec, ALL_NOTES};
pub use sampling::{deduplicate, diverse_samples, strided_samples};
pub use solve::{algorithm_widths, AlgorithmWidth};
pub use solve::{
    all_algorithm_ids, solve_additive, solve_all, solve_crc, AdditiveOp, ChecksumSpecification,
    CrcAlternative, CrcParameters, CrcSolveOptions, SolveTarget, SolvedChecksum, CRC_CUSTOM,
    SUM8_NEGATED,
};
pub use spec::{sweep_specs, ChecksumSpec, ChecksumSpecResult};
