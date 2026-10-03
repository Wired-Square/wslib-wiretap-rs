//! Payload analysis for WireTAP frames.
//!
//! - [`checksum`] — the identification pass: which bytes are worth handing to
//!   [`wiretap_checksum`]'s solvers, and why the rest were not.
//! - [`scan`] — the orchestration over a whole capture: group by frame id,
//!   sample, identify, sweep, solve, rank.
//! - [`roles`] — what each byte does, addressed from the front: static,
//!   counter, sensor, value, the 16- and 32-bit counters, sensors and text that
//!   span columns, and the mux selectors that split a frame into cases.
//! - [`structure`] — a serial link's id and source-address bytes.
//! - [`hypothesis`] — candidate bit fields over one frame's payload, ranked
//!   against its byte roles. Reached by path: its `CandidateReason` is not
//!   [`structure`]'s.
//!
//! Per-byte-column statistics live in [`wiretap_checksum::columns`], beside the
//! addressing they are indexed by. A caller that needs them
//! depends on that crate directly, as this one does; they are not re-exported.
//!
//! `wiretap-checksum` answers *what algorithm is this byte*; this crate answers
//! the prior question — *is this byte a checksum at all* — and drives the scan
//! that puts the two together.
//!
//! The two crates stay separate, and the byte-role classifier sits here beside
//! the identification pass, reading the same [`ColumnStats`] from the front
//! rather than bringing a statistics set of its own. The reasoning is in the
//! WireTAP-lib vault, `Plans/lib-extraction-a-api.md`.
//!
//! [`ColumnStats`]: wiretap_checksum::columns::ColumnStats

pub mod checksum;
pub mod hypothesis;
pub mod roles;
pub mod scan;
pub mod structure;

pub use checksum::{
    checksum_evidence, checksum_evidence_with_columns, solve_targets, ChecksumEvidence,
    RankedTarget, Rejection,
};
pub use roles::{
    classify_columns, detect_mux, find_patterns, infer_endianness, is_mux_like_sequence,
    profile_bytes, ByteColumn, ByteProfile, ByteRole, Direction, Endianness, Loop,
    MultiBytePattern, MuxAnalysis, MuxCase, MuxDetection, MuxSelector, PatternKind, Trend,
};
pub use scan::{
    analyse_group, scan_frames, scan_groups, ChecksumScanOptions, ChecksumScanResult,
    DiscoveredChecksum, FrameChecksumFinding, FrameKey, DEFAULT_MIN_LIKENESS,
};
pub use structure::{serial_structure, CandidateReason, FieldCandidate, SerialStructure};
