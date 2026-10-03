//! Live mirror validation: does a `mirror_of` frame still agree with its source?
//!
//! A catalogue can declare that one frame duplicates another (`mirror_of`), and
//! [`crate::parse`] resolves the source's signals onto the mirror, marking each
//! copied one [`Signal::inherited`](crate::model::Signal::inherited). Only those
//! inherited bytes are compared here: a signal the mirror declares *itself* — at
//! the same `start_bit:bit_length`, which makes it an override rather than an
//! inherited copy — is deliberately different data and must not read as a fault.
//! That is how `sbrxxx.toml` models `0x504`'s negated battery current and
//! `0x005`'s end-stop flag.
//!
//! The two copies arrive milliseconds apart, so a comparison is only meaningful
//! when the samples are close enough in time — see [`MirrorTracker`] for the
//! window and the latch that keep a moving signal from flapping the verdict.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::decode::frame_id_mask;
use crate::model::{Catalog, Frame};

/// Fuzz window basis when the source frame declares no interval. Doubled, as
/// every interval is, to give the pair room to arrive.
const DEFAULT_INTERVAL_MS: u64 = 1000;

/// Consecutive in-window comparisons that must fail before a mirror latches
/// invalid. A single differing sample is usually skew on a moving signal.
const MISMATCH_LATCH: u32 = 3;

/// Payload byte indices covered by a frame's *inherited* signals — the bytes a
/// mirror is expected to reproduce verbatim.
///
/// Signals the frame declares itself are excluded, which is what lets a
/// catalogue document a legitimately different byte. Mux-case signals are not
/// considered, so a mirror of a mux-only frame yields an empty set. Empty
/// means *cannot be compared*, never *compares equal* — see
/// [`MirrorTracker::new`], which refuses to track such a mirror rather than let
/// it report a vacuous match.
pub fn inherited_byte_indices(frame: &Frame) -> BTreeSet<usize> {
    let mut out = BTreeSet::new();
    for signal in &frame.signals {
        if !signal.inherited {
            continue;
        }
        let (Some(start_bit), Some(bit_length)) = (signal.start_bit, signal.bit_length) else {
            continue;
        };
        if bit_length == 0 {
            continue;
        }
        let first = (start_bit / 8) as usize;
        let last = ((start_bit + bit_length - 1) / 8) as usize;
        for index in first..=last {
            out.insert(index);
        }
    }
    out
}

/// The current state of one mirror relationship, as reported to the UI.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MirrorVerdict {
    /// Catalogue frame id this mirror is compared against.
    pub source_frame_id: u32,
    /// `None` until a first comparison has run inside the fuzz window.
    pub is_valid: Option<bool>,
    /// Gap between the two most recent samples, in milliseconds. Reported even
    /// when it exceeded the window and so produced no comparison.
    pub time_delta_ms: f64,
    /// Inherited byte indices that differed at the last in-window comparison.
    pub mismatched_byte_indices: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
struct MirrorState {
    source_frame_id: u32,
    inherited: BTreeSet<usize>,
    fuzz_window_ms: f64,
    mirror_bytes: Vec<u8>,
    mirror_ts: Option<f64>,
    source_bytes: Vec<u8>,
    source_ts: Option<f64>,
    is_valid: Option<bool>,
    time_delta_ms: f64,
    mismatched: Vec<usize>,
    consecutive_mismatches: u32,
}

impl MirrorState {
    /// Record the newest sample from one side of the pair, then re-compare.
    fn record(&mut self, is_mirror: bool, bytes: &[u8], timestamp_s: f64) {
        let (buffer, timestamp) = if is_mirror {
            (&mut self.mirror_bytes, &mut self.mirror_ts)
        } else {
            (&mut self.source_bytes, &mut self.source_ts)
        };
        buffer.clear();
        buffer.extend_from_slice(bytes);
        *timestamp = Some(timestamp_s);
        self.compare();
    }

    /// Compare the two most recent samples, if both have arrived and are close
    /// enough together. Outside the window the previous verdict stands — a
    /// mirror that stops arriving keeps its last known state rather than
    /// silently reverting to "unknown".
    fn compare(&mut self) {
        let (Some(mirror_ts), Some(source_ts)) = (self.mirror_ts, self.source_ts) else {
            return;
        };
        self.time_delta_ms = (mirror_ts - source_ts).abs() * 1000.0;
        if self.time_delta_ms > self.fuzz_window_ms {
            return;
        }

        self.mismatched = self
            .inherited
            .iter()
            .copied()
            .filter(|&i| self.mirror_bytes.get(i) != self.source_bytes.get(i))
            .collect();

        if self.mismatched.is_empty() {
            self.consecutive_mismatches = 0;
            self.is_valid = Some(true);
        } else {
            self.consecutive_mismatches += 1;
            if self.consecutive_mismatches >= MISMATCH_LATCH {
                self.is_valid = Some(false);
            }
        }
    }

    fn verdict(&self) -> MirrorVerdict {
        MirrorVerdict {
            source_frame_id: self.source_frame_id,
            is_valid: self.is_valid,
            time_delta_ms: self.time_delta_ms,
            mismatched_byte_indices: self.mismatched.clone(),
        }
    }
}

/// Per-session mirror comparison state for one catalogue.
///
/// Built from a resolved [`Catalog`], fed every frame the session delivers via
/// [`observe`](Self::observe), and read back with [`verdicts`](Self::verdicts).
/// Because the tracker belongs to the catalogue it was built from, re-attaching
/// a catalogue replaces it wholesale — there is no way for a verdict, or the
/// inherited byte set behind it, to outlive the catalogue that produced it.
///
/// The catalogue is needed only to build it: the frame-id mask is read once here
/// rather than re-derived per frame, so the streaming path never touches the
/// catalogue again and cannot be paired with the wrong one.
#[derive(Debug)]
pub struct MirrorTracker {
    /// The protocol's `frame_id_mask`, applied to every id fed in.
    mask: Option<u32>,
    /// Mirror frame id → its comparison state.
    states: BTreeMap<u32, MirrorState>,
    /// Source frame id → the mirrors that watch it.
    by_source: BTreeMap<u32, Vec<u32>>,
}

impl MirrorTracker {
    /// Build a tracker for every `mirror_of` frame in the catalogue whose source
    /// resolves **and** which inherits at least one byte. A mirror that inherits
    /// nothing (its source carries only a mux, which is never compared)
    /// is skipped rather than tracked: with no bytes to compare it could only
    /// ever report a match, and a validator that cannot check something must say
    /// nothing rather than pass it.
    pub fn new(catalog: &Catalog) -> Self {
        let mut states = BTreeMap::new();
        let mut by_source: BTreeMap<u32, Vec<u32>> = BTreeMap::new();

        for frame in &catalog.frames {
            let Some(source) = frame
                .mirror_of
                .as_deref()
                .and_then(crate::parse::parse_id)
                .and_then(|id| catalog.frame(id))
            else {
                continue;
            };
            let inherited = inherited_byte_indices(frame);
            if inherited.is_empty() {
                continue;
            }
            // `Frame.interval` is already resolved explicit → mirror source →
            // `[meta.can].default_interval` by the parser, so there is no
            // fallback chain to repeat here.
            let interval = source.interval.unwrap_or(DEFAULT_INTERVAL_MS);

            states.insert(
                frame.frame_id,
                MirrorState {
                    source_frame_id: source.frame_id,
                    inherited,
                    fuzz_window_ms: (interval * 2) as f64,
                    ..Default::default()
                },
            );
            by_source
                .entry(source.frame_id)
                .or_default()
                .push(frame.frame_id);
        }

        Self {
            mask: frame_id_mask(catalog),
            states,
            by_source,
        }
    }

    /// True when the catalogue declares no comparable mirrors, so callers can
    /// skip the per-frame work entirely.
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Apply the catalogue's `frame_id_mask` to a raw frame id, so callers can
    /// key their own lookups the same way [`verdicts`](Self::verdicts) does.
    pub fn mask_id(&self, raw_frame_id: u32) -> u32 {
        self.mask.map(|m| raw_frame_id & m).unwrap_or(raw_frame_id)
    }

    /// Feed in one delivered frame, as either side of a mirror pair.
    ///
    /// Must be called for **every** frame the session delivers, not just the
    /// ones the UI is showing: a mirror can only be judged if its source is
    /// also being seen. `timestamp_s` is the frame's arrival time in seconds.
    pub fn observe(&mut self, raw_frame_id: u32, bytes: &[u8], timestamp_s: f64) {
        let frame_id = self.mask_id(raw_frame_id);
        let Self {
            states, by_source, ..
        } = self;

        if let Some(state) = states.get_mut(&frame_id) {
            state.record(true, bytes, timestamp_s);
        }
        if let Some(mirror_ids) = by_source.get(&frame_id) {
            for mirror_id in mirror_ids {
                if let Some(state) = states.get_mut(mirror_id) {
                    state.record(false, bytes, timestamp_s);
                }
            }
        }
    }

    /// Forget every sample and verdict, keeping the catalogue-derived setup.
    ///
    /// For when the stream restarts under the same catalogue — a cleared
    /// capture, or a replay rewinding — where retained samples would otherwise
    /// re-assert a verdict the user cleared, or sit outside the fuzz window
    /// forever because time went backwards.
    pub fn reset(&mut self) {
        for state in self.states.values_mut() {
            *state = MirrorState {
                source_frame_id: state.source_frame_id,
                inherited: std::mem::take(&mut state.inherited),
                fuzz_window_ms: state.fuzz_window_ms,
                ..Default::default()
            };
        }
    }

    /// The current verdict for every tracked mirror, keyed by masked frame id.
    ///
    /// Yields one entry per mirror rather than one per observed frame, so a
    /// caller can build its lookup in O(mirrors) instead of walking the batch a
    /// second time.
    pub fn verdicts(&self) -> impl Iterator<Item = (u32, MirrorVerdict)> + '_ {
        self.states.iter().map(|(id, state)| (*id, state.verdict()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mirror pair where the mirror overrides byte 1, as `sbrxxx.toml`'s
    /// `0x005` does for the SBR end-stop flag.
    const OVERRIDE_TOML: &str = r#"
[meta]
name = "t"
[meta.can]
default_interval = 100

[frame.can."0x705"]
length = 8

[[frame.can."0x705".signals]]
name = "op"
start_bit = 0
bit_length = 8

[[frame.can."0x705".signals]]
name = "end_stop"
start_bit = 8
bit_length = 8

[[frame.can."0x705".signals]]
name = "rest"
start_bit = 16
bit_length = 48

[frame.can."0x005"]
length = 8
mirror_of = "0x705"

[[frame.can."0x005".signals]]
name = "local_end_stop"
start_bit = 8
bit_length = 8
"#;

    fn parse(toml: &str) -> Catalog {
        Catalog::parse(toml).expect("catalogue parses")
    }

    #[test]
    fn inherited_bytes_exclude_a_positional_override() {
        let cat = parse(OVERRIDE_TOML);

        let mirror = cat.frame(0x005).unwrap();
        // Byte 1 is the mirror's own signal, so it is not compared; bytes 0 and
        // 2..=7 are inherited.
        assert_eq!(
            inherited_byte_indices(mirror),
            BTreeSet::from([0, 2, 3, 4, 5, 6, 7])
        );

        // The source frame owns all of its signals, so nothing is inherited.
        assert!(inherited_byte_indices(cat.frame(0x705).unwrap()).is_empty());
    }

    #[test]
    fn an_overridden_byte_never_invalidates_the_mirror() {
        let cat = parse(OVERRIDE_TOML);
        let mut tracker = MirrorTracker::new(&cat);

        // Byte 1 differs on every sample; every other byte agrees.
        for i in 0..10 {
            let t = i as f64 * 0.1;
            tracker.observe(0x705, &[2, 0, 1, 2, 3, 4, 5, 6], t);
            tracker.observe(0x005, &[2, 1, 1, 2, 3, 4, 5, 6], t + 0.01);
        }

        let v = verdict(&tracker, 0x005).unwrap();
        assert_eq!(v.is_valid, Some(true));
        assert!(v.mismatched_byte_indices.is_empty());
        assert_eq!(v.source_frame_id, 0x705);
    }

    #[test]
    fn an_inherited_byte_latches_invalid_after_three_comparisons() {
        let cat = parse(OVERRIDE_TOML);
        let mut tracker = MirrorTracker::new(&cat);

        tracker.observe(0x705, &[2, 0, 1, 0, 0, 0, 0, 0], 0.0);

        // Byte 2 is inherited, so each differing sample counts towards the latch.
        for i in 1..=2 {
            tracker.observe(0x005, &[2, 0, 9, 0, 0, 0, 0, 0], i as f64 * 0.01);
            let v = verdict(&tracker, 0x005).unwrap();
            assert_eq!(v.is_valid, None, "must not latch before {MISMATCH_LATCH}");
            assert_eq!(v.mismatched_byte_indices, vec![2]);
        }

        tracker.observe(0x005, &[2, 0, 9, 0, 0, 0, 0, 0], 0.03);
        assert_eq!(verdict(&tracker, 0x005).unwrap().is_valid, Some(false));

        // One agreeing comparison clears it again.
        tracker.observe(0x005, &[2, 0, 1, 0, 0, 0, 0, 0], 0.04);
        let v = verdict(&tracker, 0x005).unwrap();
        assert_eq!(v.is_valid, Some(true));
        assert!(v.mismatched_byte_indices.is_empty());
    }

    #[test]
    fn samples_too_far_apart_are_not_compared() {
        let cat = parse(OVERRIDE_TOML);
        let mut tracker = MirrorTracker::new(&cat);

        // Window is the source's interval (100 ms, from [meta.can]) doubled.
        tracker.observe(0x705, &[0, 0, 0, 0, 0, 0, 0, 0], 0.0);
        tracker.observe(0x005, &[9, 9, 9, 9, 9, 9, 9, 9], 0.5);

        let v = verdict(&tracker, 0x005).unwrap();
        assert_eq!(v.is_valid, None, "no comparison outside the window");
        assert_eq!(v.time_delta_ms, 500.0, "the gap is still reported");
    }

    /// A 16-bit override spanning two bytes, as `sbrxxx.toml`'s `0x504` does for
    /// the sign-inverted battery current.
    #[test]
    fn a_multi_byte_override_excludes_its_whole_span() {
        let cat = parse(
            r#"
[meta]
name = "t"

[frame.can."0x704"]
length = 8

[[frame.can."0x704".signals]]
name = "voltage"
start_bit = 0
bit_length = 16

[[frame.can."0x704".signals]]
name = "current"
start_bit = 16
bit_length = 16

[[frame.can."0x704".signals]]
name = "temperature"
start_bit = 32
bit_length = 32

[frame.can."0x504"]
length = 8
mirror_of = "0x704"

[[frame.can."0x504".signals]]
name = "current_inverted"
start_bit = 16
bit_length = 16
"#,
        );

        assert_eq!(
            inherited_byte_indices(cat.frame(0x504).unwrap()),
            BTreeSet::from([0, 1, 4, 5, 6, 7]),
            "bytes 2-3 carry the override and are excluded"
        );

        let mut tracker = MirrorTracker::new(&cat);
        // Same voltage and temperature, negated current.
        tracker.observe(0x704, &[1, 2, 0xEC, 0xFF, 5, 6, 7, 8], 0.0);
        tracker.observe(0x504, &[1, 2, 0x14, 0x00, 5, 6, 7, 8], 0.01);
        assert_eq!(verdict(&tracker, 0x504).unwrap().is_valid, Some(true));
    }

    /// `sbrxxx.toml`'s `0x008`/`0x00a` mirror mux-only frames, so there is no
    /// plain inherited signal and no byte to compare. Reporting a match
    /// there would be a green tick for a check that never ran.
    #[test]
    fn a_mirror_of_a_mux_only_frame_is_not_tracked() {
        let cat = parse(
            r#"
[meta]
name = "t"

[frame.can."0x708"]
length = 8

[frame.can."0x708".mux]
name = "sel"
start_bit = 0
bit_length = 8

[[frame.can."0x708".mux."0".signals]]
name = "sn"
start_bit = 8
bit_length = 56

[frame.can."0x008"]
length = 8
mirror_of = "0x708"
"#,
        );

        assert!(inherited_byte_indices(cat.frame(0x008).unwrap()).is_empty());

        let mut tracker = MirrorTracker::new(&cat);
        assert!(tracker.is_empty(), "nothing comparable, so nothing tracked");

        tracker.observe(0x708, &[0, 1, 2, 3, 4, 5, 6, 7], 0.0);
        tracker.observe(0x008, &[9, 9, 9, 9, 9, 9, 9, 9], 0.01);
        assert!(
            verdict(&tracker, 0x008).is_none(),
            "no verdict beats a vacuous match"
        );
    }

    /// Real `0x005`/`0x705` traffic from a Sungrow SBR224 (WT Bendigo,
    /// 2026-07-31 05:00Z, a window where the pack sat at 100 % SoC), as
    /// `(frame id, arrival seconds, payload)`.
    ///
    /// Byte 1 is the end-stop flag: `01` on the `0x0NN` copy, `00` on `0x7NN`.
    /// Byte 5 drifts as the pack voltage moves, but both copies agree at each
    /// instant. `0x005` arrives first, `0x705` ~16 ms behind. Five pairs is one
    /// more than [`MISMATCH_LATCH`] needs, so the no-override case latches.
    const REAL_PAIRS: &[(u32, f64, [u8; 8])] = &[
        (
            0x005,
            0.000,
            [0x02, 0x01, 0x01, 0xeb, 0x20, 0x0d, 0x13, 0x00],
        ),
        (
            0x705,
            0.016,
            [0x02, 0x00, 0x01, 0xeb, 0x20, 0x0d, 0x13, 0x00],
        ),
        (
            0x005,
            1.000,
            [0x02, 0x01, 0x01, 0xeb, 0x20, 0x0c, 0x13, 0x00],
        ),
        (
            0x705,
            1.015,
            [0x02, 0x00, 0x01, 0xeb, 0x20, 0x0c, 0x13, 0x00],
        ),
        (
            0x005,
            2.029,
            [0x02, 0x01, 0x01, 0xeb, 0x20, 0x0c, 0x13, 0x00],
        ),
        (
            0x705,
            2.053,
            [0x02, 0x00, 0x01, 0xeb, 0x20, 0x0c, 0x13, 0x00],
        ),
        (
            0x005,
            3.018,
            [0x02, 0x01, 0x01, 0xeb, 0x20, 0x0b, 0x13, 0x00],
        ),
        (
            0x705,
            3.031,
            [0x02, 0x00, 0x01, 0xeb, 0x20, 0x0b, 0x13, 0x00],
        ),
        (
            0x005,
            4.018,
            [0x02, 0x01, 0x01, 0xeb, 0x20, 0x0b, 0x13, 0x00],
        ),
        (
            0x705,
            4.032,
            [0x02, 0x00, 0x01, 0xeb, 0x20, 0x0b, 0x13, 0x00],
        ),
    ];

    /// The `0x705`/`0x005` pair with production signal names, so the test reads
    /// against the real frame rather than a shape.
    ///
    /// Deliberately declares no `[meta.can]`, matching the real `sbrxxx.toml`:
    /// with no interval anywhere, the window is [`DEFAULT_INTERVAL_MS`] doubled
    /// = 2 s, which is what lets the ~1 s *between* [`REAL_PAIRS`] pairs be
    /// compared as well as the 16 ms within one. Do not fold this onto
    /// `OVERRIDE_TOML` — its 100 ms interval would silently drop those.
    const SBR_TOML: &str = r#"
[meta]
name = "sbr"

[frame.can."0x705"]
length = 8

[[frame.can."0x705".signals]]
name = "Info_Battery_Operation"
start_bit = 0
bit_length = 8

[[frame.can."0x705".signals]]
name = "705_End_Stop"
start_bit = 8
bit_length = 8

[[frame.can."0x705".signals]]
name = "Status_Battery_Voltage_Alt_705"
start_bit = 40
bit_length = 16

[frame.can."0x005"]
length = 8
mirror_of = "0x705"
"#;

    /// What the real catalogue adds to `0x005` — an override at byte 1.
    const SBR_END_STOP_OVERRIDE: &str = r#"
[[frame.can."0x005".signals]]
name = "Status_Battery_End_Stop"
start_bit = 8
bit_length = 8
"#;

    fn run_real_pairs(toml: &str) -> MirrorVerdict {
        let cat = parse(toml);
        let mut tracker = MirrorTracker::new(&cat);
        for &(frame_id, timestamp, bytes) in REAL_PAIRS {
            tracker.observe(frame_id, &bytes, timestamp);
        }
        verdict(&tracker, 0x005).expect("0x005 is a tracked mirror")
    }

    /// The regression this module exists for: declaring byte 1 locally is what
    /// tells the comparison to leave it alone. Without that the frame reads as
    /// a fault whenever the flag is set, which is what was reported.
    #[test]
    fn real_sbr_traffic_matches_only_because_byte_1_is_overridden() {
        let with = run_real_pairs(&format!("{SBR_TOML}{SBR_END_STOP_OVERRIDE}"));
        assert_eq!(with.is_valid, Some(true), "the override must hold Match");
        assert!(with.mismatched_byte_indices.is_empty());

        let without = run_real_pairs(SBR_TOML);
        assert_eq!(
            without.is_valid,
            Some(false),
            "without the override the same bytes must latch Mismatch"
        );
        assert_eq!(without.mismatched_byte_indices, vec![1]);
    }

    #[test]
    fn a_frame_that_is_not_a_mirror_has_no_verdict() {
        let cat = parse(OVERRIDE_TOML);
        let tracker = MirrorTracker::new(&cat);
        assert!(verdict(&tracker, 0x705).is_none());
        assert!(verdict(&tracker, 0x123).is_none());
    }

    #[test]
    fn a_catalogue_without_mirrors_yields_an_empty_tracker() {
        let cat = parse(
            r#"
[meta]
name = "t"
[frame.can."0x100"]
length = 8
"#,
        );
        assert!(MirrorTracker::new(&cat).is_empty());
    }

    #[test]
    fn ids_are_masked_before_lookup() {
        let cat = parse(&OVERRIDE_TOML.replace(
            "default_interval = 100",
            "default_interval = 100\nframe_id_mask = 0xFFF",
        ));
        let mut tracker = MirrorTracker::new(&cat);

        // The high bits are outside the mask, so these are 0x705 and 0x005.
        tracker.observe(0x1F000705, &[2, 0, 1, 2, 3, 4, 5, 6], 0.0);
        tracker.observe(0x1F000005, &[2, 0, 1, 2, 3, 4, 5, 6], 0.01);

        assert_eq!(verdict(&tracker, 0x1F000005).unwrap().is_valid, Some(true));
    }

    /// Test helper: the verdict for one frame id, or `None` if it is not a
    /// tracked mirror.
    fn verdict(tracker: &MirrorTracker, raw_frame_id: u32) -> Option<MirrorVerdict> {
        let id = tracker.mask_id(raw_frame_id);
        tracker.verdicts().find(|(k, _)| *k == id).map(|(_, v)| v)
    }
}
